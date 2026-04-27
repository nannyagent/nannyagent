package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"nannyagent/internal/config"
	"nannyagent/internal/logging"
	"nannyagent/internal/types"
)

const (
	// Token storage location (secure directory)
	TokenStorageDir  = "/var/lib/nannyagent"
	TokenStorageFile = "token.json"
	RefreshTokenFile = ".refresh_token"

	// Polling configuration for NannyAPI device auth flow
	MaxPollAttempts = 60 // 5 minutes (60 * 5 seconds)
	PollInterval    = 5 * time.Second
)

// AuthManager handles all NannyAPI authentication operations
type AuthManager struct {
	config    *config.Config
	client    *http.Client
	transport *http.Transport
	mu        sync.RWMutex // Protects client, transport, and error counters
	baseURL   string       // NannyAPI API URL

	// Track consecutive connection errors to detect persistent connection issues.
	// When threshold is reached, we completely rebuild the HTTP transport.
	// This is a RECOVERY mechanism - the agent NEVER stops trying.
	consecutiveConnErrors int

	// Track retry attempts for exponential backoff.
	// This allows us to increase delay between retries up to a maximum.
	// The agent will NEVER give up - it just waits longer between attempts.
	retryAttempts int
}

// isConnectionError checks if an error indicates a connection-level issue
// that would benefit from a transport reset or exponential backoff.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()

	// HTTP/2 specific errors indicating stale multiplexed connections
	if strings.Contains(errStr, "http2:") {
		return true
	}
	// Response body issues (common with stale HTTP/2)
	if strings.Contains(errStr, "response body closed") ||
		strings.Contains(errStr, "read on closed") {
		return true
	}
	// TCP-level connection problems
	if strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "i/o timeout") {
		return true
	}
	// TLS errors
	if strings.Contains(errStr, "tls:") ||
		strings.Contains(errStr, "certificate") {
		return true
	}
	return false
}

// isRefreshTokenExpiredError checks if an error indicates the refresh token is
// permanently invalid (expired, revoked, or invalid) and requires re-registration.
// Returns true only for errors where retrying with the same token is pointless.
func isRefreshTokenExpiredError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())

	// API returned 400/401/403 with clear token invalidity messages
	// Common patterns from OAuth APIs:
	if strings.Contains(errStr, "refresh_token") && (strings.Contains(errStr, "expired") ||
		strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "revoked")) {
		return true
	}
	// Status code based detection
	if strings.Contains(errStr, "status 401") || strings.Contains(errStr, "status 403") {
		return true
	}
	// Generic invalid/expired token messages
	if strings.Contains(errStr, "token") && (strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "expired") ||
		strings.Contains(errStr, "revoked") ||
		strings.Contains(errStr, "not found")) {
		return true
	}
	return false
}

// calculateBackoff returns the current backoff duration using exponential backoff.
// Uses config settings for initial delay and max delay.
// The agent NEVER gives up - this just calculates how long to wait.
func (am *AuthManager) calculateBackoff() time.Duration {
	am.mu.RLock()
	attempts := am.retryAttempts
	tc := am.config.HTTPTransport
	am.mu.RUnlock()

	initialDelay := time.Duration(tc.InitialRetryDelaySec) * time.Second
	maxDelay := time.Duration(tc.MaxRetryDelaySec) * time.Second

	if attempts <= 0 {
		return initialDelay
	}

	// Cap attempts to prevent overflow (2^30 is already huge)
	if attempts > 30 {
		return maxDelay
	}

	// Exponential backoff: initial * 2^attempts
	// Cap at maxDelay
	backoff := initialDelay * time.Duration(1<<uint(attempts))
	if backoff > maxDelay || backoff <= 0 { // Check for overflow too
		backoff = maxDelay
	}
	return backoff
}

// incrementRetryAttempts increases the retry counter for backoff calculation.
func (am *AuthManager) incrementRetryAttempts() {
	am.mu.Lock()
	am.retryAttempts++
	am.mu.Unlock()
}

// resetRetryAttempts clears the retry counter after successful request.
func (am *AuthManager) resetRetryAttempts() {
	am.mu.Lock()
	am.retryAttempts = 0
	am.mu.Unlock()
}

// createTransport builds an HTTP transport using config settings.
// This is factored out to allow complete transport replacement on persistent errors.
func createTransport(cfg *config.Config) *http.Transport {
	tc := cfg.HTTPTransport

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 10 * time.Second,

		MaxIdleConns:          tc.MaxIdleConns,
		MaxIdleConnsPerHost:   tc.MaxIdleConnsPerHost,
		IdleConnTimeout:       time.Duration(tc.IdleConnTimeoutSec) * time.Second,
		ResponseHeaderTimeout: time.Duration(tc.ResponseHeaderTimeoutSec) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		// ForceAttemptHTTP2 is the inverse of DisableHTTP2
		ForceAttemptHTTP2: !tc.DisableHTTP2,
	}

	if tc.DisableHTTP2 {
		// When HTTP/2 is disabled, we use HTTP/1.1's TLSNextProto trick
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
		logging.Debug("HTTP/2 disabled, using HTTP/1.1 only")
	}

	return transport
}

// resetTransport completely replaces the HTTP transport and client.
// This is a RECOVERY mechanism called when stale connections can't be fixed by
// CloseIdleConnections(). The agent continues retrying - this just creates fresh connections.
func (am *AuthManager) resetTransport() {
	am.mu.Lock()
	defer am.mu.Unlock()

	logging.Info("Resetting HTTP transport to recover from stale connections (after %d consecutive errors)",
		am.consecutiveConnErrors)

	// Close existing connections
	if am.transport != nil {
		am.transport.CloseIdleConnections()
	}

	// Create completely new transport and client
	am.transport = createTransport(am.config)
	am.client = &http.Client{
		Transport: am.transport,
		Timeout:   5 * time.Minute,
	}

	// Reset error counter, but keep retry attempts for backoff
	am.consecutiveConnErrors = 0
}

// recordConnError increments the error counter and resets transport if threshold reached.
// Returns true if transport was reset.
func (am *AuthManager) recordConnError() bool {
	am.mu.Lock()
	am.consecutiveConnErrors++
	threshold := am.config.HTTPTransport.TransportResetThreshold
	shouldReset := am.consecutiveConnErrors >= threshold
	am.mu.Unlock()

	if shouldReset {
		am.resetTransport()
		return true
	}
	return false
}

// clearConnErrors resets the error counter after a successful request.
func (am *AuthManager) clearConnErrors() {
	am.mu.Lock()
	am.consecutiveConnErrors = 0
	am.mu.Unlock()
}

// getClient returns the current HTTP client thread-safely.
func (am *AuthManager) getClient() *http.Client {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.client
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *config.Config) *AuthManager {
	// Get NannyAPI URL from config
	baseURL := cfg.APIBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("NANNYAPI_URL")
	}

	transport := createTransport(cfg)

	return &AuthManager{
		config:    cfg,
		baseURL:   baseURL,
		transport: transport,
		client: &http.Client{
			Transport: transport,
			// Increased default timeout for investigations/LLM responses
			Timeout: 5 * time.Minute,
		},
	}
}

// EnsureTokenStorageDir creates the token storage directory if it doesn't exist
func (am *AuthManager) EnsureTokenStorageDir() error {
	tokenPath := am.getTokenPath()
	dir := filepath.Dir(tokenPath)

	// Only enforce root if we are using the default system directory
	if dir == TokenStorageDir {
		// Check if running as root
		if os.Geteuid() != 0 {
			return fmt.Errorf("must run as root to create secure token storage directory")
		}
	}

	// Create directory with restricted permissions (0700)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token storage directory: %w", err)
	}

	return nil
}

// StartDeviceAuthorization initiates the NannyAPI device authorization flow
// Returns device_code and user_code that user needs to authorize
func (am *AuthManager) StartDeviceAuthorization() (*types.DeviceAuthResponse, error) {
	logging.Info("Starting NannyAPI device authorization flow...")

	// Create the device auth request
	payload := types.DeviceAuthRequest{
		Action: "device-auth-start",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send request to NannyAPI /api/agent endpoint
	url := fmt.Sprintf("%s/api/agent", am.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to start device authorization: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResp types.DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &deviceResp, nil
}

// AuthorizeDeviceCode polls the device auth endpoint to authorize the device code
// This is called after the user enters the user_code in the portal
func (am *AuthManager) AuthorizeDeviceCode(userCode string) error {
	logging.Info("Authorizing device code with user code: %s", userCode)

	// Create authorize request
	payload := types.AuthorizeRequest{
		Action:   "authorize",
		UserCode: userCode,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", am.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.getClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to authorize device code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("device code authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp types.AuthorizeResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !authResp.Success {
		return fmt.Errorf("authorization failed: %s", authResp.Message)
	}

	logging.Info("Device code authorized successfully")
	return nil
}

// PollForTokenAfterAuthorization polls the /api/agent endpoint until the device is authorized
func (am *AuthManager) PollForTokenAfterAuthorization(deviceCode string) (*types.TokenResponse, error) {
	logging.Info("Polling for device authorization... (will wait up to 5 minutes)")

	for attempts := 0; attempts < MaxPollAttempts; attempts++ {
		// Create register request to check if device is authorized
		payload := types.RegisterRequest{
			Action:         "register",
			DeviceCode:     deviceCode,
			Hostname:       getHostname(),
			OSType:         getPlatform(),
			PlatformFamily: getPlatformFamily(),
			Version:        "1.0.0", // Will be updated by agent
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal register request: %w", err)
		}

		url := fmt.Sprintf("%s/api/agent", am.baseURL)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("failed to create register request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := am.getClient().Do(req)
		if err != nil {
			logging.Warning("Poll attempt %d failed: %v", attempts+1, err)
			time.Sleep(PollInterval)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		// If response body read failed, continue polling
		if err != nil {
			logging.Warning("Failed to read response body: %v", err)
			time.Sleep(PollInterval)
			continue
		}

		// Check if registration was successful
		var tokenResp types.TokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			logging.Warning("Failed to parse response: %v", err)
			time.Sleep(PollInterval)
			continue
		}

		// Check for errors in response
		if tokenResp.Error != "" {
			// If device not authorized yet, continue polling
			if strings.Contains(tokenResp.Error, "device not authorized") {
				// fmt.Print(".") // Removed to avoid direct stdout usage
				time.Sleep(PollInterval)
				continue
			}
			// Other errors should be returned
			return nil, fmt.Errorf("registration failed: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
		}

		// Success! Got tokens
		if tokenResp.AccessToken != "" {
			logging.Info("\nAuthorization successful!")
			return &tokenResp, nil
		}

		time.Sleep(PollInterval)
	}

	return nil, fmt.Errorf("authorization timed out after %d attempts (5 minutes)", MaxPollAttempts)
}

// RegisterAgent performs complete NannyAPI registration and returns tokens
func (am *AuthManager) RegisterAgent(deviceCode string, hostname string, osType string, platformFamily string, version string, primaryIP string, allIPs []string, kernelVersion string) (*types.TokenResponse, error) {
	logging.Info("Registering agent with NannyAPI...")

	payload := types.RegisterRequest{
		Action:         "register",
		DeviceCode:     deviceCode,
		Hostname:       hostname,
		Version:        version,
		PrimaryIP:      primaryIP,
		KernelVersion:  kernelVersion,
		AllIPs:         allIPs,
		OSType:         osType,
		PlatformFamily: platformFamily,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register request: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", am.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create register request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("agent registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp types.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("registration failed: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token received in registration response")
	}

	logging.Info("Agent registered successfully! Agent ID: %s", tokenResp.AgentID)
	return &tokenResp, nil
}

// RefreshAccessToken refreshes an expired access token using the refresh token
func (am *AuthManager) RefreshAccessToken(refreshToken string) (*types.TokenResponse, error) {
	logging.Debug("Attempting to refresh access token...")

	payload := types.RefreshRequest{
		Action:       "refresh",
		RefreshToken: refreshToken,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", am.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp types.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token refresh failed: %s", tokenResp.ErrorDescription)
	}

	logging.Debug("Token refreshed successfully")
	return &tokenResp, nil
}

// RenewRefreshToken rotates the refresh token. The previous refresh token is
// invalidated and a new one (plus a new access token) is returned.
// This should be called when refresh_token_expires_in is below 7 days.
func (am *AuthManager) RenewRefreshToken(refreshToken string) (*types.TokenResponse, error) {
	logging.Info("Renewing refresh token...")

	payload := map[string]string{
		"action":        "renew-refresh-token",
		"refresh_token": refreshToken,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal renew-refresh-token request: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", am.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create renew-refresh-token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to renew refresh token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read renew-refresh-token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renew-refresh-token failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp types.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse renew-refresh-token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("renew-refresh-token failed: %s", tokenResp.ErrorDescription)
	}

	if tokenResp.RefreshToken == "" {
		return nil, fmt.Errorf("renew-refresh-token response missing new refresh token")
	}

	logging.Info("Refresh token renewed successfully")
	return &tokenResp, nil
}

// SaveToken saves the authentication token to secure local storage
func (am *AuthManager) SaveToken(token *types.AuthToken) error {
	if err := am.EnsureTokenStorageDir(); err != nil {
		return fmt.Errorf("failed to ensure token storage directory: %w", err)
	}

	// Save main token file
	tokenPath := am.getTokenPath()
	jsonData, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := os.WriteFile(tokenPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	// Also save refresh token separately for backup recovery
	if token.RefreshToken != "" {
		dir := filepath.Dir(tokenPath)
		refreshTokenPath := filepath.Join(dir, RefreshTokenFile)
		if err := os.WriteFile(refreshTokenPath, []byte(token.RefreshToken), 0600); err != nil {
			// Don't fail if refresh token backup fails, just log
			logging.Warning("Failed to save backup refresh token: %v", err)
		}
	}

	return nil
}

// LoadToken loads the authentication token from secure local storage
func (am *AuthManager) LoadToken() (*types.AuthToken, error) {
	token, err := am.loadTokenRaw()
	if err != nil {
		return nil, err
	}

	// Check if token is expired (with 5-minute buffer)
	if am.IsTokenExpired(token) {
		return nil, fmt.Errorf("token is expired or expiring soon")
	}

	return token, nil
}

// loadTokenRaw loads the token from file without checking expiration
func (am *AuthManager) loadTokenRaw() (*types.AuthToken, error) {
	tokenPath := am.getTokenPath()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token types.AuthToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return &token, nil
}

// LoadTokenRaw is the exported version of loadTokenRaw for use outside the package.
func (am *AuthManager) LoadTokenRaw() (*types.AuthToken, error) {
	return am.loadTokenRaw()
}

// IsTokenExpired checks if a token needs refresh
func (am *AuthManager) IsTokenExpired(token *types.AuthToken) bool {
	// Consider token expired if it expires within the next 5 minutes
	return time.Now().After(token.ExpiresAt.Add(-5 * time.Minute))
}

// EnsureAuthenticated ensures the agent has a valid token, refreshing if necessary
func (am *AuthManager) EnsureAuthenticated() (*types.AuthToken, error) {
	// Try to load existing token
	token, err := am.LoadToken()
	if err == nil && !am.IsTokenExpired(token) {
		return token, nil
	}

	// Try to refresh with existing refresh token
	var refreshToken string
	if err == nil && token.RefreshToken != "" {
		refreshToken = token.RefreshToken
	} else {
		// Try to load refresh token from backup file
		if backupRefreshToken, backupErr := am.loadRefreshTokenFromBackup(); backupErr == nil {
			refreshToken = backupRefreshToken
			logging.Debug("Found backup refresh token, attempting to use it...")
		}
	}

	if refreshToken != "" {
		refreshResp, refreshErr := am.RefreshAccessToken(refreshToken)
		if refreshErr == nil && refreshResp.AccessToken != "" {
			// Preserve agent_id from existing token
			var agentID string
			if token != nil && token.AgentID != "" {
				agentID = token.AgentID
			} else if refreshResp.AgentID != "" {
				agentID = refreshResp.AgentID
			}

			newToken := &types.AuthToken{
				AccessToken:  refreshResp.AccessToken,
				RefreshToken: refreshToken, // preserve existing refresh token (API doesn't rotate it on refresh)
				TokenType:    refreshResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second),
				AgentID:      agentID,
			}

			if saveErr := am.SaveToken(newToken); saveErr == nil {
				return newToken, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid token available and refresh failed - registration required")
}

// NeedsRefreshTokenRenewal returns true when the refresh token has fewer than
// thresholdDays days of lifetime left, based on the refresh_token_expires_in
// value returned by the last /api/agent refresh call.
func NeedsRefreshTokenRenewal(refreshTokenExpiresIn int, thresholdDays int) bool {
	if refreshTokenExpiresIn <= 0 {
		return false
	}
	thresholdSeconds := thresholdDays * 24 * 60 * 60
	return refreshTokenExpiresIn < thresholdSeconds
}

// CompleteDeviceAuthFlow runs the full device authorization flow
func (am *AuthManager) CompleteDeviceAuthFlow(agentVersion string) (*types.AuthToken, error) {
	// Step 1: Start device authorization
	deviceAuth, err := am.StartDeviceAuthorization()
	if err != nil {
		return nil, fmt.Errorf("failed to start device authorization: %w", err)
	}

	logging.Info("")
	logging.Info("════════════════════════════════════════════════")
	logging.Info("Please visit the following link to authorize:")
	logging.Info("User Code: %s", deviceAuth.UserCode)
	logging.Info("════════════════════════════════════════════════")
	logging.Info("")

	// Step 2: Poll for authorization (5 minutes timeout)
	tokenResp, err := am.PollForTokenAfterAuthorization(deviceAuth.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get token after authorization: %w", err)
	}

	// Step 3: Create token structure
	token := &types.AuthToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		AgentID:      tokenResp.AgentID,
	}

	// Step 4: Save token
	if err := am.SaveToken(token); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	logging.Info("Token saved to %s", am.getTokenPath())
	return token, nil
}

// GetCurrentAgentID retrieves the agent ID from the saved token
func (am *AuthManager) GetCurrentAgentID() (string, error) {
	token, err := am.LoadToken()
	if err != nil {
		return "", fmt.Errorf("failed to load token: %w", err)
	}

	if token.AgentID == "" {
		return "", fmt.Errorf("agent ID not found in token")
	}

	return token.AgentID, nil
}

// GetCurrentAccessToken retrieves a valid access token, refreshing if needed
func (am *AuthManager) GetCurrentAccessToken() (string, error) {
	token, err := am.EnsureAuthenticated()
	if err != nil {
		return "", fmt.Errorf("failed to ensure authentication: %w", err)
	}

	return token.AccessToken, nil
}

// AuthenticatedDo performs an HTTP request with automatic token injection,
// infinite retry with exponential backoff, and token refreshing on 401.
// The agent NEVER gives up on connection errors - it will keep retrying forever
// with increasing delays (up to the configured maximum).
func (am *AuthManager) AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	// Infinite retry loop - agent NEVER gives up
	for {
		// Load token (raw, ignoring expiration check to allow refresh flow)
		token, err := am.loadTokenRaw()
		if err != nil {
			// Token loading is a local error - no point retrying forever for this
			return nil, fmt.Errorf("failed to load token: %w", err)
		}

		// Check if token is expired locally and try to refresh proactively
		if am.IsTokenExpired(token) && token.RefreshToken != "" {
			logging.Info("Token expired locally, attempting refresh before request...")
			newTokenResp, err := am.RefreshAccessToken(token.RefreshToken)
			if err == nil {
				// Preserve existing refresh token if the API didn't return a new one
				newRefreshToken := token.RefreshToken
				if newTokenResp.RefreshToken != "" {
					newRefreshToken = newTokenResp.RefreshToken
				}
				newToken := &types.AuthToken{
					AccessToken:  newTokenResp.AccessToken,
					RefreshToken: newRefreshToken,
					TokenType:    newTokenResp.TokenType,
					ExpiresAt:    time.Now().Add(time.Duration(newTokenResp.ExpiresIn) * time.Second),
					AgentID:      token.AgentID,
				}
				if err := am.SaveToken(newToken); err == nil {
					token = newToken // Use new token for this request
				} else {
					logging.Warning("Failed to save refreshed token: %v", err)
				}
			} else if isRefreshTokenExpiredError(err) {
				// Refresh token is permanently invalid - clear it and notify
				logging.Error("═══════════════════════════════════════════════════════════════════")
				logging.Error("REFRESH TOKEN EXPIRED OR INVALID")
				logging.Error("Re-registration is required: sudo nannyagent --register")
				logging.Error("═══════════════════════════════════════════════════════════════════")
				token.RefreshToken = ""
				_ = am.SaveToken(token) // Clear the invalid refresh token
				// Proceed with expired access token - will get 401 and wait for registration
			} else {
				logging.Warning("Pre-request refresh failed: %v. Proceeding with existing token...", err)
			}
		}

		req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Set default content type if not provided
		if _, ok := headers["Content-Type"]; !ok {
			req.Header.Set("Content-Type", "application/json")
		}

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

		client := am.getClient()
		resp, err := client.Do(req)
		if err != nil {
			// Check if this is a connection-level error
			if isConnectionError(err) {
				// Track connection error and potentially reset transport
				if am.recordConnError() {
					logging.Info("Transport reset triggered by connection error: %v", err)
				}

				// Calculate backoff and wait
				backoff := am.calculateBackoff()
				am.incrementRetryAttempts()
				logging.Warning("Connection error: %v. Retrying in %v (will never give up)", err, backoff)
				time.Sleep(backoff)
				continue
			}

			// Non-connection errors - also retry with backoff
			backoff := am.calculateBackoff()
			am.incrementRetryAttempts()
			logging.Warning("Request error: %v. Retrying in %v", err, backoff)
			client.CloseIdleConnections()
			time.Sleep(backoff)
			continue
		}

		// Successful request - clear all error tracking
		am.clearConnErrors()
		am.resetRetryAttempts()

		if resp.StatusCode == http.StatusUnauthorized {
			_ = resp.Body.Close()

			if token.RefreshToken == "" {
				// No refresh token - need re-registration
				// Log this loudly and wait for user to register
				logging.Error("═══════════════════════════════════════════════════════════════════")
				logging.Error("AUTHENTICATION REQUIRED: No refresh token available.")
				logging.Error("Please run: sudo nannyagent --register")
				logging.Error("═══════════════════════════════════════════════════════════════════")

				backoff := am.calculateBackoff()
				am.incrementRetryAttempts()
				logging.Warning("Waiting %v before retrying (will keep trying after registration)...", backoff)
				time.Sleep(backoff)
				continue
			}

			// Try refresh
			logging.Info("Token expired, refreshing...")
			newTokenResp, err := am.RefreshAccessToken(token.RefreshToken)
			if err != nil {
				// Check if this is a permanent failure (refresh token expired/invalid)
				if isRefreshTokenExpiredError(err) {
					logging.Error("═══════════════════════════════════════════════════════════════════")
					logging.Error("REFRESH TOKEN EXPIRED OR INVALID")
					logging.Error("The refresh token has expired or been revoked.")
					logging.Error("Re-registration is required: sudo nannyagent --register")
					logging.Error("═══════════════════════════════════════════════════════════════════")

					// Clear the invalid refresh token to avoid retrying with it
					// Keep the agent_id in the token so re-registration can preserve it
					token.RefreshToken = ""
					if saveErr := am.SaveToken(token); saveErr != nil {
						logging.Warning("Failed to clear invalid refresh token: %v", saveErr)
					}

					// Wait with max backoff - user needs to re-register
					maxBackoff := time.Duration(am.config.HTTPTransport.MaxRetryDelaySec) * time.Second
					logging.Warning("Waiting %v before retrying (will succeed after registration)...", maxBackoff)
					time.Sleep(maxBackoff)
					continue
				}

				// Temporary refresh failure - wait and retry
				backoff := am.calculateBackoff()
				am.incrementRetryAttempts()
				logging.Warning("Token refresh failed: %v. Retrying in %v", err, backoff)
				time.Sleep(backoff)
				continue
			}

			// Preserve existing refresh token if the API didn't return a new one
			newRefreshToken := token.RefreshToken
			if newTokenResp.RefreshToken != "" {
				newRefreshToken = newTokenResp.RefreshToken
			}
			newToken := &types.AuthToken{
				AccessToken:  newTokenResp.AccessToken,
				RefreshToken: newRefreshToken,
				TokenType:    newTokenResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(newTokenResp.ExpiresIn) * time.Second),
				AgentID:      token.AgentID,
			}
			if err := am.SaveToken(newToken); err != nil {
				logging.Warning("Failed to save new token: %v", err)
			}

			// Token refreshed - retry immediately
			am.resetRetryAttempts()
			continue
		}

		// If 5xx, the API is having issues - use exponential backoff
		if resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			backoff := am.calculateBackoff()
			am.incrementRetryAttempts()
			logging.Warning("Server error %d. Retrying in %v (will never give up)", resp.StatusCode, backoff)
			time.Sleep(backoff)
			continue
		}

		// Success or client error (4xx except 401) - return response
		return resp, nil
	}
}

// AuthenticatedDoOnce performs an HTTP request with automatic token injection and
// token refreshing on 401, but NO retry logic for server errors (5xx).
// Use this for operations where retrying is not desired (e.g., large file uploads).
func (am *AuthManager) AuthenticatedDoOnce(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	// Load token (raw, ignoring expiration check to allow refresh flow)
	token, err := am.loadTokenRaw()
	if err != nil {
		return nil, fmt.Errorf("failed to load token: %w", err)
	}

	// Check if token is expired locally and try to refresh proactively
	if am.IsTokenExpired(token) && token.RefreshToken != "" {
		logging.Info("Token expired locally, attempting refresh before request...")
		newTokenResp, err := am.RefreshAccessToken(token.RefreshToken)
		if err == nil {
			// Preserve existing refresh token if the API didn't return a new one
			newRefreshToken := token.RefreshToken
			if newTokenResp.RefreshToken != "" {
				newRefreshToken = newTokenResp.RefreshToken
			}
			newToken := &types.AuthToken{
				AccessToken:  newTokenResp.AccessToken,
				RefreshToken: newRefreshToken,
				TokenType:    newTokenResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(newTokenResp.ExpiresIn) * time.Second),
				AgentID:      token.AgentID,
			}
			if err := am.SaveToken(newToken); err == nil {
				token = newToken // Use new token for this request
			} else {
				logging.Warning("Failed to save refreshed token: %v", err)
			}
		} else {
			logging.Warning("Pre-request refresh failed: %v. Proceeding with existing token...", err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default content type if not provided
	if _, ok := headers["Content-Type"]; !ok {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := am.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle 401 by trying to refresh token once
	if resp.StatusCode == http.StatusUnauthorized && token.RefreshToken != "" {
		_ = resp.Body.Close()

		logging.Info("Token expired, refreshing...")
		newTokenResp, err := am.RefreshAccessToken(token.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}

		// Preserve existing refresh token if the API didn't return a new one
		newRefreshToken := token.RefreshToken
		if newTokenResp.RefreshToken != "" {
			newRefreshToken = newTokenResp.RefreshToken
		}
		newToken := &types.AuthToken{
			AccessToken:  newTokenResp.AccessToken,
			RefreshToken: newRefreshToken,
			TokenType:    newTokenResp.TokenType,
			ExpiresAt:    time.Now().Add(time.Duration(newTokenResp.ExpiresIn) * time.Second),
			AgentID:      token.AgentID,
		}
		if err := am.SaveToken(newToken); err != nil {
			return nil, fmt.Errorf("failed to save new token: %w", err)
		}

		// Retry once with new token
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		if _, ok := headers["Content-Type"]; !ok {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Authorization", "Bearer "+newToken.AccessToken)

		resp, err = am.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed after token refresh: %w", err)
		}
	}

	return resp, nil
}

// AuthenticatedRequest performs an authenticated request and returns the status code and response body.
// It handles token refresh, retries, AND connection resets on failure.
// When HTTP/2 connection errors persist (like "response body closed"), it triggers a full
// transport reset to recover from stale connections.
// The agent NEVER gives up - retry will continue indefinitely with exponential backoff.
// usage: Prefer this over AuthenticatedDo when you need to read the full body string/JSON.
func (am *AuthManager) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	// Infinite retry loop - agent NEVER gives up
	for {
		// Use AuthenticatedDo for the request (handles 401s, 500s, and transport errors during request)
		// AuthenticatedDo itself never gives up, but if we get here there's a response to read
		resp, err := am.AuthenticatedDo(method, url, body, headers)
		if err != nil {
			// AuthenticatedDo only returns errors for truly unrecoverable issues (like no token file)
			return 0, nil, err
		}

		statusCode := resp.StatusCode
		// Read the body
		// We use a specific pattern here: read fully, then close immediately.
		// Use io.ReadAll to ensure we get everything or fail trying.
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr == nil {
			// Success - clear any error tracking
			am.clearConnErrors()
			am.resetRetryAttempts()
			return statusCode, respBody, nil
		}

		// If read failed, the response is unusable.
		// Check if it's a connection-level error
		if isConnectionError(readErr) {
			// Track connection error and potentially reset transport
			if am.recordConnError() {
				logging.Info("Transport reset triggered by response read error: %v", readErr)
			}

			// Calculate backoff and wait - never give up
			backoff := am.calculateBackoff()
			am.incrementRetryAttempts()
			logging.Warning("Response read error: %v. Retrying in %v (will never give up)", readErr, backoff)
			time.Sleep(backoff)
			continue
		}

		// Non-connection read error - also retry with backoff
		backoff := am.calculateBackoff()
		am.incrementRetryAttempts()
		logging.Warning("Failed to read response body: %v. Retrying in %v", readErr, backoff)
		am.getClient().CloseIdleConnections()
		time.Sleep(backoff)
	}
}

// Helper functions

func (am *AuthManager) getTokenPath() string {
	if am.config.TokenPath != "" {
		return am.config.TokenPath
	}
	return filepath.Join(TokenStorageDir, TokenStorageFile)
}

func (am *AuthManager) loadRefreshTokenFromBackup() (string, error) {
	tokenPath := am.getTokenPath()
	dir := filepath.Dir(tokenPath)
	refreshTokenPath := filepath.Join(dir, RefreshTokenFile)

	data, err := os.ReadFile(refreshTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read refresh token backup: %w", err)
	}

	refreshToken := strings.TrimSpace(string(data))
	if refreshToken == "" {
		return "", fmt.Errorf("refresh token backup is empty")
	}

	return refreshToken, nil
}

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

func getPlatform() string {
	// Get platform from GOOS environment variable or default
	platform := os.Getenv("GOOS")
	if platform == "" {
		// Try to detect from uname
		platform = "linux" // Default for NannyAgent
	}
	return platform
}

func getPlatformFamily() string {
	platform, family, _, err := host.PlatformInformation()
	if err != nil {
		return "unknown"
	}
	// If family is empty, use platform
	if family == "" {
		return platform
	}
	return family
}
