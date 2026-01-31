package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	config  *config.Config
	client  *http.Client
	baseURL string // NannyAPI API URL
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *config.Config) *AuthManager {
	// Get NannyAPI URL from config
	baseURL := cfg.APIBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("NANNYAPI_URL")
	}

	return &AuthManager{
		config:  cfg,
		baseURL: baseURL,
		client: &http.Client{
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

	resp, err := am.client.Do(req)
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

	resp, err := am.client.Do(req)
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

		resp, err := am.client.Do(req)
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

	resp, err := am.client.Do(req)
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

	resp, err := am.client.Do(req)
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
				RefreshToken: refreshToken,
				TokenType:    refreshResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second),
				AgentID:      agentID,
			}

			// Update refresh token if a new one was provided
			if refreshResp.RefreshToken != "" {
				newToken.RefreshToken = refreshResp.RefreshToken
			}

			if saveErr := am.SaveToken(newToken); saveErr == nil {
				return newToken, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid token available and refresh failed - registration required")
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

// GetCurrentAccessToken retrieves the current access token
func (am *AuthManager) GetCurrentAccessToken() (string, error) {
	token, err := am.LoadToken()
	if err != nil {
		return "", fmt.Errorf("failed to load token: %w", err)
	}

	return token.AccessToken, nil
}

// AuthenticatedDo performs an HTTP request with automatic token injection,
// retry logic (5 attempts, 60s delay), and token refreshing on 401.
func (am *AuthManager) AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= 5; attempt++ {
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
				// Save new token
				newToken := &types.AuthToken{
					AccessToken:  newTokenResp.AccessToken,
					RefreshToken: newTokenResp.RefreshToken,
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
			lastErr = err
			logging.Debug("Request failed (attempt %d): %v. Resetting connection pool.", attempt, err)
			am.client.CloseIdleConnections()
			time.Sleep(60 * time.Second)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			_ = resp.Body.Close()

			if token.RefreshToken == "" {
				return resp, nil
			}

			// Try refresh
			logging.Info("Token expired, refreshing...")
			newTokenResp, err := am.RefreshAccessToken(token.RefreshToken)
			if err != nil {
				lastErr = fmt.Errorf("failed to refresh token: %w", err)
				time.Sleep(60 * time.Second)
				continue
			}

			// Save new token
			newToken := &types.AuthToken{
				AccessToken:  newTokenResp.AccessToken,
				RefreshToken: newTokenResp.RefreshToken,
				TokenType:    newTokenResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(newTokenResp.ExpiresIn) * time.Second),
				AgentID:      token.AgentID,
			}
			if err := am.SaveToken(newToken); err != nil {
				lastErr = fmt.Errorf("failed to save new token: %w", err)
				time.Sleep(60 * time.Second)
				continue
			}

			// Retry immediately with new token
			continue
		}

		// If 5xx, sleep and retry
		if resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			time.Sleep(60 * time.Second)
			continue
		}

		// Success or other error
		return resp, nil
	}

	return nil, fmt.Errorf("request failed after 5 attempts: %v", lastErr)
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
			// Save new token
			newToken := &types.AuthToken{
				AccessToken:  newTokenResp.AccessToken,
				RefreshToken: newTokenResp.RefreshToken,
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

		// Save new token
		newToken := &types.AuthToken{
			AccessToken:  newTokenResp.AccessToken,
			RefreshToken: newTokenResp.RefreshToken,
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
// It handles token refresh, localized retries, AND connection resets on failure.
// usage: Prefer this over AuthenticatedDo when you need to read the full body string/JSON.
func (am *AuthManager) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	var lastErr error
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Use AuthenticatedDo for the request (handles 401s, 500s, and transport errors during request)
		resp, err := am.AuthenticatedDo(method, url, body, headers)
		if err != nil {
			// AuthenticatedDo has its own retry logic, so if it fails, it's a hard fail
			return 0, nil, err
		}

		statusCode := resp.StatusCode
		// Read the body
		// We use a specific pattern here: read fully, then close immediately.
		// Use io.ReadAll to ensure we get everything or fail trying.
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr == nil {
			return statusCode, respBody, nil
		}

		// If read failed, the status code may be valid but the response is unusable.
		// We discard the status code for this attempt since we are retrying.

		// Handle read error (e.g. http2: response body closed)
		lastErr = readErr
		// Only log aggressive connection resets at Debug level unless it's the final attempt
		if attempt < maxRetries {
			logging.Debug("Failed to read response body (attempt %d/%d): %v. Resetting connection pool.", attempt, maxRetries, readErr)
		} else {
			logging.Warning("Failed to read response body (attempt %d/%d): %v. Connection pool reset failed to resolve issue.", attempt, maxRetries, readErr)
		}

		// Force close connections to clear bad state
		am.client.CloseIdleConnections()

		// Wait before retry
		if attempt < maxRetries {
			time.Sleep(5 * time.Second)
		}
	}

	return 0, nil, fmt.Errorf("failed to read response after %d attempts: %w", maxRetries, lastErr)
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
