package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/host"

	"nannyagent/internal/config"
	"nannyagent/internal/logging"
)

// StaticTokenAuthManager handles authentication using a static API token (nsk_*).
// It bypasses the entire OAuth2 device flow, token refresh, and token renewal.
// The static token is sent as a Bearer credential on every request, and an
// X-Agent-ID header identifies the target agent.
type StaticTokenAuthManager struct {
	config    *config.Config
	client    *http.Client
	transport *http.Transport
	mu        sync.RWMutex
	baseURL   string
	agentID   string
	token     string

	// Connection error tracking (same pattern as AuthManager)
	consecutiveConnErrors int
	retryAttempts         int
}

// NewStaticTokenAuthManager creates a new static token auth manager.
func NewStaticTokenAuthManager(cfg *config.Config) *StaticTokenAuthManager {
	baseURL := cfg.APIBaseURL
	transport := createTransport(cfg)

	return &StaticTokenAuthManager{
		config:    cfg,
		baseURL:   baseURL,
		agentID:   cfg.AgentID,
		token:     cfg.StaticToken,
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Minute,
		},
	}
}

// SetAgentID sets the agent ID (called after registration).
func (sm *StaticTokenAuthManager) SetAgentID(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.agentID = id
}

// GetCurrentAgentID returns the configured agent ID.
func (sm *StaticTokenAuthManager) GetCurrentAgentID() (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.agentID == "" {
		return "", fmt.Errorf("agent_id not configured; run --register first")
	}
	return sm.agentID, nil
}

// GetCurrentAccessToken returns the static token. This satisfies the
// realtime.TokenProvider interface so SSE connections work with static tokens.
func (sm *StaticTokenAuthManager) GetCurrentAccessToken() (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.token == "" {
		return "", fmt.Errorf("static token not configured")
	}
	return sm.token, nil
}

// EnsureAuthenticated is a no-op for static tokens (always authenticated).
// Returns nil token since static token mode doesn't use AuthToken structs.
func (sm *StaticTokenAuthManager) EnsureAuthenticated() error {
	if sm.token == "" {
		return fmt.Errorf("static token not configured")
	}
	return nil
}

// staticRegisterRequest is the payload sent to the backend when registering
// an agent via static token.  Uses action "register-with-token" and includes
// system information — no device_code involved.
type staticRegisterRequest struct {
	Action         string   `json:"action"`
	Hostname       string   `json:"hostname"`
	OSType         string   `json:"os_type"`
	PlatformFamily string   `json:"platform_family"`
	Version        string   `json:"version"`
	PrimaryIP      string   `json:"primary_ip"`
	KernelVersion  string   `json:"kernel_version"`
	AllIPs         []string `json:"all_ips"`
}

// StaticRegisterResponse is the response from a static-token registration.
type StaticRegisterResponse struct {
	AgentID          string `json:"agent_id,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Register performs a direct agent registration using the static token.
// It does NOT start a device authorization flow — instead it sends a single
// POST /api/agent { action: "register-with-token" } with the static token
// Authorization header.  The backend creates the agent and returns an agent_id.
func (sm *StaticTokenAuthManager) Register(version string) (*StaticRegisterResponse, error) {
	primaryIP, allIPs := staticGetIPs()

	payload := staticRegisterRequest{
		Action:         "register-with-token",
		Hostname:       staticGetHostname(),
		OSType:         staticGetPlatform(),
		PlatformFamily: staticGetPlatformFamily(),
		Version:        version,
		PrimaryIP:      primaryIP,
		KernelVersion:  staticGetKernelVersion(),
		AllIPs:         allIPs,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register request: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", sm.baseURL)
	statusCode, body, err := sm.AuthenticatedRequest("POST", url, jsonData, nil)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}

	var resp StaticRegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response (status %d): %w", statusCode, err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("registration failed: %s — %s", resp.Error, resp.ErrorDescription)
	}

	if resp.AgentID == "" {
		return nil, fmt.Errorf("registration response missing agent_id (status %d)", statusCode)
	}

	return &resp, nil
}

// ── System-info helpers (package-level, mirror the ones in auth.go) ────────

func staticGetHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

func staticGetPlatform() string {
	platform := os.Getenv("GOOS")
	if platform == "" {
		platform = "linux"
	}
	return platform
}

func staticGetPlatformFamily() string {
	platform, family, _, err := host.PlatformInformation()
	if err != nil {
		return "unknown"
	}
	if family == "" {
		return platform
	}
	return family
}

func staticGetKernelVersion() string {
	version, err := host.KernelVersion()
	if err != nil {
		return "unknown"
	}
	return version
}

// staticGetIPs returns the primary non-loopback IP and a list of all IPs.
func staticGetIPs() (string, []string) {
	var primaryIP string
	var allIPs []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown", nil
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			allIPs = append(allIPs, ip.String())
			if primaryIP == "" && ip.To4() != nil {
				primaryIP = ip.String()
			}
		}
	}

	if primaryIP == "" {
		primaryIP = "unknown"
	}
	return primaryIP, allIPs
}

// AuthenticatedRequest performs an HTTP request with the static token and
// X-Agent-ID header. Retries indefinitely on connection errors with
// exponential backoff (same resilience as OAuth AuthManager).
func (sm *StaticTokenAuthManager) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	for {
		resp, err := sm.AuthenticatedDo(method, url, body, headers)
		if err != nil {
			return 0, nil, err
		}

		statusCode := resp.StatusCode
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr == nil {
			sm.clearConnErrors()
			sm.resetRetryAttempts()
			return statusCode, respBody, nil
		}

		// Body read failed — retry with backoff
		if isConnectionError(readErr) {
			if sm.recordConnError() {
				logging.Info("Static token: transport reset triggered by read error: %v", readErr)
			}
			backoff := sm.calculateBackoff()
			sm.incrementRetryAttempts()
			logging.Warning("Static token: read error: %v. Retrying in %v", readErr, backoff)
			time.Sleep(backoff)
			continue
		}

		backoff := sm.calculateBackoff()
		sm.incrementRetryAttempts()
		logging.Warning("Static token: read error: %v. Retrying in %v", readErr, backoff)
		sm.getClient().CloseIdleConnections()
		time.Sleep(backoff)
	}
}

// AuthenticatedDo performs an HTTP request with static token auth and infinite
// retry on connection/server errors. Returns the http.Response for callers that
// need streaming or custom body handling.
func (sm *StaticTokenAuthManager) AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	for {
		req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Set default content type if not provided
		if headers == nil || headers["Content-Type"] == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Static token auth
		req.Header.Set("Authorization", "Bearer "+sm.token)

		// X-Agent-ID to act as the specific agent
		sm.mu.RLock()
		agentID := sm.agentID
		sm.mu.RUnlock()
		if agentID != "" {
			req.Header.Set("X-Agent-ID", agentID)
		}

		client := sm.getClient()
		resp, err := client.Do(req)
		if err != nil {
			if isConnectionError(err) {
				if sm.recordConnError() {
					logging.Info("Static token: transport reset after connection error: %v", err)
				}
				backoff := sm.calculateBackoff()
				sm.incrementRetryAttempts()
				logging.Warning("Static token: connection error: %v. Retrying in %v (will never give up)", err, backoff)
				time.Sleep(backoff)
				continue
			}

			backoff := sm.calculateBackoff()
			sm.incrementRetryAttempts()
			logging.Warning("Static token: request error: %v. Retrying in %v", err, backoff)
			client.CloseIdleConnections()
			time.Sleep(backoff)
			continue
		}

		sm.clearConnErrors()
		sm.resetRetryAttempts()

		// 401/403 with static token is fatal — don't retry
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return resp, nil
		}

		// 5xx — retry with backoff
		if resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			backoff := sm.calculateBackoff()
			sm.incrementRetryAttempts()
			logging.Warning("Static token: server error %d. Retrying in %v", resp.StatusCode, backoff)
			time.Sleep(backoff)
			continue
		}

		return resp, nil
	}
}

// ── Connection error tracking (mirrors AuthManager) ────────────────────────

func (sm *StaticTokenAuthManager) calculateBackoff() time.Duration {
	sm.mu.RLock()
	attempts := sm.retryAttempts
	tc := sm.config.HTTPTransport
	sm.mu.RUnlock()

	initialDelay := time.Duration(tc.InitialRetryDelaySec) * time.Second
	maxDelay := time.Duration(tc.MaxRetryDelaySec) * time.Second

	if attempts <= 0 {
		return initialDelay
	}
	if attempts > 30 {
		return maxDelay
	}

	backoff := initialDelay * time.Duration(math.Pow(2, float64(attempts)))
	if backoff > maxDelay || backoff <= 0 {
		backoff = maxDelay
	}
	return backoff
}

func (sm *StaticTokenAuthManager) incrementRetryAttempts() {
	sm.mu.Lock()
	sm.retryAttempts++
	sm.mu.Unlock()
}

func (sm *StaticTokenAuthManager) resetRetryAttempts() {
	sm.mu.Lock()
	sm.retryAttempts = 0
	sm.mu.Unlock()
}

func (sm *StaticTokenAuthManager) recordConnError() bool {
	sm.mu.Lock()
	sm.consecutiveConnErrors++
	threshold := sm.config.HTTPTransport.TransportResetThreshold
	shouldReset := sm.consecutiveConnErrors >= threshold
	sm.mu.Unlock()

	if shouldReset {
		sm.resetTransport()
		return true
	}
	return false
}

func (sm *StaticTokenAuthManager) clearConnErrors() {
	sm.mu.Lock()
	sm.consecutiveConnErrors = 0
	sm.mu.Unlock()
}

func (sm *StaticTokenAuthManager) resetTransport() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	logging.Info("Static token: resetting HTTP transport (after %d consecutive errors)",
		sm.consecutiveConnErrors)

	if sm.transport != nil {
		sm.transport.CloseIdleConnections()
	}

	sm.transport = createTransport(sm.config)
	sm.client = &http.Client{
		Transport: sm.transport,
		Timeout:   5 * time.Minute,
	}
	sm.consecutiveConnErrors = 0
}

func (sm *StaticTokenAuthManager) getClient() *http.Client {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.client
}
