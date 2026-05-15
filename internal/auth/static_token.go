package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"nannyagent/internal/config"
	"nannyagent/internal/hostinfo"
	"nannyagent/internal/logging"
	"nannyagent/internal/nannyapi"
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
		client:    newHTTPClient(transport),
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
	metadata := hostinfo.Collect()

	payload := staticRegisterRequest{
		Action:         nannyapi.ActionRegisterWithToken,
		Hostname:       metadata.Hostname,
		OSType:         metadata.Platform,
		PlatformFamily: metadata.PlatformFamily,
		Version:        version,
		PrimaryIP:      metadata.PrimaryIP,
		KernelVersion:  metadata.KernelVersion,
		AllIPs:         metadata.AllIPs,
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

// AuthenticatedRequest performs an HTTP request with the static token and
// X-Agent-ID header. Retries indefinitely on connection errors with
// exponential backoff (same resilience as OAuth AuthManager).
func (sm *StaticTokenAuthManager) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	return authenticatedRequestWithRetry(sm, func() (*http.Response, error) {
		return sm.AuthenticatedDo(method, url, body, headers)
	}, responseRetryLogConfig{
		transportResetFormat: "Static token: transport reset triggered by read error: %v",
		connectionReadFormat: "Static token: read error: %v. Retrying in %v",
		readFormat:           "Static token: read error: %v. Retrying in %v",
	})
}

// AuthenticatedDo performs an HTTP request with static token auth and infinite
// retry on connection/server errors. Returns the http.Response for callers that
// need streaming or custom body handling.
func (sm *StaticTokenAuthManager) AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	for {
		req, err := newAPIRequest(method, url, body, headers)
		if err != nil {
			return nil, err
		}

		// Static token auth
		setBearerAuthorization(req, sm.token)

		// X-Agent-ID to act as the specific agent
		sm.mu.RLock()
		agentID := sm.agentID
		sm.mu.RUnlock()
		setAgentIDHeader(req, agentID)

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

	return calculateBackoff(attempts, tc)
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
	sm.client = newHTTPClient(sm.transport)
	sm.consecutiveConnErrors = 0
}

func (sm *StaticTokenAuthManager) getClient() *http.Client {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.client
}
