package auth

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

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
