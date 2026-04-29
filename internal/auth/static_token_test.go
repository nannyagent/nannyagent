package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nannyagent/internal/config"
)

func TestNewStaticTokenAuthManager(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		StaticToken:   "nsk_abc123def456",
		AgentID:       "agent_test_1",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)
	if sm == nil {
		t.Fatal("Expected StaticTokenAuthManager to be created")
	}
	if sm.token != "nsk_abc123def456" {
		t.Errorf("Expected token nsk_abc123def456, got %s", sm.token)
	}
	if sm.agentID != "agent_test_1" {
		t.Errorf("Expected agentID agent_test_1, got %s", sm.agentID)
	}
	if sm.client == nil {
		t.Error("HTTP client not initialized")
	}
}

func TestStaticTokenAuthManager_GetCurrentAgentID(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		StaticToken:   "nsk_abc123",
		AgentID:       "agent_42",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	id, err := sm.GetCurrentAgentID()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if id != "agent_42" {
		t.Errorf("Expected agent_42, got %s", id)
	}
}

func TestStaticTokenAuthManager_GetCurrentAgentID_Missing(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		StaticToken:   "nsk_abc123",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	_, err := sm.GetCurrentAgentID()
	if err == nil {
		t.Error("Expected error for missing agent ID")
	}
}

func TestStaticTokenAuthManager_GetCurrentAccessToken(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		StaticToken:   "nsk_token_value",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	token, err := sm.GetCurrentAccessToken()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if token != "nsk_token_value" {
		t.Errorf("Expected nsk_token_value, got %s", token)
	}
}

func TestStaticTokenAuthManager_GetCurrentAccessToken_Missing(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	_, err := sm.GetCurrentAccessToken()
	if err == nil {
		t.Error("Expected error for missing static token")
	}
}

func TestStaticTokenAuthManager_EnsureAuthenticated(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		StaticToken:   "nsk_valid",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	err := sm.EnsureAuthenticated()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestStaticTokenAuthManager_EnsureAuthenticated_NoToken(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	err := sm.EnsureAuthenticated()
	if err == nil {
		t.Error("Expected error for missing static token")
	}
}

func TestStaticTokenAuthManager_SetAgentID(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:    "http://localhost:8090",
		StaticToken:   "nsk_abc",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	sm.SetAgentID("new_agent_id")
	id, err := sm.GetCurrentAgentID()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if id != "new_agent_id" {
		t.Errorf("Expected new_agent_id, got %s", id)
	}
}

func TestStaticTokenAuthManager_AuthenticatedRequest(t *testing.T) {
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer nsk_test_token_123" {
			t.Errorf("Expected Bearer nsk_test_token_123, got %s", authHeader)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Verify X-Agent-ID header
		agentID := r.Header.Get("X-Agent-ID")
		if agentID != "agent_abc" {
			t.Errorf("Expected X-Agent-ID agent_abc, got %s", agentID)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{"success": true, "message": "ok"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		APIBaseURL:    server.URL,
		StaticToken:   "nsk_test_token_123",
		AgentID:       "agent_abc",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	statusCode, body, err := sm.AuthenticatedRequest("POST", server.URL+"/api/agent", []byte(`{"action":"ingest-metrics"}`), nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", statusCode)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("Expected success=true, got %v", resp["success"])
	}
}

func TestStaticTokenAuthManager_AuthenticatedRequest_NoAgentID(t *testing.T) {
	// Verify that requests work without X-Agent-ID when agent_id is not set
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer nsk_test_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// X-Agent-ID should NOT be present
		agentID := r.Header.Get("X-Agent-ID")
		if agentID != "" {
			t.Errorf("Expected no X-Agent-ID header, got %s", agentID)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}))
	defer server.Close()

	cfg := &config.Config{
		APIBaseURL:    server.URL,
		StaticToken:   "nsk_test_token",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	statusCode, _, err := sm.AuthenticatedRequest("POST", server.URL+"/api/agent", []byte(`{}`), nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", statusCode)
	}
}

func TestStaticTokenAuthManager_AuthenticatedDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer nsk_do_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		APIBaseURL:    server.URL,
		StaticToken:   "nsk_do_test",
		AgentID:       "agent_do",
		HTTPTransport: config.DefaultHTTPTransportConfig,
	}

	sm := NewStaticTokenAuthManager(cfg)

	resp, err := sm.AuthenticatedDo("GET", server.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestStaticTokenAuthManager_CalculateBackoff(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:  "http://localhost:8090",
		StaticToken: "nsk_test",
		HTTPTransport: config.HTTPTransportConfig{
			InitialRetryDelaySec:    30,
			MaxRetryDelaySec:        1800,
			TransportResetThreshold: 3,
		},
	}

	sm := NewStaticTokenAuthManager(cfg)

	// Initial backoff should be the initial delay
	backoff := sm.calculateBackoff()
	if backoff.Seconds() != 30 {
		t.Errorf("Expected 30s initial backoff, got %v", backoff)
	}

	// After incrementing, backoff should increase
	sm.incrementRetryAttempts()
	backoff = sm.calculateBackoff()
	if backoff.Seconds() != 60 { // 30 * 2^1
		t.Errorf("Expected 60s backoff after 1 attempt, got %v", backoff)
	}

	// Reset should go back to initial
	sm.resetRetryAttempts()
	backoff = sm.calculateBackoff()
	if backoff.Seconds() != 30 {
		t.Errorf("Expected 30s after reset, got %v", backoff)
	}
}

func TestStaticTokenAuthManager_ConnectionErrorTracking(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL:  "http://localhost:8090",
		StaticToken: "nsk_test",
		HTTPTransport: config.HTTPTransportConfig{
			InitialRetryDelaySec:     30,
			MaxRetryDelaySec:         1800,
			TransportResetThreshold:  3,
			MaxIdleConns:             10,
			MaxIdleConnsPerHost:      5,
			IdleConnTimeoutSec:       30,
			ResponseHeaderTimeoutSec: 30,
		},
	}

	sm := NewStaticTokenAuthManager(cfg)

	// Record 2 errors - should not reset
	reset1 := sm.recordConnError()
	if reset1 {
		t.Error("Should not reset after 1 error")
	}
	reset2 := sm.recordConnError()
	if reset2 {
		t.Error("Should not reset after 2 errors")
	}

	// Third error should trigger reset
	reset3 := sm.recordConnError()
	if !reset3 {
		t.Error("Should reset after 3 errors (threshold)")
	}

	// After reset, counter should be back to 0
	sm.mu.RLock()
	if sm.consecutiveConnErrors != 0 {
		t.Errorf("Expected 0 consecutive errors after reset, got %d", sm.consecutiveConnErrors)
	}
	sm.mu.RUnlock()
}
