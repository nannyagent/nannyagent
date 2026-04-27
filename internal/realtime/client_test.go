package realtime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nannyagent/internal/types"
)

// staticTokenProvider is a test double that always returns the same token.
type staticTokenProvider struct{ token string }

func (s *staticTokenProvider) GetCurrentAccessToken() (string, error) { return s.token, nil }

func mockToken(t string) TokenProvider { return &staticTokenProvider{token: t} }

func TestClient_Start(t *testing.T) {
	// Create a mock SSE server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/realtime" {
			switch r.Method {
			case "GET":
				// Handshake
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")

				// Send clientId
				_, _ = fmt.Fprintf(w, "data: {\"clientId\": \"test-client-id\"}\n\n")
				w.(http.Flusher).Flush()

				// Wait for subscription (simulated)
				time.Sleep(100 * time.Millisecond)

				// Send an event
				_, _ = fmt.Fprintf(w, "data: {\"action\": \"create\", \"record\": {\"id\": \"inv-123\", \"user_prompt\": \"test prompt\"}}\n\n")
				w.(http.Flusher).Flush()

				// Keep connection open for a bit
				time.Sleep(1 * time.Second)
				return
			case "POST":
				// Subscription
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Channel to signal test completion
	done := make(chan struct{})

	// Handler to verify callback
	handler := func(id, prompt string) {
		if id != "inv-123" {
			t.Errorf("Expected investigation ID 'inv-123', got '%s'", id)
		}
		if prompt != "test prompt" {
			t.Errorf("Expected prompt 'test prompt', got '%s'", prompt)
		}
		close(done)
	}

	client := NewClient(server.URL, mockToken("test-token"), handler, nil, nil)

	// Run Start in a goroutine
	go client.Start()

	// Wait for handler to be called or timeout
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for investigation handler")
	}
}

// TestCalculateBackoff tests the exponential backoff calculation
func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, InitialBackoff},     // First attempt: 30s
		{1, 60 * time.Second},   // Second attempt: 30s * 2^1 = 60s
		{2, 120 * time.Second},  // Third attempt: 30s * 2^2 = 120s
		{3, 240 * time.Second},  // Fourth attempt: 30s * 2^3 = 240s
		{4, 480 * time.Second},  // Fifth attempt: 30s * 2^4 = 480s
		{5, 960 * time.Second},  // Sixth attempt: 30s * 2^5 = 960s (16m)
		{6, 1920 * time.Second}, // Seventh attempt: 30s * 2^6 = 1920s (32m) -> capped at 30m
		{7, MaxBackoff},         // Capped at max
		{10, MaxBackoff},        // Capped at max
		{100, MaxBackoff},       // Capped at max
	}

	for _, tt := range tests {
		result := CalculateBackoff(tt.attempt)
		// For attempts that would exceed MaxBackoff, check against MaxBackoff
		expected := tt.expected
		if expected > MaxBackoff {
			expected = MaxBackoff
		}
		if result != expected {
			t.Errorf("CalculateBackoff(%d) = %v, expected %v", tt.attempt, result, expected)
		}
	}
}

// TestCalculateBackoff_NeverExceedsMax ensures backoff never exceeds the maximum
func TestCalculateBackoff_NeverExceedsMax(t *testing.T) {
	for attempt := 0; attempt < 1000; attempt++ {
		result := CalculateBackoff(attempt)
		if result > MaxBackoff {
			t.Errorf("CalculateBackoff(%d) = %v, exceeds MaxBackoff %v", attempt, result, MaxBackoff)
		}
	}
}

// TestCalculateBackoff_Constants verifies the constants are set correctly
func TestCalculateBackoff_Constants(t *testing.T) {
	if InitialBackoff != 30*time.Second {
		t.Errorf("InitialBackoff should be 30s, got %v", InitialBackoff)
	}
	if MaxBackoff != 30*time.Minute {
		t.Errorf("MaxBackoff should be 30m, got %v", MaxBackoff)
	}
	if BackoffFactor != 2.0 {
		t.Errorf("BackoffFactor should be 2.0, got %v", BackoffFactor)
	}
}

// TestCalculateBackoff_NegativeAttempt tests handling of negative attempts
func TestCalculateBackoff_NegativeAttempt(t *testing.T) {
	result := CalculateBackoff(-1)
	if result != InitialBackoff {
		t.Errorf("CalculateBackoff(-1) = %v, expected %v", result, InitialBackoff)
	}
}

// TestClient_RebootHandler tests that reboot operations are handled correctly
func TestClient_RebootHandler(t *testing.T) {
	// Create a mock SSE server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/realtime" {
			switch r.Method {
			case "GET":
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")

				// Send clientId
				_, _ = fmt.Fprintf(w, "data: {\"clientId\": \"test-client-id\"}\n\n")
				w.(http.Flusher).Flush()

				time.Sleep(100 * time.Millisecond)

				// Send a reboot operation event
				rebootEvent := `{"action": "create", "record": {"id": "reboot-123", "agent_id": "agent-456", "status": "sent", "timeout_seconds": 300, "reason": "maintenance", "requested_at": "2026-01-24T10:00:00Z"}}`
				_, _ = fmt.Fprintf(w, "data: %s\n\n", rebootEvent)
				w.(http.Flusher).Flush()

				time.Sleep(1 * time.Second)
				return
			case "POST":
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	done := make(chan struct{})

	rebootHandler := func(payload types.AgentRebootPayload) {
		if payload.RebootID != "reboot-123" {
			t.Errorf("Expected RebootID 'reboot-123', got '%s'", payload.RebootID)
		}
		if payload.AgentID != "agent-456" {
			t.Errorf("Expected AgentID 'agent-456', got '%s'", payload.AgentID)
		}
		if payload.TimeoutSeconds != 300 {
			t.Errorf("Expected TimeoutSeconds 300, got %d", payload.TimeoutSeconds)
		}
		close(done)
	}

	client := NewClient(server.URL, mockToken("test-token"), nil, nil, rebootHandler)

	go client.Start()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for reboot handler")
	}
}

// TestClient_PatchHandler tests that patch operations are handled correctly
func TestClient_PatchHandler(t *testing.T) {
	// Create a mock SSE server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/realtime" {
			switch r.Method {
			case "GET":
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")

				_, _ = fmt.Fprintf(w, "data: {\"clientId\": \"test-client-id\"}\n\n")
				w.(http.Flusher).Flush()

				time.Sleep(100 * time.Millisecond)

				// Send a patch operation event
				patchEvent := `{"action": "create", "record": {"id": "patch-123", "mode": "dry-run", "script_id": "script-456", "script_url": "/scripts/test.sh"}}`
				_, _ = fmt.Fprintf(w, "data: %s\n\n", patchEvent)
				w.(http.Flusher).Flush()

				time.Sleep(1 * time.Second)
				return
			case "POST":
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	done := make(chan struct{})

	patchHandler := func(payload types.AgentPatchPayload) {
		if payload.OperationID != "patch-123" {
			t.Errorf("Expected OperationID 'patch-123', got '%s'", payload.OperationID)
		}
		if payload.Mode != "dry-run" {
			t.Errorf("Expected Mode 'dry-run', got '%s'", payload.Mode)
		}
		close(done)
	}

	client := NewClient(server.URL, mockToken("test-token"), nil, patchHandler, nil)

	go client.Start()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for patch handler")
	}
}
