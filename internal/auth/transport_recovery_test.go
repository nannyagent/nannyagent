package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"nannyagent/internal/config"
)

// =============================================================================
// Tests for HTTP/2 Connection Recovery and Exponential Backoff
// These tests verify the behavior described in docs/CONFIGURATION.md
// =============================================================================

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "http2 response body closed",
			err:      &testError{"http2: response body closed"},
			expected: true,
		},
		{
			name:     "read on closed body",
			err:      &testError{"http: read on closed response body"},
			expected: true,
		},
		{
			name:     "connection reset",
			err:      &testError{"connection reset by peer"},
			expected: true,
		},
		{
			name:     "connection refused",
			err:      &testError{"dial tcp: connection refused"},
			expected: true,
		},
		{
			name:     "broken pipe",
			err:      &testError{"write: broken pipe"},
			expected: true,
		},
		{
			name:     "unexpected EOF",
			err:      &testError{"unexpected EOF"},
			expected: true,
		},
		{
			name:     "network unreachable",
			err:      &testError{"network is unreachable"},
			expected: true,
		},
		{
			name:     "i/o timeout",
			err:      &testError{"i/o timeout"},
			expected: true,
		},
		{
			name:     "tls error",
			err:      &testError{"tls: handshake failure"},
			expected: true,
		},
		{
			name:     "no such host",
			err:      &testError{"no such host"},
			expected: true,
		},
		{
			name:     "regular error - not connection related",
			err:      &testError{"invalid JSON"},
			expected: false,
		},
		{
			name:     "authorization error",
			err:      &testError{"unauthorized"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isConnectionError(tt.err)
			if result != tt.expected {
				t.Errorf("isConnectionError(%q) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// =============================================================================
// Tests for Refresh Token Expiry Detection
// These tests verify the agent correctly detects when re-registration is needed
// =============================================================================

func TestIsRefreshTokenExpiredError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "refresh_token expired",
			err:      &testError{"token refresh failed: refresh_token has expired"},
			expected: true,
		},
		{
			name:     "refresh_token invalid",
			err:      &testError{"refresh_token is invalid or revoked"},
			expected: true,
		},
		{
			name:     "refresh token revoked",
			err:      &testError{"error: refresh_token revoked"},
			expected: true,
		},
		{
			name:     "401 status code",
			err:      &testError{"token refresh failed with status 401: unauthorized"},
			expected: true,
		},
		{
			name:     "403 status code",
			err:      &testError{"token refresh failed with status 403: forbidden"},
			expected: true,
		},
		{
			name:     "generic token expired",
			err:      &testError{"token expired please re-authenticate"},
			expected: true,
		},
		{
			name:     "token invalid",
			err:      &testError{"the token is invalid"},
			expected: true,
		},
		{
			name:     "token not found",
			err:      &testError{"token not found in database"},
			expected: true,
		},
		{
			name:     "connection error - not permanent",
			err:      &testError{"connection refused"},
			expected: false,
		},
		{
			name:     "500 server error - not permanent",
			err:      &testError{"token refresh failed with status 500: internal server error"},
			expected: false,
		},
		{
			name:     "network timeout - not permanent",
			err:      &testError{"failed to refresh token: i/o timeout"},
			expected: false,
		},
		{
			name:     "generic error - not permanent",
			err:      &testError{"something went wrong"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRefreshTokenExpiredError(tt.err)
			if result != tt.expected {
				t.Errorf("isRefreshTokenExpiredError(%q) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestCalculateBackoff(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "backoff_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	cfg := &config.Config{
		APIBaseURL: "http://localhost:8080",
		TokenPath:  tokenPath,
		HTTPTransport: config.HTTPTransportConfig{
			InitialRetryDelaySec:    1,  // 1 second for faster testing
			MaxRetryDelaySec:        10, // 10 seconds max
			TransportResetThreshold: 3,
		},
	}
	// Apply defaults for any missing fields
	cfg.HTTPTransport.ApplyDefaults()

	am := NewAuthManager(cfg)

	tests := []struct {
		name          string
		retryAttempts int
		expectedMin   time.Duration
		expectedMax   time.Duration
	}{
		{
			name:          "first attempt",
			retryAttempts: 0,
			expectedMin:   1 * time.Second,
			expectedMax:   1 * time.Second,
		},
		{
			name:          "second attempt (2^1)",
			retryAttempts: 1,
			expectedMin:   2 * time.Second,
			expectedMax:   2 * time.Second,
		},
		{
			name:          "third attempt (2^2)",
			retryAttempts: 2,
			expectedMin:   4 * time.Second,
			expectedMax:   4 * time.Second,
		},
		{
			name:          "fourth attempt (2^3 = 8)",
			retryAttempts: 3,
			expectedMin:   8 * time.Second,
			expectedMax:   8 * time.Second,
		},
		{
			name:          "fifth attempt (2^4 = 16, capped at max 10)",
			retryAttempts: 4,
			expectedMin:   10 * time.Second, // Capped at max
			expectedMax:   10 * time.Second,
		},
		{
			name:          "many attempts (always capped at max)",
			retryAttempts: 100,
			expectedMin:   10 * time.Second,
			expectedMax:   10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset retry attempts
			am.mu.Lock()
			am.retryAttempts = tt.retryAttempts
			am.mu.Unlock()

			backoff := am.calculateBackoff()
			if backoff < tt.expectedMin || backoff > tt.expectedMax {
				t.Errorf("calculateBackoff() with %d attempts = %v, want between %v and %v",
					tt.retryAttempts, backoff, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestTransportResetAfterConsecutiveErrors(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "transport_reset_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	cfg := &config.Config{
		APIBaseURL: "http://localhost:8080",
		TokenPath:  tokenPath,
		HTTPTransport: config.HTTPTransportConfig{
			TransportResetThreshold: 3, // Reset after 3 consecutive errors
			MaxIdleConns:            10,
			MaxIdleConnsPerHost:     5,
			IdleConnTimeoutSec:      30,
		},
	}
	cfg.HTTPTransport.ApplyDefaults()

	am := NewAuthManager(cfg)

	// Keep track of original transport
	originalTransport := am.transport

	// First error - should not reset
	wasReset := am.recordConnError()
	if wasReset {
		t.Error("Transport should not reset after 1 error")
	}
	if am.transport != originalTransport {
		t.Error("Transport was replaced after 1 error")
	}

	// Second error - should not reset
	wasReset = am.recordConnError()
	if wasReset {
		t.Error("Transport should not reset after 2 errors")
	}
	if am.transport != originalTransport {
		t.Error("Transport was replaced after 2 errors")
	}

	// Third error - should trigger reset
	wasReset = am.recordConnError()
	if !wasReset {
		t.Error("Transport should have been reset after 3 errors")
	}
	if am.transport == originalTransport {
		t.Error("Transport was not replaced after threshold reached")
	}

	// Verify error counter was reset
	am.mu.RLock()
	errorCount := am.consecutiveConnErrors
	am.mu.RUnlock()
	if errorCount != 0 {
		t.Errorf("Error counter should be 0 after reset, got %d", errorCount)
	}
}

func TestClearConnErrorsOnSuccess(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "clear_errors_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	cfg := &config.Config{
		APIBaseURL: "http://localhost:8080",
		TokenPath:  tokenPath,
		HTTPTransport: config.HTTPTransportConfig{
			TransportResetThreshold: 5,
		},
	}
	cfg.HTTPTransport.ApplyDefaults()

	am := NewAuthManager(cfg)

	// Record some errors (but not enough to trigger reset)
	am.recordConnError()
	am.recordConnError()

	// Verify error count
	am.mu.RLock()
	errorCount := am.consecutiveConnErrors
	am.mu.RUnlock()
	if errorCount != 2 {
		t.Errorf("Expected 2 errors, got %d", errorCount)
	}

	// Clear errors (simulating successful request)
	am.clearConnErrors()

	// Verify errors were cleared
	am.mu.RLock()
	errorCount = am.consecutiveConnErrors
	am.mu.RUnlock()
	if errorCount != 0 {
		t.Errorf("Expected 0 errors after clear, got %d", errorCount)
	}
}

func TestRetryAttemptsTracking(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "retry_tracking_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	cfg := &config.Config{
		APIBaseURL: "http://localhost:8080",
		TokenPath:  tokenPath,
		HTTPTransport: config.HTTPTransportConfig{
			InitialRetryDelaySec: 1,
			MaxRetryDelaySec:     60,
		},
	}
	cfg.HTTPTransport.ApplyDefaults()

	am := NewAuthManager(cfg)

	// Initial state
	am.mu.RLock()
	initialAttempts := am.retryAttempts
	am.mu.RUnlock()
	if initialAttempts != 0 {
		t.Errorf("Initial retry attempts should be 0, got %d", initialAttempts)
	}

	// Increment attempts
	am.incrementRetryAttempts()
	am.incrementRetryAttempts()
	am.incrementRetryAttempts()

	am.mu.RLock()
	attempts := am.retryAttempts
	am.mu.RUnlock()
	if attempts != 3 {
		t.Errorf("Expected 3 retry attempts, got %d", attempts)
	}

	// Reset attempts
	am.resetRetryAttempts()

	am.mu.RLock()
	attempts = am.retryAttempts
	am.mu.RUnlock()
	if attempts != 0 {
		t.Errorf("Expected 0 retry attempts after reset, got %d", attempts)
	}
}

func TestNewAuthManagerWithHTTPTransportConfig(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "auth_manager_config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	// Test with custom configuration
	cfg := &config.Config{
		APIBaseURL: "http://localhost:8080",
		TokenPath:  tokenPath,
		HTTPTransport: config.HTTPTransportConfig{
			MaxIdleConns:             20,
			MaxIdleConnsPerHost:      10,
			IdleConnTimeoutSec:       60,
			ResponseHeaderTimeoutSec: 45,
			DisableHTTP2:             true,
			TransportResetThreshold:  5,
			InitialRetryDelaySec:     5,
			MaxRetryDelaySec:         300,
		},
	}

	am := NewAuthManager(cfg)

	// Verify transport was created
	if am.transport == nil {
		t.Error("Transport should not be nil")
	}

	// Verify client was created
	if am.client == nil {
		t.Error("Client should not be nil")
	}

	// Verify config was stored
	if am.config != cfg {
		t.Error("Config was not stored correctly")
	}

	// Verify base URL was set
	if am.baseURL != "http://localhost:8080" {
		t.Errorf("Expected baseURL 'http://localhost:8080', got '%s'", am.baseURL)
	}
}
