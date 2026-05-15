package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nannyagent/internal/config"
	"nannyagent/internal/hostinfo"
	"nannyagent/internal/nannyapi"
	"nannyagent/internal/types"
)

// TestNewAuthManager tests the creation of AuthManager for NannyAPI
func TestNewAuthManager(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL: "http://localhost:8090",
	}

	am := NewAuthManager(cfg)

	if am == nil {
		t.Fatal("Expected AuthManager to be created")
	}
	if am.config != cfg {
		t.Error("Config not set correctly")
	}
	if am.client == nil {
		t.Error("HTTP client not initialized")
	}
	if am.baseURL != "http://localhost:8090" {
		t.Errorf("Expected baseURL http://localhost:8090, got %s", am.baseURL)
	}
}

// TestEnsureTokenStorageDir tests creating the token storage directory
func TestEnsureTokenStorageDir(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	// Clean up first
	_ = os.RemoveAll(TokenStorageDir)

	err := am.EnsureTokenStorageDir()
	if err != nil {
		t.Fatalf("Failed to create token storage dir: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(TokenStorageDir)
	if err != nil {
		t.Fatalf("Token storage dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Token storage path is not a directory")
	}

	// Verify permissions (should be 0700)
	mode := info.Mode().Perm()
	if mode != 0700 {
		t.Errorf("Expected permissions 0700, got %v", mode)
	}
}

// TestEnsureTokenStorageDir_NonRoot tests that non-root fails appropriately
func TestEnsureTokenStorageDir_NonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Skipping non-root test when running as root")
	}

	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	err := am.EnsureTokenStorageDir()
	if err == nil {
		t.Error("Expected error when not running as root")
	}
}

// TestStartDeviceAuthorization tests the NannyAPI device auth request
func TestStartDeviceAuthorization(t *testing.T) {
	// Create test server for NannyAPI API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != nannyapi.EndpointAgent {
			t.Errorf("Expected path %s, got %s", nannyapi.EndpointAgent, r.URL.Path)
		}

		resp := types.DeviceAuthResponse{
			DeviceCode:      "test_device_code_uuid",
			UserCode:        "TESTCDE1",
			VerificationURI: "http://example.com/verify",
			ExpiresIn:       900,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		APIBaseURL: server.URL,
	}
	am := NewAuthManager(cfg)

	resp, err := am.StartDeviceAuthorization()
	if err != nil {
		t.Fatalf("Failed to start device authorization: %v", err)
	}

	if resp.DeviceCode != "test_device_code_uuid" {
		t.Errorf("Expected device code, got '%s'", resp.DeviceCode)
	}
	if resp.UserCode != "TESTCDE1" {
		t.Errorf("Expected user code 'TESTCDE1', got '%s'", resp.UserCode)
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("Expected positive expires_in, got %d", resp.ExpiresIn)
	}
}

// TestRefreshAccessToken tests token refresh
func TestRefreshAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.RefreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Action != nannyapi.ActionRefresh {
			t.Errorf("Expected action='refresh', got '%s'", req.Action)
		}
		if req.RefreshToken != "old_refresh_token" {
			t.Errorf("Expected refresh_token 'old_refresh_token', got '%s'", req.RefreshToken)
		}

		resp := types.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			AgentID:      "test_agent",
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		APIBaseURL: server.URL,
	}
	am := NewAuthManager(cfg)

	resp, err := am.RefreshAccessToken("old_refresh_token")
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	if resp.AccessToken != "new_access_token" {
		t.Errorf("Expected new access token, got '%s'", resp.AccessToken)
	}
	if resp.AgentID != "test_agent" {
		t.Errorf("Expected agent_id 'test_agent', got '%s'", resp.AgentID)
	}
}

// TestSaveAndLoadToken tests token persistence
func TestSaveAndLoadToken(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()

	cfg := &config.Config{
		TokenPath: filepath.Join(tmpDir, "test_token.json"),
	}
	am := NewAuthManager(cfg)

	// Create test token
	token := &types.AuthToken{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AgentID:      "test_agent_id",
	}

	// Need to mock EnsureTokenStorageDir since we're not running as root in tests
	_ = os.MkdirAll(tmpDir, 0700)

	// Save token
	err := am.SaveToken(token)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Load token
	loadedToken, err := am.LoadToken()
	if err != nil {
		t.Fatalf("Failed to load token: %v", err)
	}

	// Verify
	if loadedToken.AccessToken != token.AccessToken {
		t.Errorf("Access token mismatch: expected '%s', got '%s'", token.AccessToken, loadedToken.AccessToken)
	}
	if loadedToken.RefreshToken != token.RefreshToken {
		t.Errorf("Refresh token mismatch: expected '%s', got '%s'", token.RefreshToken, loadedToken.RefreshToken)
	}
	if loadedToken.AgentID != token.AgentID {
		t.Errorf("Agent ID mismatch: expected '%s', got '%s'", token.AgentID, loadedToken.AgentID)
	}
}

// TestLoadToken_Expired tests that expired tokens are rejected
func TestLoadToken_Expired(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		TokenPath: filepath.Join(tmpDir, "test_token.json"),
	}
	am := NewAuthManager(cfg)

	// Create expired token
	token := &types.AuthToken{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Already expired
		AgentID:      "test_agent_id",
	}

	// Mock token storage dir
	_ = os.MkdirAll(tmpDir, 0700)

	// Save token
	err := am.SaveToken(token)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Try to load expired token
	_, err = am.LoadToken()
	if err == nil {
		t.Error("Expected error when loading expired token")
	}
}

// TestIsTokenExpired tests token expiry detection
func TestIsTokenExpired(t *testing.T) {
	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "Valid token (1 hour)",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "Expiring soon (4 minutes)",
			expiresAt: time.Now().Add(4 * time.Minute),
			expected:  true,
		},
		{
			name:      "Already expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &types.AuthToken{
				ExpiresAt: tt.expiresAt,
			}

			result := am.IsTokenExpired(token)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGetTokenPath tests token path resolution
func TestGetTokenPath(t *testing.T) {
	tests := []struct {
		name         string
		configPath   string
		expectedPath string
	}{
		{
			name:         "Custom token path",
			configPath:   "/custom/path/token.json",
			expectedPath: "/custom/path/token.json",
		},
		{
			name:         "Default token path",
			configPath:   "",
			expectedPath: filepath.Join(TokenStorageDir, TokenStorageFile),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				TokenPath: tt.configPath,
			}
			am := NewAuthManager(cfg)

			path := am.getTokenPath()
			if path != tt.expectedPath {
				t.Errorf("Expected path '%s', got '%s'", tt.expectedPath, path)
			}
		})
	}
}

// TestGetHostname tests hostname retrieval
func TestHostInfoHostname(t *testing.T) {
	hostname := hostinfo.Hostname()

	if hostname == "" {
		t.Error("Hostname should not be empty")
	}

	// Should not be longer than reasonable limits
	if len(hostname) > 255 {
		t.Errorf("Hostname too long: %d characters", len(hostname))
	}
}

// TestAuthorizeDeviceCode tests the authorize request
func TestAuthorizeDeviceCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.AuthorizeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Action != nannyapi.ActionAuthorize {
			t.Errorf("Expected action='authorize', got '%s'", req.Action)
		}
		if req.UserCode != "TESTCDE1" {
			t.Errorf("Expected user_code 'TESTCDE1', got '%s'", req.UserCode)
		}

		resp := types.AuthorizeResponse{
			Success: true,
			Message: "Device authorized successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		APIBaseURL: server.URL,
	}
	am := NewAuthManager(cfg)

	err := am.AuthorizeDeviceCode("TESTCDE1")
	if err != nil {
		t.Fatalf("Failed to authorize device code: %v", err)
	}
}
