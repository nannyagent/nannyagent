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
	"nannyagent/internal/types"
)

// refreshHandlerNoRefreshToken simulates an API that returns a new access_token but NO refresh_token
// in the body (the real-world behavior of the /api/agent refresh action).
func refreshHandlerNoRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req types.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Action == "refresh" {
		resp := types.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "", // intentionally empty — API never returns this on refresh
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			AgentID:      "test_agent_id",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// TestRefreshDoesNotDestroyRefreshToken verifies that when the API returns an empty
// refresh_token during a refresh call, the existing refresh_token is preserved on disk.
// This was the root cause of the production auth failure.
func TestRefreshDoesNotDestroyRefreshToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.json")

	original := &types.AuthToken{
		AccessToken:  "expired_access_token",
		RefreshToken: "precious_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		AgentID:      "test_agent_id",
	}
	data, _ := json.Marshal(original)
	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		t.Fatalf("Failed to write token: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent" {
			refreshHandlerNoRefreshToken(w, r)
			return
		}
		if r.URL.Path == "/api/test" && r.Header.Get("Authorization") == "Bearer new_access_token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()

	am := NewAuthManager(&config.Config{APIBaseURL: ts.URL, TokenPath: tokenPath})
	resp, err := am.AuthenticatedDo("GET", ts.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("AuthenticatedDo failed: %v", err)
	}
	_ = resp.Body.Close()

	saved, err := am.loadTokenRaw()
	if err != nil {
		t.Fatalf("Failed to read saved token: %v", err)
	}
	if saved.RefreshToken != "precious_refresh_token" {
		t.Errorf("Refresh token was destroyed: expected 'precious_refresh_token', got '%s'", saved.RefreshToken)
	}
}

// TestRefreshDoesNotDestroyRefreshToken_401 is the same test but triggered via a 401 response
// (the other code path where the bug also existed).
func TestRefreshDoesNotDestroyRefreshToken_401(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.json")

	original := &types.AuthToken{
		AccessToken:  "stale_access_token",
		RefreshToken: "precious_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour), // looks valid locally but server returns 401
		AgentID:      "test_agent_id",
	}
	data, _ := json.Marshal(original)
	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		t.Fatalf("Failed to write token: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent" {
			refreshHandlerNoRefreshToken(w, r)
			return
		}
		if r.URL.Path == "/api/test" {
			switch r.Header.Get("Authorization") {
			case "Bearer stale_access_token":
				w.WriteHeader(http.StatusUnauthorized)
			case "Bearer new_access_token":
				w.WriteHeader(http.StatusOK)
			default:
				http.Error(w, "unexpected", http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()

	am := NewAuthManager(&config.Config{APIBaseURL: ts.URL, TokenPath: tokenPath})
	resp, err := am.AuthenticatedDo("GET", ts.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("AuthenticatedDo failed: %v", err)
	}
	_ = resp.Body.Close()

	saved, err := am.loadTokenRaw()
	if err != nil {
		t.Fatalf("Failed to read saved token: %v", err)
	}
	if saved.RefreshToken != "precious_refresh_token" {
		t.Errorf("Refresh token was destroyed on 401 retry: expected 'precious_refresh_token', got '%s'", saved.RefreshToken)
	}
}

// TestNeedsRefreshTokenRenewal verifies the threshold logic.
func TestNeedsRefreshTokenRenewal(t *testing.T) {
	cases := []struct {
		name          string
		expiresIn     int
		thresholdDays int
		want          bool
	}{
		{"zero expiresIn means unknown, skip renewal", 0, 7, false},
		{"well outside threshold", 30 * 24 * 3600, 7, false},
		{"exactly at threshold boundary", 7 * 24 * 3600, 7, false},
		{"one second inside threshold", 7*24*3600 - 1, 7, true},
		{"deep inside threshold", 3 * 24 * 3600, 7, true},
		{"almost expired", 60, 7, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NeedsRefreshTokenRenewal(tc.expiresIn, tc.thresholdDays)
			if got != tc.want {
				t.Errorf("NeedsRefreshTokenRenewal(%d, %d) = %v, want %v", tc.expiresIn, tc.thresholdDays, got, tc.want)
			}
		})
	}
}

// TestRenewRefreshToken_Success verifies that RenewRefreshToken returns a new token pair.
func TestRenewRefreshToken_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Action != "renew-refresh-token" {
			http.Error(w, "wrong action", http.StatusBadRequest)
			return
		}
		if req.RefreshToken != "old_refresh_token" {
			http.Error(w, "wrong token", http.StatusUnauthorized)
			return
		}
		resp := types.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "rotated_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	am := NewAuthManager(&config.Config{APIBaseURL: ts.URL})
	resp, err := am.RenewRefreshToken("old_refresh_token")
	if err != nil {
		t.Fatalf("RenewRefreshToken failed: %v", err)
	}
	if resp.RefreshToken != "rotated_refresh_token" {
		t.Errorf("Expected rotated_refresh_token, got %q", resp.RefreshToken)
	}
	if resp.AccessToken != "new_access_token" {
		t.Errorf("Expected new_access_token, got %q", resp.AccessToken)
	}
}

// TestRenewRefreshToken_ServerError verifies that a server error is returned as an error,
// not silently ignored.
func TestRenewRefreshToken_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	am := NewAuthManager(&config.Config{APIBaseURL: ts.URL})
	_, err := am.RenewRefreshToken("some_token")
	if err == nil {
		t.Error("Expected error from server 503, got nil")
	}
}

func TestAuthenticatedDo_ExpiredToken(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "auth_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	tokenPath := filepath.Join(tmpDir, "token.json")

	// Create an expired token
	expiredToken := &types.AuthToken{
		AccessToken:  "expired_access_token",
		RefreshToken: "valid_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		AgentID:      "test_agent_id",
	}

	tokenData, _ := json.Marshal(expiredToken)
	if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
		t.Fatalf("Failed to write expired token: %v", err)
	}

	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a refresh request
		if r.Method == "POST" && r.URL.Path == "/api/agent" {
			var req types.RefreshRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.Action == "refresh" && req.RefreshToken == "valid_refresh_token" {
				// Return new token
				resp := types.TokenResponse{
					AccessToken:  "new_access_token",
					RefreshToken: "new_refresh_token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					AgentID:      "test_agent_id",
				}
				err := json.NewEncoder(w).Encode(resp)
				if err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					return
				}
				return
			}
		}

		// Check if it's the actual request
		if r.URL.Path == "/api/test" {
			authHeader := r.Header.Get("Authorization")
			switch authHeader {
			case "Bearer new_access_token":
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("success"))
				if err != nil {
					http.Error(w, "Failed to write response", http.StatusInternalServerError)
					return
				}
				return
			case "Bearer expired_access_token":
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		http.Error(w, "Not found or unauthorized", http.StatusNotFound)
	}))
	defer ts.Close()

	// Initialize AuthManager
	cfg := &config.Config{
		APIBaseURL: ts.URL,
		TokenPath:  tokenPath,
	}
	am := NewAuthManager(cfg)

	// Perform AuthenticatedDo
	resp, err := am.AuthenticatedDo("GET", ts.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("AuthenticatedDo failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify that the token file was updated
	newTokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	var newToken types.AuthToken
	if err := json.Unmarshal(newTokenData, &newToken); err != nil {
		t.Fatalf("Failed to parse new token: %v", err)
	}

	if newToken.AccessToken != "new_access_token" {
		t.Errorf("Token file was not updated with new access token")
	}
}

func TestAuthenticatedDo_401Retry(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "auth_test_401")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	// Create a valid token (locally)
	validToken := &types.AuthToken{
		AccessToken:  "valid_access_token_locally",
		RefreshToken: "valid_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour), // Valid for 1 hour
		AgentID:      "test_agent_id",
	}

	tokenData, _ := json.Marshal(validToken)
	if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
		t.Fatalf("Failed to write token: %v", err)
	}

	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a refresh request
		if r.Method == "POST" && r.URL.Path == "/api/agent" {
			var req types.RefreshRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.Action == "refresh" && req.RefreshToken == "valid_refresh_token" {
				// Return new token
				resp := types.TokenResponse{
					AccessToken:  "new_access_token",
					RefreshToken: "new_refresh_token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					AgentID:      "test_agent_id",
				}
				err := json.NewEncoder(w).Encode(resp)
				if err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					return
				}
				return
			}
		}

		// Check if it's the actual request
		if r.URL.Path == "/api/test" {
			authHeader := r.Header.Get("Authorization")
			switch authHeader {
			case "Bearer new_access_token":
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("success"))
				if err != nil {
					http.Error(w, "Failed to write response", http.StatusInternalServerError)
					return
				}
				return
			case "Bearer valid_access_token_locally":
				// Simulate 401 even if token looks valid locally
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		http.Error(w, "Not found or unauthorized", http.StatusNotFound)
	}))
	defer ts.Close()

	// Initialize AuthManager
	cfg := &config.Config{
		APIBaseURL: ts.URL,
		TokenPath:  tokenPath,
	}
	am := NewAuthManager(cfg)

	// Perform AuthenticatedDo
	resp, err := am.AuthenticatedDo("GET", ts.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("AuthenticatedDo failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify that the token file was updated
	newTokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	var newToken types.AuthToken
	if err := json.Unmarshal(newTokenData, &newToken); err != nil {
		t.Fatalf("Failed to parse new token: %v", err)
	}

	if newToken.AccessToken != "new_access_token" {
		t.Errorf("Token file was not updated with new access token")
	}
}
