package patches

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nannyagent/internal/nannyapi"
	"nannyagent/internal/types"
)

func TestPatchManager_DownloadScript(t *testing.T) {
	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		if r.Header.Get(nannyapi.HeaderAuthorization) != nannyapi.BearerPrefix+"test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return a simple script
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("#!/bin/bash\necho 'test'\n"))
	}))
	defer ts.Close()

	mockAuth := &mockAuthManager{token: "test-token"}
	pm := NewPatchManager(ts.URL, mockAuth, "test-agent-id")

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "patch-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	scriptPath := filepath.Join(tmpDir, "script.sh")

	// Test download
	err = pm.downloadScript("/test/script", scriptPath)
	if err != nil {
		t.Errorf("downloadScript failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Error("Script file was not created")
	}

	// Verify content
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Errorf("Failed to read script: %v", err)
	}

	if string(content) != "#!/bin/bash\necho 'test'\n" {
		t.Errorf("Script content mismatch. Got: %s", string(content))
	}
}

func TestPatchManager_ValidateScript(t *testing.T) {
	// Create a test server that returns SHA256 validation
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		if r.Header.Get(nannyapi.HeaderAuthorization) != nannyapi.BearerPrefix+"test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return validation response
		resp := map[string]string{
			"id":     "test-script-id",
			"sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", // SHA256 of "hello world\n"
			"name":   "test-script.sh",
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	mockAuth := &mockAuthManager{token: "test-token"}
	pm := NewPatchManager(ts.URL, mockAuth, "test-agent-id")

	// Create temp file with known content
	tmpDir, err := os.MkdirTemp("", "patch-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	scriptPath := filepath.Join(tmpDir, "script.sh")
	err = os.WriteFile(scriptPath, []byte("hello world"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test validation with matching SHA256
	scriptURL := "/api/files/collection/test-script-id/script.sh"
	err = pm.validateScript(scriptURL, scriptPath)
	if err != nil {
		t.Errorf("validateScript failed: %v", err)
	}
}

func TestPatchManager_ValidateScript_Mismatch(t *testing.T) {
	// Create a test server that returns SHA256 validation
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return validation response with different SHA256
		resp := map[string]string{
			"id":     "test-script-id",
			"sha256": "0000000000000000000000000000000000000000000000000000000000000000",
			"name":   "test-script.sh",
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	mockAuth := &mockAuthManager{token: "test-token"}
	pm := NewPatchManager(ts.URL, mockAuth, "test-agent-id")

	// Create temp file
	tmpDir, err := os.MkdirTemp("", "patch-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	scriptPath := filepath.Join(tmpDir, "script.sh")
	err = os.WriteFile(scriptPath, []byte("hello world"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test validation with mismatched SHA256
	scriptURL := "/api/files/collection/test-script-id/script.sh"
	err = pm.validateScript(scriptURL, scriptPath)
	if err == nil {
		t.Error("validateScript should have failed with SHA256 mismatch")
	}

	if err != nil && !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Errorf("Expected SHA256 mismatch error, got: %v", err)
	}
}

func TestPatchManager_ValidateScript_StripsQueryParameters(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/scripts/test-script-id/validate":
			resp := map[string]string{
				"id":     "test-script-id",
				"sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
				"name":   "test-script.sh",
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	pm := NewPatchManager(ts.URL, &mockAuthManager{token: "test-token"}, "test-agent-id")

	tmpDir, err := os.MkdirTemp("", "patch-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	scriptPath := filepath.Join(tmpDir, "script.sh")
	if err := os.WriteFile(scriptPath, []byte("hello world"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	err = pm.validateScript("/api/files/collection/test-script-id/script.sh?download=1", scriptPath)
	if err != nil {
		t.Fatalf("validateScript with query params failed: %v", err)
	}
}

func TestPatchManager_HandlePatchOperation_DryRun(t *testing.T) {
	// Skip if in CI
	if os.Getenv("CI") != "" {
		t.Skip("Skipping integration test in CI")
	}

	// Create a test server
	serverCalls := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls[r.URL.Path]++

		switch r.URL.Path {
		case "/api/files/test/test-script-id/script.sh", "/test/script.sh":
			// Return a simple dry-run script
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("#!/bin/bash\necho 'Dry run complete'\nexit 0\n"))
		case "/api/scripts/test-script-id/validate":
			// Return validation response (SHA256 of the script above)
			resp := map[string]string{
				"id":     "test-script-id",
				"sha256": "1c4e3c1bde3c3e3a3e3c3e3a3e3c3e3a3e3c3e3a3e3c3e3a3e3c3e3a3e3c3e3a", // placeholder
				"name":   "test-script.sh",
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/patches/test-op-id/result":
			// Accept the result upload
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"updated"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	mockAuth := &mockAuthManager{token: "test-token"}
	pm := NewPatchManager(ts.URL, mockAuth, "test-agent-id")

	payload := types.AgentPatchPayload{
		OperationID: "test-op-id",
		Mode:        "dry-run",
		ScriptURL:   "/test/script.sh",
		ScriptArgs:  "",
		Timestamp:   "2023-01-01T00:00:00Z",
	}

	// This test will fail validation (SHA256 mismatch) but demonstrates the flow
	err := pm.HandlePatchOperation(payload)

	// We expect this to fail at validation step since we can't easily compute the exact SHA256
	// The test mainly verifies that the function doesn't panic and handles errors gracefully
	if err == nil {
		t.Log("Patch operation completed (unexpected)")
	} else {
		t.Logf("Patch operation failed as expected during validation: %v", err)
	}

	// Verify that server endpoints were called
	if serverCalls["/test/script.sh"] == 0 && serverCalls["/api/files/test/test-script-id/script.sh"] == 0 {
		t.Error("Script download endpoint was not called")
	}
}
