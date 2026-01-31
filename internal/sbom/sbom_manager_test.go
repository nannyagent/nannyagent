package sbom

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nannyagent/internal/types"
)

// mockAuthManager implements the auth interface for testing
type mockAuthManager struct {
	doOnceFunc func(method, url string, body []byte, headers map[string]string) (*http.Response, error)
}

func (m *mockAuthManager) AuthenticatedDoOnce(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	return m.doOnceFunc(method, url, body, headers)
}

// mockResponse creates a mock HTTP response
func mockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestNewSBOMManager(t *testing.T) {
	mock := &mockAuthManager{}
	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")

	if manager == nil {
		t.Fatal("NewSBOMManager returned nil")
	}
	if manager.baseURL != "http://localhost:8090" {
		t.Errorf("Expected baseURL 'http://localhost:8090', got '%s'", manager.baseURL)
	}
	if manager.agentID != "test-agent-id" {
		t.Errorf("Expected agentID 'test-agent-id', got '%s'", manager.agentID)
	}
}

func TestIsSyftAvailable(t *testing.T) {
	mock := &mockAuthManager{}
	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")

	// This test will pass or fail based on whether syft is actually installed
	available := manager.isSyftAvailable()
	t.Logf("syft available: %v", available)
}

func TestHandleSBOMScan_SyftNotAvailable(t *testing.T) {
	// Create a manager that will fail the syft check
	callCount := 0
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			callCount++
			if strings.Contains(url, "/status") {
				return mockResponse(200, `{"status": "ok"}`), nil
			}
			if strings.Contains(url, "/config/syft") {
				// Return empty config for test
				return mockResponse(200, `{"exclude_patterns": []}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}
	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")

	// If syft is not installed, this should report failure
	if !manager.isSyftAvailable() {
		payload := types.AgentSBOMPayload{
			ScanID:   "test-scan-123",
			ScanType: "host",
		}

		err := manager.HandleSBOMScan(payload)
		if err == nil {
			t.Error("Expected error when syft is not available")
		}
		if !strings.Contains(err.Error(), "syft is not installed") {
			t.Errorf("Expected error about syft not installed, got: %v", err)
		}
	}
}

func TestFetchSyftConfig(t *testing.T) {
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/config/syft") {
				if method != "GET" {
					t.Errorf("Expected GET method, got %s", method)
				}
				return mockResponse(200, `{"exclude_patterns": ["**/proc/**", "**/sys/**", "**/dev/**"]}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	config, err := manager.fetchSyftConfig()

	if err != nil {
		t.Errorf("fetchSyftConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	if len(config.ExcludePatterns) != 3 {
		t.Errorf("Expected 3 exclude patterns, got %d", len(config.ExcludePatterns))
	}

	expectedPatterns := []string{"**/proc/**", "**/sys/**", "**/dev/**"}
	for i, pattern := range expectedPatterns {
		if config.ExcludePatterns[i] != pattern {
			t.Errorf("Expected pattern '%s', got '%s'", pattern, config.ExcludePatterns[i])
		}
	}
}

func TestFetchSyftConfig_EmptyPatterns(t *testing.T) {
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/config/syft") {
				return mockResponse(200, `{"exclude_patterns": []}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	config, err := manager.fetchSyftConfig()

	if err != nil {
		t.Errorf("fetchSyftConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}

	if len(config.ExcludePatterns) != 0 {
		t.Errorf("Expected 0 exclude patterns, got %d", len(config.ExcludePatterns))
	}
}

func TestFetchSyftConfig_ServerError(t *testing.T) {
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/config/syft") {
				return mockResponse(500, `{"error": "internal server error"}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	_, err := manager.fetchSyftConfig()

	if err == nil {
		t.Error("Expected error when server returns 500")
	}
}

func TestUploadSBOM(t *testing.T) {
	// Create a temp file with fake SBOM data
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")

	fakeSBOM := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"version":     1,
		"components":  []interface{}{},
	}
	sbomData, _ := json.Marshal(fakeSBOM)
	if err := os.WriteFile(sbomPath, sbomData, 0644); err != nil {
		t.Fatalf("Failed to create test SBOM file: %v", err)
	}

	uploadCalled := false
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/upload") {
				uploadCalled = true

				// Verify it's a multipart form
				contentType := headers["Content-Type"]
				if !strings.Contains(contentType, "multipart/form-data") {
					t.Errorf("Expected multipart/form-data, got: %s", contentType)
				}

				// Return success response
				response := types.SBOMUploadResponse{
					ScanID:  "test-scan-123",
					Status:  "completed",
					Message: "SBOM uploaded successfully",
					VulnCounts: types.SBOMVulnCounts{
						Critical: 0,
						High:     1,
						Medium:   2,
						Low:      3,
						Total:    6,
					},
				}
				respBody, _ := json.Marshal(response)
				return mockResponse(200, string(respBody)), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	payload := types.AgentSBOMPayload{
		ScanID:     "test-scan-123",
		ScanType:   "host",
		SourceName: "test-host",
	}

	err := manager.uploadSBOM(payload, sbomPath)
	if err != nil {
		t.Errorf("uploadSBOM failed: %v", err)
	}

	if !uploadCalled {
		t.Error("Upload endpoint was not called")
	}
}

func TestReportFailure(t *testing.T) {
	statusCalled := false
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/status") {
				statusCalled = true

				// Verify the body contains status and error_msg
				var payload map[string]interface{}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Errorf("Failed to unmarshal status payload: %v", err)
				}

				if payload["status"] != "failed" {
					t.Errorf("Expected status 'failed', got '%v'", payload["status"])
				}

				if payload["error_msg"] == nil || payload["error_msg"] == "" {
					t.Error("Expected error_msg to be set")
				}

				return mockResponse(200, `{"status": "ok"}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	err := manager.reportFailure("test-scan-123", "test error message")

	// reportFailure should always return an error (the failure we're reporting)
	if err == nil {
		t.Error("Expected reportFailure to return an error")
	}

	if !statusCalled {
		t.Error("Status endpoint was not called")
	}

	if !strings.Contains(err.Error(), "test error message") {
		t.Errorf("Expected error to contain 'test error message', got: %v", err)
	}
}

func TestAcknowledgeScan(t *testing.T) {
	acknowledgeCalled := false
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/acknowledge") {
				acknowledgeCalled = true
				if method != "POST" {
					t.Errorf("Expected POST method, got %s", method)
				}
				return mockResponse(200, `{}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	err := manager.acknowledgeScan("test-scan-123")

	if err != nil {
		t.Errorf("acknowledgeScan failed: %v", err)
	}

	if !acknowledgeCalled {
		t.Error("Acknowledge endpoint was not called")
	}
}

func TestAcknowledgeScan_Failure(t *testing.T) {
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/acknowledge") {
				return mockResponse(500, `{"error": "internal server error"}`), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	err := manager.acknowledgeScan("test-scan-123")

	if err == nil {
		t.Error("Expected acknowledgeScan to fail with 500 status")
	}
}

func TestGzipCompression(t *testing.T) {
	// Test that the upload process properly compresses data
	testData := `{"test": "data", "large": "` + strings.Repeat("x", 1000) + `"}`

	// Create temp file
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")
	if err := os.WriteFile(sbomPath, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var receivedBody []byte
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			if strings.Contains(url, "/upload") {
				receivedBody = body

				response := types.SBOMUploadResponse{
					ScanID: "test-scan-123",
					Status: "completed",
				}
				respBody, _ := json.Marshal(response)
				return mockResponse(200, string(respBody)), nil
			}
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")
	payload := types.AgentSBOMPayload{
		ScanID:   "test-scan-123",
		ScanType: "host",
	}

	err := manager.uploadSBOM(payload, sbomPath)
	if err != nil {
		t.Errorf("uploadSBOM failed: %v", err)
	}

	// The received body should be multipart form data containing tar.gz content
	if len(receivedBody) == 0 {
		t.Error("Expected non-empty body")
	}

	// Check that the body contains .tar.gz extension in filename
	bodyStr := string(receivedBody)
	if !strings.Contains(bodyStr, ".tar.gz") {
		t.Error("Body does not contain .tar.gz extension in filename")
	}
}

func TestScanTypeValidation(t *testing.T) {
	mock := &mockAuthManager{
		doOnceFunc: func(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
			return mockResponse(200, `{}`), nil
		},
	}

	manager := NewSBOMManager("http://localhost:8090", mock, "test-agent-id")

	// Test invalid scan type
	payload := types.AgentSBOMPayload{
		ScanID:   "test-scan-123",
		ScanType: "invalid-type",
	}

	// This test only works if syft is available
	if manager.isSyftAvailable() {
		// Create empty config for test
		config := &SyftConfig{ExcludePatterns: []string{}}
		// executeScan should fail with unknown scan type
		_, err := manager.executeScan(payload, config)
		if err == nil {
			t.Error("Expected error for invalid scan type")
		}
		if !strings.Contains(err.Error(), "unknown scan type") {
			t.Errorf("Expected 'unknown scan type' error, got: %v", err)
		}
	}
}

func TestDecompressGzip(t *testing.T) {
	// Helper test to verify gzip decompression works
	originalData := []byte("test data for compression")

	// Compress
	var compressed strings.Builder
	gzWriter := gzip.NewWriter(&compressed)
	_, err := gzWriter.Write(originalData)
	if err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("Failed to close gzip writer: %v", err)
	}

	// Decompress
	gzReader, err := gzip.NewReader(strings.NewReader(compressed.String()))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	if string(decompressed) != string(originalData) {
		t.Errorf("Decompressed data doesn't match original")
	}
}

func TestSyftConfig(t *testing.T) {
	config := SyftConfig{
		ExcludePatterns: []string{"**/proc/**", "**/sys/**"},
	}

	if len(config.ExcludePatterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(config.ExcludePatterns))
	}

	if config.ExcludePatterns[0] != "**/proc/**" {
		t.Errorf("Expected '**/proc/**', got '%s'", config.ExcludePatterns[0])
	}
}
