package sbom

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nannyagent/internal/logging"
	"nannyagent/internal/types"
)

// execCommand allows mocking exec.Command in tests
var execCommand = exec.Command

// SyftConfig holds the syft configuration from the API
type SyftConfig struct {
	ExcludePatterns []string `json:"exclude_patterns"`
}

// SBOMManager handles SBOM scanning operations
type SBOMManager struct {
	baseURL     string
	authManager interface {
		AuthenticatedDoOnce(method, url string, body []byte, headers map[string]string) (*http.Response, error)
	}
	agentID string
}

// NewSBOMManager creates a new SBOM manager
func NewSBOMManager(baseURL string, authManager interface {
	AuthenticatedDoOnce(method, url string, body []byte, headers map[string]string) (*http.Response, error)
}, agentID string) *SBOMManager {
	return &SBOMManager{
		baseURL:     baseURL,
		authManager: authManager,
		agentID:     agentID,
	}
}

// HandleSBOMScan processes an SBOM scan request from the API
func (sm *SBOMManager) HandleSBOMScan(payload types.AgentSBOMPayload) error {
	logging.Info("Processing SBOM scan: %s (type: %s)", payload.ScanID, payload.ScanType)

	// 1. Check if syft is available
	if !sm.isSyftAvailable() {
		return sm.reportFailure(payload.ScanID, "syft is not installed or not in PATH")
	}

	// 2. Acknowledge the scan request
	if err := sm.acknowledgeScan(payload.ScanID); err != nil {
		return sm.reportFailure(payload.ScanID, fmt.Sprintf("Failed to acknowledge scan: %v", err))
	}

	// 3. Fetch syft configuration from API
	syftConfig, err := sm.fetchSyftConfig()
	if err != nil {
		logging.Warning("Failed to fetch syft config, using defaults: %v", err)
		// Use default patterns if API call fails
		syftConfig = &SyftConfig{
			ExcludePatterns: []string{
				"**/proc/**",
				"**/sys/**",
				"**/dev/**",
				"**/run/**",
				"**/tmp/**",
				"**/var/cache/**",
				"**/var/log/**",
			},
		}
	}

	// 4. Execute the scan based on type with config from API
	sbomPath, err := sm.executeScan(payload, syftConfig)
	if err != nil {
		return sm.reportFailure(payload.ScanID, fmt.Sprintf("Scan failed: %v", err))
	}
	defer func() { _ = os.Remove(sbomPath) }()

	// 5. Compress and upload (single attempt, no retries)
	if err := sm.uploadSBOM(payload, sbomPath); err != nil {
		return sm.reportFailure(payload.ScanID, fmt.Sprintf("Upload failed: %v", err))
	}

	logging.Info("SBOM scan %s completed successfully", payload.ScanID)
	return nil
}

// isSyftAvailable checks if syft binary is available
func (sm *SBOMManager) isSyftAvailable() bool {
	_, err := exec.LookPath("syft")
	return err == nil
}

// fetchSyftConfig retrieves syft configuration from the API
func (sm *SBOMManager) fetchSyftConfig() (*SyftConfig, error) {
	url := fmt.Sprintf("%s/api/sbom/config/syft", sm.baseURL)

	resp, err := sm.authManager.AuthenticatedDoOnce("GET", url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch syft config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("syft config request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var config SyftConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode syft config: %w", err)
	}

	logging.Debug("Fetched syft config with %d exclude patterns", len(config.ExcludePatterns))
	return &config, nil
}

// acknowledgeScan sends acknowledgment to the API
func (sm *SBOMManager) acknowledgeScan(scanID string) error {
	url := fmt.Sprintf("%s/api/sbom/scans/%s/acknowledge", sm.baseURL, scanID)

	resp, err := sm.authManager.AuthenticatedDoOnce("POST", url, nil, nil)
	if err != nil {
		return fmt.Errorf("acknowledge request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("acknowledge failed with status %d: %s", resp.StatusCode, string(body))
	}

	logging.Info("SBOM scan %s acknowledged successfully", scanID)
	return nil
}

// executeScan runs syft based on the scan type with config from API
func (sm *SBOMManager) executeScan(payload types.AgentSBOMPayload, config *SyftConfig) (string, error) {
	// Create temp file for output
	tmpFile, err := os.CreateTemp("", "nannyagent-sbom-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	var args []string

	switch payload.ScanType {
	case "host":
		// Build args with exclude patterns from API
		args = []string{"scan", "dir:/"}
		for _, pattern := range config.ExcludePatterns {
			args = append(args, "--exclude", pattern)
		}
		args = append(args, "-o", fmt.Sprintf("json=%s", tmpPath))
		logging.Info("Starting host filesystem scan with %d exclusions...", len(config.ExcludePatterns))

	case "container":
		// Container scan - try podman first, then docker
		targetID := payload.VMID
		if targetID == "" {
			targetID = payload.LXCID
		}
		if targetID == "" {
			targetID = payload.SourceName
		}

		// Try podman first
		args = []string{"scan", fmt.Sprintf("podman:%s", targetID), "-o", fmt.Sprintf("json=%s", tmpPath)}
		logging.Info("Starting container scan for %s...", targetID)

	case "image":
		// Image scan
		args = []string{"scan", payload.SourceName, "-o", fmt.Sprintf("json=%s", tmpPath)}
		logging.Info("Starting image scan for %s...", payload.SourceName)

	default:
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("unknown scan type: %s", payload.ScanType)
	}

	// Execute syft
	cmd := execCommand("syft", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	// For container scans, if podman fails, try docker
	if err != nil && payload.ScanType == "container" {
		logging.Debug("Podman scan failed, trying Docker: %v", err)
		targetID := payload.VMID
		if targetID == "" {
			targetID = payload.LXCID
		}
		if targetID == "" {
			targetID = payload.SourceName
		}

		args = []string{"scan", fmt.Sprintf("docker:%s", targetID), "-o", fmt.Sprintf("json=%s", tmpPath)}
		cmd = execCommand("syft", args...)
		cmd.Stderr = &stderr
		err = cmd.Run()
	}

	if err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("syft scan failed: %w, stderr: %s", err, stderr.String())
	}

	// Check if output file was created and has content
	fileInfo, err := os.Stat(tmpPath)
	if err != nil || fileInfo.Size() == 0 {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("syft produced no output")
	}

	logging.Info("SBOM scan completed in %v, output size: %d bytes", duration, fileInfo.Size())
	return tmpPath, nil
}

// uploadSBOM compresses to tar.gz and uploads the SBOM to the API (single attempt)
func (sm *SBOMManager) uploadSBOM(payload types.AgentSBOMPayload, sbomPath string) error {
	// Read the SBOM file
	sbomData, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	// Create tar.gz archive (gzip-compressed tarball)
	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzWriter)

	// Add the SBOM JSON file to the tar archive
	header := &tar.Header{
		Name:    filepath.Base(sbomPath),
		Mode:    0644,
		Size:    int64(len(sbomData)),
		ModTime: time.Now(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tarWriter.Write(sbomData); err != nil {
		return fmt.Errorf("failed to write tar content: %w", err)
	}

	// Close tar writer first, then gzip writer
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize compression: %w", err)
	}

	logging.Info("Compressed SBOM from %d to %d bytes (%.1f%% reduction)",
		len(sbomData), compressed.Len(),
		100.0-float64(compressed.Len())*100.0/float64(len(sbomData)))

	// Create multipart form
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Add the compressed SBOM file as tar.gz
	tarGzName := strings.TrimSuffix(filepath.Base(sbomPath), ".json") + ".tar.gz"
	part, err := writer.CreateFormFile("sbom_archive", tarGzName)
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := io.Copy(part, &compressed); err != nil {
		return fmt.Errorf("failed to write form file: %w", err)
	}

	// Add form fields
	_ = writer.WriteField("scan_id", payload.ScanID)
	_ = writer.WriteField("scan_type", payload.ScanType)

	sourceName := payload.SourceName
	if sourceName == "" {
		hostname, _ := os.Hostname()
		sourceName = hostname
	}
	_ = writer.WriteField("source_name", sourceName)

	if payload.SourceType != "" {
		_ = writer.WriteField("source_type", payload.SourceType)
	}

	if payload.LXCID != "" {
		_ = writer.WriteField("lxc_id", payload.LXCID)
	}

	if payload.VMID != "" {
		_ = writer.WriteField("vmid", payload.VMID)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Upload to API (single attempt, no retries)
	url := fmt.Sprintf("%s/api/sbom/upload", sm.baseURL)
	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
	}

	resp, err := sm.authManager.AuthenticatedDoOnce("POST", url, body.Bytes(), headers)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response to log vulnerability counts
	var uploadResp types.SBOMUploadResponse
	if err := json.Unmarshal(respBody, &uploadResp); err == nil {
		logging.Info("SBOM scan %s: %d vulnerabilities (Critical: %d, High: %d, Medium: %d, Low: %d)",
			payload.ScanID,
			uploadResp.VulnCounts.Total,
			uploadResp.VulnCounts.Critical,
			uploadResp.VulnCounts.High,
			uploadResp.VulnCounts.Medium,
			uploadResp.VulnCounts.Low)
	}

	return nil
}

// reportFailure sends a failure status to the API
func (sm *SBOMManager) reportFailure(scanID string, errMsg string) error {
	logging.Error("SBOM scan %s failed: %s", scanID, errMsg)

	url := fmt.Sprintf("%s/api/sbom/scans/%s/status", sm.baseURL, scanID)

	payload := map[string]interface{}{
		"status":    "failed",
		"error_msg": errMsg,
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := sm.authManager.AuthenticatedDoOnce("POST", url, jsonData, nil)
	if err != nil {
		logging.Warning("Failed to report scan failure: %v", err)
		return fmt.Errorf("scan failed: %s (also failed to report: %w)", errMsg, err)
	}
	defer func() { _ = resp.Body.Close() }()

	return fmt.Errorf("scan failed: %s", errMsg)
}
