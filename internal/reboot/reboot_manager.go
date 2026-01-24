package reboot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"nannyagent/internal/logging"
	"nannyagent/internal/types"
)

// execCommand allows mocking exec.Command in tests
var execCommand = exec.Command

// RebootManager handles reboot operations
type RebootManager struct {
	baseURL     string
	authManager interface {
		AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error)
	}
}

// NewRebootManager creates a new reboot manager
func NewRebootManager(baseURL string, authManager interface {
	AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}) *RebootManager {
	return &RebootManager{
		baseURL:     baseURL,
		authManager: authManager,
	}
}

// HandleRebootOperation processes a reboot operation request
func (rm *RebootManager) HandleRebootOperation(payload types.AgentRebootPayload) error {
	logging.Info("Processing reboot operation: %s", payload.RebootID)

	// 1. Acknowledge the reboot
	if err := rm.AcknowledgeReboot(payload.RebootID); err != nil {
		return rm.reportFailure(payload.RebootID, fmt.Sprintf("Failed to acknowledge reboot: %v", err))
	}

	logging.Info("Reboot acknowledged, initiating reboot...")

	// 2. Execute the reboot
	if err := rm.executeReboot(payload); err != nil {
		return rm.reportFailure(payload.RebootID, fmt.Sprintf("Failed to execute reboot: %v", err))
	}

	// Note: If we reach here for host reboot, the system should be rebooting
	// For LXC reboot, we can return successfully as the container will reboot
	return nil
}

// AcknowledgeReboot sends acknowledgment to the API
func (rm *RebootManager) AcknowledgeReboot(rebootID string) error {
	url := fmt.Sprintf("%s/api/reboot/%s/acknowledge", rm.baseURL, rebootID)

	statusCode, body, err := rm.authManager.AuthenticatedRequest("POST", url, nil, nil)
	if err != nil {
		return fmt.Errorf("acknowledge request failed: %w", err)
	}

	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("acknowledge failed with status %d: %s", statusCode, string(body))
	}

	logging.Info("Reboot %s acknowledged successfully", rebootID)
	return nil
}

// executeReboot performs the actual reboot
func (rm *RebootManager) executeReboot(payload types.AgentRebootPayload) error {
	if payload.LXCID != "" || payload.VMID != "" {
		// LXC container reboot via Proxmox
		return rm.executeContainerReboot(payload)
	}

	// Host reboot
	return rm.executeHostReboot(payload)
}

// executeHostReboot performs a host system reboot
func (rm *RebootManager) executeHostReboot(payload types.AgentRebootPayload) error {
	logging.Info("Executing host reboot (reason: %s)", payload.Reason)

	// Try systemctl reboot first (preferred on systemd systems)
	cmd := execCommand("systemctl", "reboot")
	if err := cmd.Start(); err != nil {
		// Fallback to shutdown command
		logging.Warning("systemctl reboot failed, trying shutdown -r now: %v", err)
		cmd = execCommand("shutdown", "-r", "now")
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("both reboot methods failed: %w", err)
		}
	}

	// Don't wait for the command to complete - system will reboot
	logging.Info("Reboot command issued, system will reboot momentarily...")
	return nil
}

// executeContainerReboot performs an LXC container reboot via Proxmox
func (rm *RebootManager) executeContainerReboot(payload types.AgentRebootPayload) error {
	// Use VMID if available (preferred for Proxmox), otherwise fallback to LXCID
	targetID := payload.LXCID
	if payload.VMID != "" {
		targetID = payload.VMID
	}

	logging.Info("Executing LXC container reboot: %s (reason: %s)", targetID, payload.Reason)

	// Use pct reboot command
	cmd := execCommand("pct", "reboot", targetID)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		return fmt.Errorf("pct reboot failed after %v: %s (stderr: %s)", duration, err.Error(), stderrBuf.String())
	}

	logging.Info("LXC container %s reboot initiated successfully (took %v)", targetID, duration)
	return nil
}

// reportFailure reports a failed reboot operation to the API
func (rm *RebootManager) reportFailure(rebootID string, errorMsg string) error {
	logging.Error("Reboot operation %s failed: %s", rebootID, errorMsg)

	url := fmt.Sprintf("%s/api/reboot/%s/fail", rm.baseURL, rebootID)

	payload := map[string]string{
		"error": errorMsg,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal failure payload: %w", err)
	}

	statusCode, body, err := rm.authManager.AuthenticatedRequest("POST", url, jsonData, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		logging.Error("Failed to report reboot failure: %v", err)
		return err
	}

	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		logging.Error("Report failure returned status %d: %s", statusCode, string(body))
	}

	return fmt.Errorf("%s", errorMsg)
}
