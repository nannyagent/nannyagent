package reboot

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"

	"nannyagent/internal/types"
)

// mockAuthManager implements the auth interface for testing
type mockAuthManager struct {
	statusCode int
	response   []byte
	err        error
}

func (m *mockAuthManager) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	return m.statusCode, m.response, m.err
}

func TestNewRebootManager(t *testing.T) {
	authManager := &mockAuthManager{}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	if rm == nil {
		t.Fatal("expected non-nil RebootManager")
	}
	if rm.baseURL != "http://localhost:8090" {
		t.Errorf("expected baseURL 'http://localhost:8090', got '%s'", rm.baseURL)
	}
	if rm.agentID != "agent-123" {
		t.Errorf("expected agentID 'agent-123', got '%s'", rm.agentID)
	}
}

func TestAcknowledgeReboot_Success(t *testing.T) {
	authManager := &mockAuthManager{
		statusCode: http.StatusOK,
		response:   []byte(`{"success": true}`),
	}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	err := rm.AcknowledgeReboot("reboot-456")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestAcknowledgeReboot_NoContent(t *testing.T) {
	authManager := &mockAuthManager{
		statusCode: http.StatusNoContent,
		response:   nil,
	}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	err := rm.AcknowledgeReboot("reboot-456")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestAcknowledgeReboot_Failure(t *testing.T) {
	authManager := &mockAuthManager{
		statusCode: http.StatusBadRequest,
		response:   []byte(`{"error": "invalid reboot id"}`),
	}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	err := rm.AcknowledgeReboot("reboot-456")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestReportFailure(t *testing.T) {
	authManager := &mockAuthManager{
		statusCode: http.StatusOK,
		response:   []byte(`{}`),
	}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	err := rm.reportFailure("reboot-456", "test error message")
	if err == nil {
		t.Error("expected error (the error message itself), got nil")
	}
	if err.Error() != "test error message" {
		t.Errorf("expected error message 'test error message', got '%s'", err.Error())
	}
}

func TestExecuteContainerReboot_Success(t *testing.T) {
	// Mock exec.Command
	oldExecCommand := execCommand
	defer func() { execCommand = oldExecCommand }()

	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("echo", "rebooting")
	}

	authManager := &mockAuthManager{}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	payload := types.AgentRebootPayload{
		RebootID: "reboot-456",
		VMID:     "100",
		Reason:   "test reboot",
	}

	err := rm.executeContainerReboot(payload)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestExecuteContainerReboot_WithLXCID(t *testing.T) {
	// Mock exec.Command
	oldExecCommand := execCommand
	defer func() { execCommand = oldExecCommand }()

	var capturedArgs []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.Command("echo", "rebooting")
	}

	authManager := &mockAuthManager{}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	payload := types.AgentRebootPayload{
		RebootID: "reboot-456",
		LXCID:    "lxc-200",
		Reason:   "test reboot",
	}

	err := rm.executeContainerReboot(payload)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Should use LXCID when VMID is not provided
	if len(capturedArgs) < 2 || capturedArgs[1] != "lxc-200" {
		t.Errorf("expected LXCID 'lxc-200' in args, got: %v", capturedArgs)
	}
}

func TestExecuteContainerReboot_PreferVMID(t *testing.T) {
	// Mock exec.Command
	oldExecCommand := execCommand
	defer func() { execCommand = oldExecCommand }()

	var capturedArgs []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.Command("echo", "rebooting")
	}

	authManager := &mockAuthManager{}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	payload := types.AgentRebootPayload{
		RebootID: "reboot-456",
		LXCID:    "lxc-200",
		VMID:     "100",
		Reason:   "test reboot",
	}

	err := rm.executeContainerReboot(payload)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Should prefer VMID over LXCID
	if len(capturedArgs) < 2 || capturedArgs[1] != "100" {
		t.Errorf("expected VMID '100' in args, got: %v", capturedArgs)
	}
}

func TestHandleRebootOperation_AcknowledgeFailure(t *testing.T) {
	// Mock the API server to fail acknowledgment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "server error"}`))
	}))
	defer server.Close()

	authManager := &mockAuthManager{
		statusCode: http.StatusInternalServerError,
		response:   []byte(`{"error": "server error"}`),
	}
	rm := NewRebootManager(server.URL, authManager, "agent-123")

	payload := types.AgentRebootPayload{
		RebootID:       "reboot-456",
		Reason:         "test reboot",
		TimeoutSeconds: 300,
	}

	err := rm.HandleRebootOperation(payload)
	if err == nil {
		t.Error("expected error when acknowledgment fails, got nil")
	}
}

func TestExecuteReboot_HostReboot(t *testing.T) {
	// Mock exec.Command to avoid actually rebooting
	oldExecCommand := execCommand
	defer func() { execCommand = oldExecCommand }()

	execCommand = func(name string, args ...string) *exec.Cmd {
		// Return a command that starts successfully but does nothing dangerous
		return exec.Command("echo", "would reboot")
	}

	authManager := &mockAuthManager{}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	payload := types.AgentRebootPayload{
		RebootID: "reboot-456",
		Reason:   "test reboot",
	}

	// This should attempt host reboot since no LXCID/VMID is set
	err := rm.executeReboot(payload)
	if err != nil {
		t.Errorf("expected no error for mocked host reboot, got: %v", err)
	}
}

func TestExecuteReboot_ContainerReboot(t *testing.T) {
	// Mock exec.Command
	oldExecCommand := execCommand
	defer func() { execCommand = oldExecCommand }()

	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("echo", "would reboot container")
	}

	authManager := &mockAuthManager{}
	rm := NewRebootManager("http://localhost:8090", authManager, "agent-123")

	payload := types.AgentRebootPayload{
		RebootID: "reboot-456",
		VMID:     "100",
		Reason:   "test reboot",
	}

	// This should route to container reboot since VMID is set
	err := rm.executeReboot(payload)
	if err != nil {
		t.Errorf("expected no error for mocked container reboot, got: %v", err)
	}
}

func TestRebootPayloadFields(t *testing.T) {
	payload := types.AgentRebootPayload{
		RebootID:       "reboot-123",
		AgentID:        "agent-456",
		LXCID:          "lxc-789",
		VMID:           "100",
		Reason:         "maintenance window",
		TimeoutSeconds: 600,
		RequestedAt:    "2026-01-24T10:00:00Z",
	}

	if payload.RebootID != "reboot-123" {
		t.Errorf("expected RebootID 'reboot-123', got '%s'", payload.RebootID)
	}
	if payload.AgentID != "agent-456" {
		t.Errorf("expected AgentID 'agent-456', got '%s'", payload.AgentID)
	}
	if payload.LXCID != "lxc-789" {
		t.Errorf("expected LXCID 'lxc-789', got '%s'", payload.LXCID)
	}
	if payload.VMID != "100" {
		t.Errorf("expected VMID '100', got '%s'", payload.VMID)
	}
	if payload.Reason != "maintenance window" {
		t.Errorf("expected Reason 'maintenance window', got '%s'", payload.Reason)
	}
	if payload.TimeoutSeconds != 600 {
		t.Errorf("expected TimeoutSeconds 600, got %d", payload.TimeoutSeconds)
	}
	if payload.RequestedAt != "2026-01-24T10:00:00Z" {
		t.Errorf("expected RequestedAt '2026-01-24T10:00:00Z', got '%s'", payload.RequestedAt)
	}
}

func TestRebootStatusConstants(t *testing.T) {
	// Verify all status constants are defined correctly
	statuses := map[types.RebootStatus]string{
		types.RebootStatusPending:   "pending",
		types.RebootStatusSent:      "sent",
		types.RebootStatusRebooting: "rebooting",
		types.RebootStatusCompleted: "completed",
		types.RebootStatusFailed:    "failed",
		types.RebootStatusTimeout:   "timeout",
	}

	for status, expected := range statuses {
		if string(status) != expected {
			t.Errorf("expected status '%s', got '%s'", expected, string(status))
		}
	}
}
