package agent

import (
	"nannyagent/internal/types"
	"testing"
)

// MockAuthManager
type MockAuthManager struct {
	Token *types.AuthToken
}

func (m *MockAuthManager) GetCurrentAgentID() (string, error) {
	return "agent-123", nil
}

func (m *MockAuthManager) LoadToken() (*types.AuthToken, error) {
	return m.Token, nil
}

func (m *MockAuthManager) EnsureAuthenticated() (*types.AuthToken, error) {
	return m.Token, nil
}

func TestNewLinuxDiagnosticAgent(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()
	if agent == nil {
		t.Fatal("Expected agent to be created")
	}
}

func TestNewLinuxDiagnosticAgentWithAuth(t *testing.T) {
	mockAuth := &MockAuthManager{
		Token: &types.AuthToken{AccessToken: "test-token"},
	}
	agent := NewLinuxDiagnosticAgentWithAuth(mockAuth, "http://localhost:8090")
	if agent == nil {
		t.Fatal("Expected agent to be created")
	}
}

func TestStripResponseCodeFence(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "json fenced block",
			input: "```json\n{\"response_type\":\"diagnostic\"}\n```",
			want:  "{\"response_type\":\"diagnostic\"}",
		},
		{
			name:  "plain fenced block",
			input: "```\n{\"response_type\":\"resolution\"}\n```",
			want:  "{\"response_type\":\"resolution\"}",
		},
		{
			name:  "plain json",
			input: "  {\"response_type\":\"resolution\"}  ",
			want:  "{\"response_type\":\"resolution\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripResponseCodeFence(tt.input); got != tt.want {
				t.Fatalf("stripResponseCodeFence() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeProbeTarget(t *testing.T) {
	tests := []struct {
		name          string
		request       types.EBPFRequest
		wantProbeType string
		wantTarget    string
	}{
		{
			name: "tracepoint prefix",
			request: types.EBPFRequest{
				Target: "tracepoint:syscalls:sys_enter_openat",
			},
			wantProbeType: "t",
			wantTarget:    "syscalls:sys_enter_openat",
		},
		{
			name: "kprobe prefix",
			request: types.EBPFRequest{
				Target: "kprobe:tcp_connect",
			},
			wantProbeType: "p",
			wantTarget:    "tcp_connect",
		},
		{
			name: "kretprobe type",
			request: types.EBPFRequest{
				Type:   "kretprobe",
				Target: "do_sys_openat2",
			},
			wantProbeType: "r",
			wantTarget:    "do_sys_openat2",
		},
		{
			name: "syscall target normalization",
			request: types.EBPFRequest{
				Type:   "syscall",
				Target: "openat",
			},
			wantProbeType: "p",
			wantTarget:    "__x64_sys_openat",
		},
		{
			name: "syscall legacy prefix normalization",
			request: types.EBPFRequest{
				Type:   "syscall",
				Target: "sys_write",
			},
			wantProbeType: "p",
			wantTarget:    "__x64_sys_write",
		},
		{
			name: "syscall target with namespace left alone",
			request: types.EBPFRequest{
				Type:   "syscall",
				Target: "syscalls:sys_enter_write",
			},
			wantProbeType: "p",
			wantTarget:    "syscalls:sys_enter_write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProbeType, gotTarget := normalizeProbeTarget(tt.request)
			if gotProbeType != tt.wantProbeType || gotTarget != tt.wantTarget {
				t.Fatalf("normalizeProbeTarget() = (%q, %q), want (%q, %q)", gotProbeType, gotTarget, tt.wantProbeType, tt.wantTarget)
			}
		})
	}
}
