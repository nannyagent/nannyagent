package patches

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"nannyagent/internal/nannyapi"
	"nannyagent/internal/types"
)

// TestHelperProcess is used to mock exec.Command
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	// Extract command and args
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}

	cmd, args := args[0], args[1:]

	// Handle "pct" command
	if cmd == "pct" {
		// Expected args: exec <lxc_id> -- bash -s -- <args>
		if len(args) < 5 {
			fmt.Fprintf(os.Stderr, "Invalid pct args: %v\n", args)
			os.Exit(1)
		}

		if args[0] != "exec" {
			fmt.Fprintf(os.Stderr, "Expected 'exec', got '%s'\n", args[0])
			os.Exit(1)
		}

		lxcID := args[1]
		if lxcID != "100" {
			fmt.Fprintf(os.Stderr, "Expected LXC ID '100', got '%s'\n", lxcID)
			os.Exit(1)
		}

		// Check for "--" separator
		if args[2] != "--" {
			fmt.Fprintf(os.Stderr, "Expected '--', got '%s'\n", args[2])
			os.Exit(1)
		}

		// Check bash command
		if args[3] != "bash" || args[4] != "-s" {
			fmt.Fprintf(os.Stderr, "Expected 'bash -s', got '%s %s'\n", args[3], args[4])
			os.Exit(1)
		}

		// Read script content from stdin
		scriptContentBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read stdin: %v\n", err)
			os.Exit(1)
		}
		scriptContent := string(scriptContentBytes)

		if !strings.Contains(scriptContent, "echo 'lxc patch'") {
			fmt.Fprintf(os.Stderr, "Script content mismatch. Got: %s\n", scriptContent)
			os.Exit(1)
		}

		// Check trailing "--"
		if args[5] != "--" {
			fmt.Fprintf(os.Stderr, "Expected trailing '--', got '%s'\n", args[5])
			os.Exit(1)
		}

		// Check extra args (mode)
		if len(args) > 6 {
			mode := args[6]
			if mode != "--dry-run" && mode != "--apply" {
				fmt.Fprintf(os.Stderr, "Unexpected mode arg: %s\n", mode)
				os.Exit(1)
			}
		}

		// Output success JSON
		fmt.Print(`[{"name": "test-pkg", "version": "1.0", "update_type": "install", "details": "Installed test-pkg"}]`)
		os.Exit(0)
	}

	// Handle script execution (host mode)
	if strings.HasSuffix(cmd, "patch_script") {
		fmt.Print(`[{"name": "host-pkg", "version": "1.0", "update_type": "install", "details": "Installed host-pkg"}]`)
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
	os.Exit(1)
}

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestPatchManager_HandlePatchOperation_LXC(t *testing.T) {
	// Mock execCommand
	oldExecCommand := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = oldExecCommand }()

	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(nannyapi.HeaderAuthorization) != nannyapi.BearerPrefix+"test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Handle script download
		if strings.HasPrefix(r.URL.Path, "/api/files/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("#!/bin/bash\necho 'lxc patch'\n"))
			return
		}

		// Handle validation
		if strings.HasSuffix(r.URL.Path, "/validate") {
			resp := map[string]string{
				"id":     "test-script-id",
				"sha256": "b7cad9a520d437330ce70326ef2bcbc91c8be5b41874f2ae0b8abd4d4f913fe3", // SHA256 of "#!/bin/bash\necho 'lxc patch'\n"
				"name":   "test-script.sh",
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Handle result upload
		if strings.HasSuffix(r.URL.Path, "/result") {
			// Verify lxc_id is present in multipart form
			err := r.ParseMultipartForm(10 << 20)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(err.Error()))
				return
			}

			lxcID := r.FormValue("lxc_id")
			if lxcID != "lxc-uuid-123" {
				w.WriteHeader(http.StatusBadRequest)
				_, err := fmt.Fprintf(w, "Expected lxc_id=lxc-uuid-123, got %s", lxcID)
				if err != nil {
					t.Fatalf("Failed to write response: %v", err)
				}
				return
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	mockAuth := &mockAuthManager{token: "test-token"}
	pm := NewPatchManager(ts.URL, mockAuth, "test-agent-id")

	payload := types.AgentPatchPayload{
		OperationID: "op-lxc-1",
		Mode:        "dry-run",
		ScriptURL:   "/api/files/col/rec/script.sh",
		ScriptID:    "rec",
		LXCID:       "lxc-uuid-123",
		VMID:        "100",
		Timestamp:   "2025-01-01T00:00:00Z",
	}

	err := pm.HandlePatchOperation(payload)
	if err != nil {
		t.Fatalf("HandlePatchOperation failed: %v", err)
	}
}
