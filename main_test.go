package main

import (
	"strings"
	"testing"

	"nannyagent/internal/app"
	"nannyagent/internal/config"
)

func TestValidateDiagnosisPrompt(t *testing.T) {
	tests := []struct {
		name    string
		prompt  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid prompt with sufficient detail",
			prompt:  "postgresql is running slow on production server",
			wantErr: false,
		},
		{
			name:    "Valid prompt with more context",
			prompt:  "disk is full on /var partition and cannot write logs",
			wantErr: false,
		},
		{
			name:    "Too short - less than 10 characters",
			prompt:  "how",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Too short - 8 characters",
			prompt:  "help me",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Incomplete - only 1 word",
			prompt:  "postgresql",
			wantErr: true,
			errMsg:  "prompt is incomplete (minimum 3 words required for meaningful diagnosis)",
		},
		{
			name:    "Incomplete - only 2 words (but also too short)",
			prompt:  "disk full",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)", // 9 chars, fails length check first
		},
		{
			name:    "Empty prompt",
			prompt:  "",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Whitespace only",
			prompt:  "   ",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Valid prompt with leading/trailing spaces",
			prompt:  "  disk usage is high on server  ",
			wantErr: false,
		},
		{
			name:    "Edge case - exactly 10 characters, 3 words",
			prompt:  "abc def ghi",
			wantErr: false,
		},
		{
			name:    "Edge case - 10 characters but only 2 words",
			prompt:  "hello world",
			wantErr: true,
			errMsg:  "prompt is incomplete (minimum 3 words required for meaningful diagnosis)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := app.ValidateDiagnosisPrompt(tt.prompt)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateDiagnosisPrompt() expected error but got nil")
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("validateDiagnosisPrompt() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateDiagnosisPrompt() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestVersionText(t *testing.T) {
	output := app.VersionText("1.2.3")
	if !strings.Contains(output, "nannyagent version 1.2.3") {
		t.Fatalf("VersionText missing version: %q", output)
	}
	if !strings.Contains(output, "Linux diagnostic agent with eBPF capabilities") {
		t.Fatalf("VersionText missing description: %q", output)
	}
}

func TestHelpText(t *testing.T) {
	output := app.HelpText("nannyagent", "1.2.3")
	required := []string{
		"Version: 1.2.3",
		"nannyagent [COMMAND] [OPTIONS]",
		"--register",
		"--status",
		"Documentation: https://nannyai.dev/documentation",
	}
	for _, item := range required {
		if !strings.Contains(output, item) {
			t.Fatalf("HelpText missing %q in %q", item, output)
		}
	}
}

func TestApplyLegacyPositionalCommands(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, flags *config.CLIFlags, warnings []string)
	}{
		{
			name: "register",
			args: []string{"register"},
			check: func(t *testing.T, flags *config.CLIFlags, warnings []string) {
				if !flags.Register || len(warnings) != 1 {
					t.Fatalf("expected register flag and warning, got %+v %v", flags, warnings)
				}
			},
		},
		{
			name: "diagnose",
			args: []string{"diagnose", "disk full on root"},
			check: func(t *testing.T, flags *config.CLIFlags, warnings []string) {
				if flags.Diagnose != "disk full on root" {
					t.Fatalf("expected diagnose prompt to be set, got %q", flags.Diagnose)
				}
				if len(warnings) != 1 {
					t.Fatalf("expected warning, got %v", warnings)
				}
			},
		},
		{
			name: "unknown",
			args: []string{"noop"},
			check: func(t *testing.T, flags *config.CLIFlags, warnings []string) {
				if len(warnings) != 0 {
					t.Fatalf("expected no warnings, got %v", warnings)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := &config.CLIFlags{}
			warnings := app.ApplyLegacyPositionalCommands(flags, tt.args)
			tt.check(t, flags, warnings)
		})
	}
}

// TestConfigLoadingConstraints verifies that we only support specific config sources
// This is a conceptual test since we can't easily mock the file system for main.go functions directly
// without refactoring main.go to accept a config loader interface.
// However, we can verify the behavior via integration tests or by checking the config package tests.
// Since we already updated internal/config/config_test.go, we rely on those tests.
// Here we can add tests for other main.go utility functions.

func TestCheckKernelVersionCompatibility_Parsing(t *testing.T) {
	major, err := app.KernelMajorVersion("5.15.0-56-generic")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if major != 5 {
		t.Fatalf("expected major version 5, got %d", major)
	}
}

func TestKernelMajorVersionErrors(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "unknown", text: "unknown", want: "cannot determine kernel version"},
		{name: "invalid", text: "x.15.0", want: "cannot parse major kernel version: x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := app.KernelMajorVersion(tt.text)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("KernelMajorVersion(%q) error = %v, want %q", tt.text, err, tt.want)
			}
		})
	}
}

func TestResolveSystemdServiceStatus(t *testing.T) {
	status, available, err := app.ResolveSystemdServiceStatus(
		func(string) (string, error) { return "/bin/systemctl", nil },
		func(name string, args ...string) ([]byte, error) { return []byte("active\n"), nil },
		"nannyagent",
	)
	if err != nil || !available || status != "Service running" {
		t.Fatalf("ResolveSystemdServiceStatus() = (%q, %v, %v)", status, available, err)
	}
}

func TestValidateDiagnosisPrompt_RealWorldExamples(t *testing.T) {
	validPrompts := []string{
		"postgresql database is running slow",
		"cannot connect to remote server via SSH",
		"disk usage is at 95% on /var partition",
		"apache service keeps crashing every hour",
		"high CPU usage by python process",
		"nginx returns 502 bad gateway error",
		"memory leak in nodejs application",
		"docker container fails to start",
		"kubernetes pod in crash loop backoff",
		"redis connection timeout after upgrade",
	}

	for _, prompt := range validPrompts {
		t.Run("Valid: "+prompt, func(t *testing.T) {
			err := app.ValidateDiagnosisPrompt(prompt)
			if err != nil {
				t.Errorf("validateDiagnosisPrompt(%q) unexpected error = %v", prompt, err)
			}
		})
	}

	invalidPrompts := map[string]string{
		"help":        "prompt is too short (minimum 10 characters required)",
		"fix this":    "prompt is too short (minimum 10 characters required)",                     // 8 chars
		"slow server": "prompt is incomplete (minimum 3 words required for meaningful diagnosis)", // 11 chars, 2 words
		"how":         "prompt is too short (minimum 10 characters required)",
	}

	// "what is wrong" is actually valid (13 chars, 3 words) - remove from invalid list

	for prompt, expectedErr := range invalidPrompts {
		t.Run("Invalid: "+prompt, func(t *testing.T) {
			err := app.ValidateDiagnosisPrompt(prompt)
			if err == nil {
				t.Errorf("validateDiagnosisPrompt(%q) expected error but got nil", prompt)
				return
			}
			if err.Error() != expectedErr {
				t.Errorf("validateDiagnosisPrompt(%q) error = %v, want %v", prompt, err.Error(), expectedErr)
			}
		})
	}
}
