package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nannyagent/internal/config"
)

func VersionText(version string) string {
	return fmt.Sprintf("nannyagent version %s\nLinux diagnostic agent with eBPF capabilities\n", version)
}

func HelpText(binaryName, version string) string {
	return fmt.Sprintf(`NannyAgent - AI-Powered Linux Diagnostic Agent
Version: %s

USAGE:
  %s [COMMAND] [OPTIONS]

COMMANDS:
  --register                  Register agent with NannyAI
  --status                    Show agent status
  --diagnose <issue>          Run one-off diagnosis
  --daemon                    Run as daemon (systemd)
  --version                   Show version
  --help                      Show this help

CONFIG OVERRIDES (higher priority than config.yaml):
  --api-url <url>             NannyAPI endpoint URL
  --portal-url <url>          Portal URL for device authorization
  --token-path <path>         Token storage path
  --metrics-interval <secs>   Metrics collection interval
  --proxmox-interval <secs>   Proxmox data collection interval
  --agent-id <id>             Agent ID (for static token mode)
  --debug                     Enable debug mode

AUTHENTICATION:
  OAuth2 (default):   Register interactively with --register
  Static token:       Set static_token in /etc/nannyagent/config.yaml
                      Then run --register to auto-register

EXAMPLES:
  sudo nannyagent --register
  sudo nannyagent --register --api-url http://localhost:8090
  nannyagent --status
  sudo nannyagent --diagnose "postgresql is slow"
  sudo nannyagent    # Interactive mode

Documentation: https://nannyai.dev/documentation
`, version, binaryName)
}

func ApplyLegacyPositionalCommands(cliFlags *config.CLIFlags, positionalArgs []string) []string {
	if len(positionalArgs) == 0 {
		return nil
	}

	var warnings []string
	switch positionalArgs[0] {
	case "register":
		warnings = append(warnings, "Please use: nannyagent --register (with -- prefix)")
		cliFlags.Register = true
	case "status":
		warnings = append(warnings, "Please use: nannyagent --status (with -- prefix)")
		cliFlags.Status = true
	case "diagnose":
		warnings = append(warnings, "Please use: nannyagent --diagnose (with -- prefix)")
		if len(positionalArgs) > 1 {
			cliFlags.Diagnose = positionalArgs[1]
		}
	case "daemon":
		warnings = append(warnings, "Please use: nannyagent --daemon (with -- prefix)")
		cliFlags.Daemon = true
	}

	return warnings
}

func ValidateDiagnosisPrompt(prompt string) error {
	prompt = strings.TrimSpace(prompt)

	if len(prompt) < 10 {
		return fmt.Errorf("prompt is too short (minimum 10 characters required)")
	}

	if len(strings.Fields(prompt)) < 3 {
		return fmt.Errorf("prompt is incomplete (minimum 3 words required for meaningful diagnosis)")
	}

	return nil
}

func TokenPath(configuredPath, dataDir string) string {
	if configuredPath != "" {
		return configuredPath
	}
	return filepath.Join(dataDir, "token.json")
}

func CheckExistingAgentInstance(tokenPath string) error {
	if _, err := os.Stat(tokenPath); err == nil {
		return fmt.Errorf("agent already registered on this machine (token found at %s)", tokenPath)
	}
	return nil
}

func KernelMajorVersion(kernelVersion string) (int, error) {
	if kernelVersion == "" || kernelVersion == "unknown" {
		return 0, fmt.Errorf("cannot determine kernel version")
	}

	parts := strings.Split(kernelVersion, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("cannot parse kernel version: %s", kernelVersion)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("cannot parse major kernel version: %s", parts[0])
	}

	return major, nil
}

func ResolveSystemdServiceStatus(lookPath func(string) (string, error), runner func(name string, args ...string) ([]byte, error), service string) (string, bool, error) {
	if _, err := lookPath("systemctl"); err != nil {
		return "", false, nil
	}

	output, err := runner("systemctl", "is-active", service)
	if err != nil {
		return "", true, err
	}

	status := strings.TrimSpace(string(output))
	if status == "active" {
		return "Service running", true, nil
	}
	if status == "" {
		return "Service unknown", true, nil
	}

	return fmt.Sprintf("Service %s", status), true, nil
}
