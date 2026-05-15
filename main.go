package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"nannyagent/internal/app"
	"nannyagent/internal/config"
	"nannyagent/internal/hostinfo"
	"nannyagent/internal/logging"
)

const (
	// DataDir is the hardcoded path for agent data (not configurable)
	DataDir = "/var/lib/nannyagent"
)

var Version = "dev" // Will be set by build ldflags (e.g., -ldflags "-X main.Version=1.0.0")

// showVersion displays the version information (stdout only, no syslog)
func showVersion() {
	fmt.Print(app.VersionText(Version))
	os.Exit(0)
}

// showHelp displays the help information (stdout only, no syslog)
func showHelp() {
	fmt.Print(app.HelpText(os.Args[0], Version))
	os.Exit(0)
}

// checkRootPrivileges ensures the program is running as root
func checkRootPrivileges() {
	if os.Geteuid() != 0 {
		logging.Error("This program must be run as root for eBPF functionality")
		logging.Error("Please run with: sudo %s", os.Args[0])
		logging.Error("Reason: eBPF programs require root privileges to:\n - Load programs into the kernel\n - Attach to kernel functions and tracepoints\n - Access kernel memory maps")
		os.Exit(1)
	}
}

// checkKernelVersionCompatibility ensures kernel version is 5.x or higher
func checkKernelVersionCompatibility() {
	kernelVersion := hostinfo.KernelVersion()
	major, err := app.KernelMajorVersion(kernelVersion)
	if err != nil {
		logging.Error("%v", err)
		os.Exit(1)
	}

	// Check if kernel is 5.x or higher
	if major < 5 {
		logging.Error("Kernel version %s is not supported", kernelVersion)
		logging.Error("Required: Linux kernel 5.x or higher")
		logging.Error("Current: %s (major version: %d)", kernelVersion, major)
		logging.Error("Reason: NannyAgent requires modern kernel features:\n - Advanced eBPF capabilities\n - BTF (BPF Type Format) support\n - Enhanced security and stability")
		os.Exit(1)
	}
}

// checkEBPFSupport validates eBPF subsystem availability
func checkEBPFSupport() {
	// Check if /sys/kernel/debug/tracing exists (debugfs mounted)
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		logging.Warning("debugfs not mounted. Some eBPF features may not work")
		logging.Info("To fix: sudo mount -t debugfs debugfs /sys/kernel/debug")
	}

	// Check if bpftrace is available (this is all we need)
	if _, err := exec.LookPath("bpftrace"); err != nil {
		logging.Error("bpftrace not found in PATH")
		logging.Error("Please install bpftrace: apt-get install bpftrace (Debian/Ubuntu) or yum install bpftrace (RHEL/CentOS)")
		os.Exit(1)
	}
}

// runRegisterCommand handles agent registration with NannyAPI device flow
func runRegisterCommand(cliFlags *config.CLIFlags) {
	app.RunRegisterCommand(Version, DataDir, cliFlags)
}

// runStatusCommand shows agent connectivity and status with NannyAPI (stdout only)
func runStatusCommand(cliFlags *config.CLIFlags) {
	app.RunStatusCommand(Version, DataDir, cliFlags)
}

func main() {
	// Parse CLI flags (all config options available as --flag)
	cliFlags := config.ParseCLIFlags()

	// Also check for commands without -- prefix (for backward compatibility)
	// NOTE: Go's flag.Parse stops at the first non-flag argument, so config
	// flags (e.g. --api-url) placed *after* a positional command won't be
	// parsed.  Users should prefer the --command form for full flag support.
	if flag.NArg() > 0 {
		for _, warning := range app.ApplyLegacyPositionalCommands(cliFlags, flag.Args()) {
			logging.Warning("%s", warning)
		}
	}

	// Whitelist: commands that don't require root or auth
	// Handle --version flag (no root required)
	if cliFlags.Version {
		showVersion()
	}

	// Handle --help flag (no root required)
	if cliFlags.Help {
		showHelp()
	}

	// Handle --status flag (no root or auth required) - EXIT IMMEDIATELY
	if cliFlags.Status {
		runStatusCommand(cliFlags)
		return
	}

	// Handle --register flag (requires root, no auth needed) - EXIT IMMEDIATELY
	if cliFlags.Register {
		checkRootPrivileges()
		runRegisterCommand(cliFlags)
		return
	}

	logging.Info("NannyAgent v%s starting...", Version)

	// Perform system compatibility checks first
	logging.Info("Performing system compatibility checks...")
	checkRootPrivileges()
	checkKernelVersionCompatibility()
	checkEBPFSupport()
	logging.Info("All system checks passed")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Apply CLI flags (highest priority)
	cfg.ApplyCLIFlags(cliFlags)

	// Re-validate after CLI overrides
	if err := cfg.ValidateAfterMerge(); err != nil {
		logging.Error("Invalid configuration: %v", err)
		os.Exit(1)
	}

	cfg.PrintConfig()

	// ── Branch on authentication mode ──────────────────────────────────────
	if cfg.UseStaticToken() {
		runWithStaticToken(cfg, cliFlags)
	} else {
		runWithOAuth(cfg, cliFlags)
	}
}

// runWithStaticToken runs the agent using a static API token.
// No OAuth token refresh or renewal goroutines are started.
func runWithStaticToken(cfg *config.Config, cliFlags *config.CLIFlags) {
	app.RunWithStaticToken(Version, cfg, cliFlags)
}

// runWithOAuth runs the agent using the traditional OAuth2 device flow.
func runWithOAuth(cfg *config.Config, cliFlags *config.CLIFlags) {
	app.RunWithOAuth(Version, cfg, cliFlags)
}
