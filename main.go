package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nannyagent/internal/agent"
	"nannyagent/internal/auth"
	"nannyagent/internal/config"
	"nannyagent/internal/logging"
	"nannyagent/internal/metrics"
	"nannyagent/internal/patches"
	"nannyagent/internal/proxmox"
	"nannyagent/internal/realtime"
	"nannyagent/internal/reboot"
	"nannyagent/internal/types"
)

const (
	// DataDir is the hardcoded path for agent data (not configurable)
	DataDir = "/var/lib/nannyagent"
)

var Version = "dev" // Will be set by build ldflags (e.g., -ldflags "-X main.Version=1.0.0")

// showVersion displays the version information (stdout only, no syslog)
func showVersion() {
	fmt.Printf("nannyagent version %s\n", Version)
	fmt.Println("Linux diagnostic agent with eBPF capabilities")
	os.Exit(0)
}

// showHelp displays the help information (stdout only, no syslog)
func showHelp() {
	fmt.Println("NannyAgent - AI-Powered Linux Diagnostic Agent")
	fmt.Printf("Version: %s\n\n", Version)
	fmt.Println("USAGE:")
	fmt.Printf("  %s [COMMAND] [OPTIONS]\n\n", os.Args[0])
	fmt.Println("COMMANDS:")
	fmt.Println("  --register                  Register agent with NannyAI")
	fmt.Println("  --status                    Show agent status")
	fmt.Println("  --diagnose <issue>          Run one-off diagnosis")
	fmt.Println("  --daemon                    Run as daemon (systemd)")
	fmt.Println("  --version                   Show version")
	fmt.Println("  --help                      Show this help")
	fmt.Println()
	fmt.Println("CONFIG OVERRIDES (higher priority than config.yaml):")
	fmt.Println("  --api-url <url>             NannyAPI endpoint URL")
	fmt.Println("  --portal-url <url>          Portal URL for device authorization")
	fmt.Println("  --token-path <path>         Token storage path")
	fmt.Println("  --metrics-interval <secs>   Metrics collection interval")
	fmt.Println("  --proxmox-interval <secs>   Proxmox data collection interval")
	fmt.Println("  --agent-id <id>             Agent ID (for static token mode)")
	fmt.Println("  --debug                     Enable debug mode")
	fmt.Println()
	fmt.Println("AUTHENTICATION:")
	fmt.Println("  OAuth2 (default):   Register interactively with --register")
	fmt.Println("  Static token:       Set static_token in /etc/nannyagent/config.yaml")
	fmt.Println("                      Then run --register to auto-register")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  sudo nannyagent --register")
	fmt.Println("  sudo nannyagent --register --api-url http://localhost:8090")
	fmt.Println("  nannyagent --status")
	fmt.Println("  sudo nannyagent --diagnose \"postgresql is slow\"")
	fmt.Println("  sudo nannyagent    # Interactive mode")
	fmt.Println()
	fmt.Printf("Documentation: https://nannyai.dev/documentation\n")
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
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		logging.Error("Cannot determine kernel version: %v", err)
		os.Exit(1)
	}

	kernelVersion := strings.TrimSpace(string(output))

	// Parse version (e.g., "5.15.0-56-generic" -> major=5, minor=15)
	parts := strings.Split(kernelVersion, ".")
	if len(parts) < 2 {
		logging.Error("Cannot parse kernel version: %s", kernelVersion)
		os.Exit(1)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		logging.Error("Cannot parse major kernel version: %s", parts[0])
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

// validateDiagnosisPrompt validates that a diagnosis prompt is meaningful
func validateDiagnosisPrompt(prompt string) error {
	prompt = strings.TrimSpace(prompt)

	// Check minimum length (at least 10 characters)
	if len(prompt) < 10 {
		return fmt.Errorf("prompt is too short (minimum 10 characters required)")
	}

	// Check it has at least 3 words for meaningful context
	words := strings.Fields(prompt)
	if len(words) < 3 {
		return fmt.Errorf("prompt is incomplete (minimum 3 words required for meaningful diagnosis)")
	}

	return nil
}

// testAPIConnectivity tests if we can reach the API endpoint using NannyAPI
func testAPIConnectivity(cfg *config.Config, authManager interface {
	AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}, agentID string) error {
	// Test by sending metrics to NannyAPI /api/agent endpoint
	metricsCollector := metrics.NewCollector(Version, cfg.APIBaseURL)
	systemMetrics, err := metricsCollector.GatherSystemMetrics()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	err = metricsCollector.IngestMetrics(agentID, authManager, systemMetrics)
	if err != nil {
		return fmt.Errorf("metrics ingestion failed: %w", err)
	}

	return nil
}

// checkExistingAgentInstance verifies if an agent is already registered on this machine
func checkExistingAgentInstance() error {
	tokenPath := filepath.Join(DataDir, "token.json")

	// Check if token file exists
	if _, err := os.Stat(tokenPath); err == nil {
		return fmt.Errorf("agent already registered on this machine (token found at %s)", tokenPath)
	}

	return nil
}

// runRegisterCommand handles agent registration with NannyAPI device flow
func runRegisterCommand(cliFlags *config.CLIFlags) {
	logging.Info("Starting NannyAgent registration with NannyAPI")

	// Check if agent is already registered on this machine
	if err := checkExistingAgentInstance(); err != nil {
		logging.Error("Cannot register: %v", err)
		logging.Error("Only one agent instance is allowed per machine")
		logging.Error("To re-register, remove the existing token:")
		logging.Error("  sudo rm -rf %s", DataDir)
		os.Exit(1)
	}

	// Load configuration (use defaults if not available)
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.Warning("Could not load configuration, using defaults: %v", err)
		cfg = &config.DefaultConfig
		cfg.APIBaseURL = os.Getenv("NANNYAPI_URL")
	}

	// Apply CLI flags (highest priority)
	cfg.ApplyCLIFlags(cliFlags)

	// Re-validate after CLI overrides
	if err := cfg.ValidateAfterMerge(); err != nil {
		logging.Error("Invalid configuration: %v", err)
		os.Exit(1)
	}

	// Ensure we have a NannyAPI URL
	if cfg.APIBaseURL == "" {
		logging.Error("NannyAPI URL not configured")
		logging.Error("Set NANNYAPI_URL environment variable, configure in /etc/nannyagent/config.yaml,")
		logging.Error("or pass --api-url <url>")
		os.Exit(1)
	}

	// ── Static token registration (fully automated, no user interaction) ────
	if cfg.UseStaticToken() {
		runStaticTokenRegister(cfg)
		return
	}

	// ── OAuth2 device flow registration (interactive) ──────────────────────
	runOAuthRegister(cfg)
}

// runStaticTokenRegister performs automated registration using a static token.
// It sends a single POST /api/agent with the static token — no device auth flow.
func runStaticTokenRegister(cfg *config.Config) {
	logging.Info("Using static token for direct registration (no device auth)")

	staticAuth := auth.NewStaticTokenAuthManager(cfg)

	resp, err := staticAuth.Register(Version)
	if err != nil {
		logging.Error("Registration failed: %v", err)
		os.Exit(1)
	}

	logging.Info("Registration successful!")
	logging.Info("Agent ID: %s", resp.AgentID)

	if err := cfg.SaveAgentID(resp.AgentID); err != nil {
		logging.Warning("Could not save agent_id to config file: %v", err)
		logging.Info("Please add manually: agent_id: \"%s\" to /etc/nannyagent/config.yaml", resp.AgentID)
	} else {
		logging.Info("Agent ID saved to /etc/nannyagent/config.yaml")
	}

	// Save a token marker file so checkExistingAgentInstance recognizes
	// the agent as registered and --status can read the agent_id.
	token := &types.AuthToken{
		AgentID:   resp.AgentID,
		TokenType: "static",
		ExpiresAt: time.Now().Add(100 * 365 * 24 * time.Hour), // effectively never
	}

	authMgr := auth.NewAuthManager(cfg)
	if err := authMgr.SaveToken(token); err != nil {
		logging.Warning("Failed to save token marker file: %v", err)
	}

	logging.Info("")
	logging.Info("Next steps:")
	logging.Info("  1. Enable and start the service: sudo systemctl enable --now nannyagent")
	logging.Info("  2. Check status: nannyagent --status")
	logging.Info("  3. View logs: sudo journalctl -u nannyagent -f")
	os.Exit(0)
}

// runOAuthRegister performs the interactive OAuth2 device flow registration.
func runOAuthRegister(cfg *config.Config) {
	// Initialize auth manager with NannyAPI URL
	authManager := auth.NewAuthManager(cfg)

	// Step 1: Start device authorization
	logging.Info("Initiating NannyAPI device authorization flow...")
	deviceAuth, err := authManager.StartDeviceAuthorization()
	if err != nil {
		logging.Error("Failed to start device authorization: %v", err)
		os.Exit(1)
	}

	// Step 2: Display user code to user
	logging.Info("")
	logging.Info("════════════════════════════════════════════════════════════")
	logging.Info("Please visit the following link to authorize this agent:")
	logging.Info("")
	logging.Info("Portal: https://nannyai.dev")
	logging.Info("User Code: %s", deviceAuth.UserCode)
	logging.Info("")
	logging.Info("Enter the code when prompted on the portal")
	logging.Info("════════════════════════════════════════════════════════════")
	logging.Info("")

	// Step 3: Poll for authorization with timeout (5 minutes)
	logging.Info("Waiting for authorization (timeout in 5 minutes)...")
	tokenResp, err := authManager.PollForTokenAfterAuthorization(deviceAuth.DeviceCode)
	if err != nil {
		logging.Error("Authorization failed: %v", err)
		os.Exit(1)
	}

	// Step 4: Create and save token
	token := &types.AuthToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		AgentID:      tokenResp.AgentID,
	}

	if err := authManager.SaveToken(token); err != nil {
		logging.Error("Failed to save token: %v", err)
		os.Exit(1)
	}

	logging.Info("Registration successful!")
	logging.Info("Agent ID: %s", token.AgentID)
	logging.Info("Token saved to: %s", cfg.TokenPath)
	logging.Info("")
	logging.Info("Next steps:")
	logging.Info("  1. Enable and start the service: sudo systemctl enable --now nannyagent")
	logging.Info("  2. Check status: nannyagent --status")
	logging.Info("  3. View logs: sudo journalctl -u nannyagent -f")
	os.Exit(0)
}

// runStatusCommand shows agent connectivity and status with NannyAPI (stdout only)
func runStatusCommand(cliFlags *config.CLIFlags) {
	// Disable syslog for status command - everything goes to stdout only
	logging.DisableSyslogOnly()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI flags
	cfg.ApplyCLIFlags(cliFlags)

	// Re-validate after CLI overrides
	if err := cfg.ValidateAfterMerge(); err != nil {
		fmt.Printf("Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Show API endpoint
	apiURL := cfg.APIBaseURL
	if apiURL == "" {
		apiURL = os.Getenv("NANNYAPI_URL")
	}
	fmt.Printf("API Endpoint: %s\n", apiURL)

	// Show auth mode
	if cfg.UseStaticToken() {
		fmt.Println("Auth Mode: Static Token")
	} else {
		fmt.Println("Auth Mode: OAuth2")
	}

	// Check if agent is registered
	if cfg.UseStaticToken() && cfg.AgentID != "" {
		// In static-token mode, a configured agent_id means the agent is registered
		// even if the token marker file is absent.
	} else {
		tokenPath := cfg.TokenPath
		if tokenPath == "" {
			tokenPath = filepath.Join(DataDir, "token.json")
		}
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			fmt.Println("Not registered")
			fmt.Println("\nRegister with: sudo nannyagent --register")
			os.Exit(1)
		}
	}

	if cfg.UseStaticToken() {
		// Static token mode: get agent ID from config or token file
		agentID := cfg.AgentID
		if agentID == "" {
			authManager := auth.NewAuthManager(cfg)
			agentID, err = authManager.GetCurrentAgentID()
			if err != nil {
				fmt.Println("Failed to get Agent ID")
				os.Exit(1)
			}
		}
		fmt.Printf("Agent ID: %s\n", agentID)

		// Test connectivity
		staticAuth := auth.NewStaticTokenAuthManager(cfg)
		if agentID != "" {
			staticAuth.SetAgentID(agentID)
		}
		metricsCollector := metrics.NewCollector(Version, cfg.APIBaseURL)
		systemMetrics, err := metricsCollector.GatherSystemMetrics()
		if err != nil {
			fmt.Println("Failed to gather metrics")
			os.Exit(1)
		}
		err = metricsCollector.IngestMetrics(agentID, staticAuth, systemMetrics)
		if err != nil {
			fmt.Println("Metrics ingestion failed")
			os.Exit(1)
		}
	} else {
		// OAuth mode
		authManager := auth.NewAuthManager(cfg)
		_, err = authManager.EnsureAuthenticated()
		if err != nil {
			fmt.Println("Authentication failed")
			os.Exit(1)
		}

		agentID, err := authManager.GetCurrentAgentID()
		if err != nil {
			fmt.Println("Failed to get Agent ID")
			os.Exit(1)
		}
		fmt.Printf("Agent ID: %s\n", agentID)

		metricsCollector := metrics.NewCollector(Version, cfg.APIBaseURL)
		systemMetrics, err := metricsCollector.GatherSystemMetrics()
		if err != nil {
			fmt.Println("Failed to gather metrics")
			os.Exit(1)
		}
		err = metricsCollector.IngestMetrics(agentID, authManager, systemMetrics)
		if err != nil {
			fmt.Println("Metrics ingestion failed")
			os.Exit(1)
		}
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.Command("systemctl", "is-active", "nannyagent")
		output, _ := cmd.Output()
		status := strings.TrimSpace(string(output))

		if status == "active" {
			fmt.Println("Service running")
		} else {
			fmt.Printf("Service %s\n", status)
		}
	}

	os.Exit(0)
}

// runInteractiveDiagnostics starts the interactive diagnostic session
func runInteractiveDiagnostics(diagAgent *agent.LinuxDiagnosticAgent) {
	logging.Info("Linux Diagnostic Agent Started")
	logging.Info("Enter a system issue description (or 'quit' to exit):")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "quit" || input == "exit" {
			break
		}

		if input == "" {
			continue
		}

		// Validate minimum prompt length (at least 10 characters for meaningful diagnosis)
		if len(input) < 10 {
			logging.Warning("Prompt is too short. Please provide a more detailed description of the problem.")
			logging.Info("Minimum 10 characters required. Example: 'Disk is full on /var partition'")
			continue
		}

		// Check if it's just 1 or 2 words
		words := strings.Fields(input)
		if len(words) < 3 {
			logging.Warning("Prompt is incomplete. Please describe the problem in more detail.")
			logging.Info("Example: 'Cannot create files in /var filesystem despite showing free space'")
			continue
		}

		// Process the issue with AI capabilities via TensorZero
		// First create investigation record
		logging.Info("Creating investigation record...")

		id, err := diagAgent.CreateInvestigation(input)
		if err != nil {
			logging.Error("Failed to create investigation record: %v", err)
			continue
		}

		logging.Info("Created investigation ID: %s", id)

		// Set ID on agent and run diagnosis
		diagAgent.SetInvestigationID(id)
		if err := diagAgent.DiagnoseIssueWithInvestigation(input); err != nil {
			logging.Error("Diagnosis failed: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		logging.Error("Scanner error: %v", err)
	}

	logging.Info("Goodbye!")
}

func main() {
	// Parse CLI flags (all config options available as --flag)
	cliFlags := config.ParseCLIFlags()

	// Also check for commands without -- prefix (for backward compatibility)
	// NOTE: Go's flag.Parse stops at the first non-flag argument, so config
	// flags (e.g. --api-url) placed *after* a positional command won't be
	// parsed.  Users should prefer the --command form for full flag support.
	if flag.NArg() > 0 {
		cmd := flag.Arg(0)
		switch cmd {
		case "register":
			logging.Warning("Please use: nannyagent --register (with -- prefix)")
			cliFlags.Register = true
		case "status":
			logging.Warning("Please use: nannyagent --status (with -- prefix)")
			cliFlags.Status = true
		case "diagnose":
			logging.Warning("Please use: nannyagent --diagnose (with -- prefix)")
			if flag.NArg() > 1 {
				cliFlags.Diagnose = flag.Arg(1)
			}
		case "daemon":
			logging.Warning("Please use: nannyagent --daemon (with -- prefix)")
			cliFlags.Daemon = true
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
	staticAuth := auth.NewStaticTokenAuthManager(cfg)

	// Verify we have an agent ID
	agentID, err := staticAuth.GetCurrentAgentID()
	if err != nil {
		// Try loading from token file as fallback
		oauthMgr := auth.NewAuthManager(cfg)
		agentID, err = oauthMgr.GetCurrentAgentID()
		if err != nil {
			logging.Error("Agent ID not found. Register first: sudo nannyagent --register")
			os.Exit(1)
		}
		staticAuth.SetAgentID(agentID)
	}

	// Verify static token works
	if err := staticAuth.EnsureAuthenticated(); err != nil {
		logging.Error("Static token authentication failed: %v", err)
		os.Exit(1)
	}

	// Test API connectivity
	logging.Info("Testing connectivity to NannyAPI with static token...")
	if err := testAPIConnectivity(cfg, staticAuth, agentID); err != nil {
		logging.Error("Cannot connect to NannyAPI API: %v", err)
		logging.Error("Endpoint: %s", cfg.APIBaseURL)
		os.Exit(1)
	}
	logging.Info("API connectivity OK (static token mode)")

	// Initialize the diagnostic agent
	diagAgent := agent.NewLinuxDiagnosticAgentWithAuth(staticAuth, cfg.APIBaseURL)

	// Handle --diagnose flag
	if cliFlags.Diagnose != "" {
		logging.Info("Running one-off diagnosis...")
		if err := validateDiagnosisPrompt(cliFlags.Diagnose); err != nil {
			logging.Error("%v", err)
			os.Exit(1)
		}
		if err := diagAgent.DiagnoseIssue(cliFlags.Diagnose); err != nil {
			logging.Error("Diagnosis failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Start SSE connection
	go func() {
		investigationHandler := func(id, prompt string) {
			prompt = strings.TrimSpace(prompt)
			investigationAgent := agent.NewLinuxDiagnosticAgentWithAuth(staticAuth, cfg.APIBaseURL)
			investigationAgent.SetInvestigationID(id)
			if err := investigationAgent.DiagnoseIssueWithInvestigation(prompt); err != nil {
				logging.Error("Investigation %s failed: %v", id, err)
			} else {
				logging.Info("Investigation %s completed successfully", id)
			}
		}

		patchHandler := func(payload types.AgentPatchPayload) {
			logging.Info("Triggering patch operation %s (mode: %s)...", payload.OperationID, payload.Mode)
			patchManager := patches.NewPatchManager(cfg.APIBaseURL, staticAuth, agentID)
			if err := patchManager.HandlePatchOperation(payload); err != nil {
				logging.Error("Patch operation %s failed: %v", payload.OperationID, err)
			}
		}

		rebootHandler := func(payload types.AgentRebootPayload) {
			logging.Info("Triggering reboot operation %s...", payload.RebootID)
			rebootManager := reboot.NewRebootManager(cfg.APIBaseURL, staticAuth)
			if err := rebootManager.HandleRebootOperation(payload); err != nil {
				logging.Error("Reboot operation %s failed: %v", payload.RebootID, err)
			}
		}

		realtimeClient := realtime.NewClient(cfg.APIBaseURL, staticAuth, investigationHandler, patchHandler, rebootHandler)
		realtimeClient.Start()
	}()

	// Start metrics ingestion
	go func() {
		logging.Info("Starting metrics ingestion (interval: %ds, static token)...", cfg.MetricsInterval)
		metricsCollector := metrics.NewCollector(Version, cfg.APIBaseURL)
		ticker := time.NewTicker(time.Duration(cfg.MetricsInterval) * time.Second)
		defer ticker.Stop()

		systemMetrics, err := metricsCollector.GatherSystemMetrics()
		if err == nil {
			if err := metricsCollector.IngestMetrics(agentID, staticAuth, systemMetrics); err != nil {
				logging.Error("Failed to ingest initial metrics: %v", err)
			}
		}

		for range ticker.C {
			systemMetrics, err := metricsCollector.GatherSystemMetrics()
			if err != nil {
				logging.Error("Failed to gather metrics: %v", err)
				continue
			}
			if err := metricsCollector.IngestMetrics(agentID, staticAuth, systemMetrics); err != nil {
				logging.Error("Failed to ingest metrics: %v", err)
			}
		}
	}()

	// No token renewal goroutine needed for static tokens

	// Start Proxmox collector
	proxmoxManager := proxmox.NewManager(cfg, staticAuth)
	proxmoxManager.Start()

	// Check if running in daemon mode
	if cliFlags.Daemon {
		if err := logging.EnableSyslogOnly(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize syslog: %v\n", err)
			os.Exit(1)
		}
		logging.Info("Running in daemon mode (static token, no interactive session)")
		select {}
	}

	// Interactive mode
	if !cliFlags.Daemon {
		runInteractiveDiagnostics(diagAgent)
	}
}

// runWithOAuth runs the agent using the traditional OAuth2 device flow.
func runWithOAuth(cfg *config.Config, cliFlags *config.CLIFlags) {
	// Initialize components
	authManager := auth.NewAuthManager(cfg)

	// Ensure authentication
	_, err := authManager.EnsureAuthenticated()
	if err != nil {
		logging.Error("Authentication failed: %v", err)
		os.Exit(1)
	}

	// Get Agent ID
	agentID, err := authManager.GetCurrentAgentID()
	if err != nil {
		logging.Error("Failed to get Agent ID: %v", err)
		os.Exit(1)
	}

	// Test API connectivity with authenticated token
	logging.Info("Testing connectivity to NannyAPI API...")
	if err := testAPIConnectivity(cfg, authManager, agentID); err != nil {
		logging.Error("Cannot connect to NannyAPI API: %v", err)
		logging.Error("Endpoint: %s", cfg.APIBaseURL)
		logging.Error("Please check:")
		logging.Error("  1. Network connectivity")
		logging.Error("  2. Firewall settings")
		logging.Error("  3. API endpoint configured in /etc/nannyagent/config.yaml")
		os.Exit(1)
	}
	logging.Info("API connectivity OK")

	logging.Info("Authentication successful!")

	// Initialize the diagnostic agent for interactive CLI use with authentication
	diagAgent := agent.NewLinuxDiagnosticAgentWithAuth(authManager, cfg.APIBaseURL)

	// Handle --diagnose flag (one-off diagnosis)
	if cliFlags.Diagnose != "" {
		logging.Info("Running one-off diagnosis...")

		// Validate the diagnosis prompt
		if err := validateDiagnosisPrompt(cliFlags.Diagnose); err != nil {
			logging.Error("%v", err)
			logging.Info("Example: sudo nannyagent --diagnose \"postgresql is slow and using high CPU\"")
			os.Exit(1)
		}

		if err := diagAgent.DiagnoseIssue(cliFlags.Diagnose); err != nil {
			logging.Error("Diagnosis failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Start SSE connection in a separate goroutine
	go func() {
		investigationHandler := func(id, prompt string) {
			prompt = strings.TrimSpace(prompt)
			investigationAgent := agent.NewLinuxDiagnosticAgentWithAuth(authManager, cfg.APIBaseURL)
			investigationAgent.SetInvestigationID(id)
			if err := investigationAgent.DiagnoseIssueWithInvestigation(prompt); err != nil {
				logging.Error("Investigation %s failed: %v", id, err)
			} else {
				logging.Info("Investigation %s completed successfully", id)
			}
		}

		patchHandler := func(payload types.AgentPatchPayload) {
			logging.Info("Triggering patch operation %s (mode: %s)...", payload.OperationID, payload.Mode)
			patchManager := patches.NewPatchManager(cfg.APIBaseURL, authManager, agentID)
			if err := patchManager.HandlePatchOperation(payload); err != nil {
				logging.Error("Patch operation %s failed: %v", payload.OperationID, err)
			} else {
				logging.Info("Patch operation %s completed successfully", payload.OperationID)
			}
		}

		rebootHandler := func(payload types.AgentRebootPayload) {
			logging.Info("Triggering reboot operation %s...", payload.RebootID)
			rebootManager := reboot.NewRebootManager(cfg.APIBaseURL, authManager)
			if err := rebootManager.HandleRebootOperation(payload); err != nil {
				logging.Error("Reboot operation %s failed: %v", payload.RebootID, err)
			} else {
				logging.Info("Reboot operation %s completed successfully", payload.RebootID)
			}
		}

		realtimeClient := realtime.NewClient(cfg.APIBaseURL, authManager, investigationHandler, patchHandler, rebootHandler)
		realtimeClient.Start()
	}()

	// Start metrics ingestion in a separate goroutine
	go func() {
		logging.Info("Starting metrics ingestion (interval: %ds)...", cfg.MetricsInterval)
		metricsCollector := metrics.NewCollector(Version, cfg.APIBaseURL)
		ticker := time.NewTicker(time.Duration(cfg.MetricsInterval) * time.Second)
		defer ticker.Stop()

		systemMetrics, err := metricsCollector.GatherSystemMetrics()
		if err == nil {
			if err := metricsCollector.IngestMetrics(agentID, authManager, systemMetrics); err != nil {
				logging.Error("Failed to ingest initial metrics: %v", err)
			}
		}

		for range ticker.C {
			systemMetrics, err := metricsCollector.GatherSystemMetrics()
			if err != nil {
				logging.Error("Failed to gather metrics: %v", err)
				continue
			}
			if err := metricsCollector.IngestMetrics(agentID, authManager, systemMetrics); err != nil {
				logging.Error("Failed to ingest metrics: %v", err)
			}
		}
	}()

	// Start background refresh token renewal goroutine (OAuth only)
	go func() {
		normalCheckInterval := time.Duration(cfg.TokenRenewalCheckIntervalSecs) * time.Second
		retryInterval := time.Duration(cfg.TokenRenewalRetryIntervalSecs) * time.Second

		nextCheck := time.Now().Add(normalCheckInterval)

		for {
			now := time.Now()
			if now.Before(nextCheck) {
				time.Sleep(time.Until(nextCheck))
			}

			token, err := authManager.LoadTokenRaw()
			if err != nil {
				logging.Warning("Token renewal check: failed to load token: %v", err)
				nextCheck = time.Now().Add(normalCheckInterval)
				continue
			}
			if token.RefreshToken == "" {
				nextCheck = time.Now().Add(normalCheckInterval)
				continue
			}

			refreshResp, err := authManager.RefreshAccessToken(token.RefreshToken)
			if err != nil {
				logging.Warning("Token renewal check: refresh call failed: %v", err)
				nextCheck = time.Now().Add(normalCheckInterval)
				continue
			}

			updatedToken := &types.AuthToken{
				AccessToken:  refreshResp.AccessToken,
				RefreshToken: token.RefreshToken,
				TokenType:    refreshResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second),
				AgentID:      token.AgentID,
			}
			if saveErr := authManager.SaveToken(updatedToken); saveErr != nil {
				logging.Warning("Token renewal check: failed to save updated token: %v", saveErr)
			}

			if !auth.NeedsRefreshTokenRenewal(refreshResp.RefreshTokenExpiresIn, cfg.TokenRenewalThresholdDays) {
				nextCheck = time.Now().Add(normalCheckInterval)
				continue
			}

			logging.Info("Refresh token expires in %ds (threshold: %d days) — renewing...",
				refreshResp.RefreshTokenExpiresIn, cfg.TokenRenewalThresholdDays)
			renewResp, err := authManager.RenewRefreshToken(token.RefreshToken)
			if err != nil {
				logging.Warning("Refresh token renewal failed: %v (will retry in %s)", err, retryInterval)
				nextCheck = time.Now().Add(retryInterval)
				continue
			}

			newToken := &types.AuthToken{
				AccessToken:  renewResp.AccessToken,
				RefreshToken: renewResp.RefreshToken,
				TokenType:    renewResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(renewResp.ExpiresIn) * time.Second),
				AgentID:      token.AgentID,
			}
			if err := authManager.SaveToken(newToken); err != nil {
				logging.Warning("Failed to save renewed token: %v (will retry in %s)", err, retryInterval)
				nextCheck = time.Now().Add(retryInterval)
				continue
			}

			logging.Info("Refresh token renewed and saved successfully")
			nextCheck = time.Now().Add(normalCheckInterval)
		}
	}()

	// Start Proxmox collector
	proxmoxManager := proxmox.NewManager(cfg, authManager)
	proxmoxManager.Start()

	// Check if running in daemon mode
	if cliFlags.Daemon {
		if err := logging.EnableSyslogOnly(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize syslog: %v\n", err)
			os.Exit(1)
		}

		logging.Info("Running in daemon mode (no interactive session)")
		logging.Info("Logs will be sent to syslog. View with: journalctl -u nannyagent -f")
		select {}
	}

	// Handle interactive mode (default if no flags)
	if !cliFlags.Daemon {
		runInteractiveDiagnostics(diagAgent)
	}
}
