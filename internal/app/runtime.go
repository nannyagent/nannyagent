package app

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
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

func RunRegisterCommand(version, dataDir string, cliFlags *config.CLIFlags) {
	logging.Info("Starting NannyAgent registration with NannyAPI")

	cfg, tokenPath, err := loadRegisterConfig(dataDir, cliFlags)
	if err != nil {
		logging.Error("Invalid configuration: %v", err)
		os.Exit(1)
	}

	if err := CheckExistingAgentInstance(tokenPath); err != nil {
		logging.Error("Cannot register: %v", err)
		logging.Error("Only one agent instance is allowed per machine")
		logging.Error("To re-register, remove the existing token:")
		logging.Error("  sudo rm -rf %s", dataDir)
		os.Exit(1)
	}

	if cfg.APIBaseURL == "" {
		logging.Error("NannyAPI URL not configured")
		logging.Error("Set NANNYAPI_URL environment variable, configure in /etc/nannyagent/config.yaml,")
		logging.Error("or pass --api-url <url>")
		os.Exit(1)
	}

	if cfg.UseStaticToken() {
		runStaticTokenRegister(version, cfg)
		return
	}

	runOAuthRegister(cfg)
}

func loadRegisterConfig(dataDir string, cliFlags *config.CLIFlags) (*config.Config, string, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.Warning("Could not load configuration, using defaults: %v", err)
		defaultConfig := config.DefaultConfig
		cfg = &defaultConfig
		cfg.APIBaseURL = os.Getenv("NANNYAPI_URL")
	}

	cfg.ApplyCLIFlags(cliFlags)
	if err := cfg.ValidateAfterMerge(); err != nil {
		return nil, "", err
	}

	return cfg, TokenPath(cfg.TokenPath, dataDir), nil
}

func runStaticTokenRegister(version string, cfg *config.Config) {
	logging.Info("Using static token for direct registration (no device auth)")

	staticAuth := auth.NewStaticTokenAuthManager(cfg)
	resp, err := staticAuth.Register(version)
	if err != nil {
		logging.Error("Registration failed: %v", err)
		os.Exit(1)
	}

	logging.Info("Registration successful!")
	logging.Info("Agent ID: %s", resp.AgentID)

	if err := cfg.SaveAgentID(resp.AgentID); err != nil {
		logging.Warning("Could not save agent_id to config file: %v", err)
		logging.Info("Please add manually: agent_id: %q to /etc/nannyagent/config.yaml", resp.AgentID)
	} else {
		logging.Info("Agent ID saved to /etc/nannyagent/config.yaml")
	}

	token := &types.AuthToken{
		AgentID:   resp.AgentID,
		TokenType: "static",
		ExpiresAt: time.Now().Add(100 * 365 * 24 * time.Hour),
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

func runOAuthRegister(cfg *config.Config) {
	authManager := auth.NewAuthManager(cfg)

	logging.Info("Initiating NannyAPI device authorization flow...")
	deviceAuth, err := authManager.StartDeviceAuthorization()
	if err != nil {
		logging.Error("Failed to start device authorization: %v", err)
		os.Exit(1)
	}

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

	logging.Info("Waiting for authorization (timeout in 5 minutes)...")
	tokenResp, err := authManager.PollForTokenAfterAuthorization(deviceAuth.DeviceCode)
	if err != nil {
		logging.Error("Authorization failed: %v", err)
		os.Exit(1)
	}

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

func RunStatusCommand(version, dataDir string, cliFlags *config.CLIFlags) {
	logging.DisableSyslogOnly()

	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		os.Exit(1)
	}

	cfg.ApplyCLIFlags(cliFlags)
	if err := cfg.ValidateAfterMerge(); err != nil {
		fmt.Printf("Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	apiURL := cfg.APIBaseURL
	if apiURL == "" {
		apiURL = os.Getenv("NANNYAPI_URL")
	}
	fmt.Printf("API Endpoint: %s\n", apiURL)

	if cfg.UseStaticToken() {
		fmt.Println("Auth Mode: Static Token")
	} else {
		fmt.Println("Auth Mode: OAuth2")
	}

	if !cfg.UseStaticToken() || cfg.AgentID == "" {
		tokenPath := TokenPath(cfg.TokenPath, dataDir)
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			fmt.Println("Not registered")
			fmt.Println("\nRegister with: sudo nannyagent --register")
			os.Exit(1)
		}
	}

	if cfg.UseStaticToken() {
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

		staticAuth := auth.NewStaticTokenAuthManager(cfg)
		if agentID != "" {
			staticAuth.SetAgentID(agentID)
		}
		if err := TestAPIConnectivity(version, cfg, staticAuth, agentID); err != nil {
			fmt.Println("Metrics ingestion failed")
			os.Exit(1)
		}
	} else {
		authManager := auth.NewAuthManager(cfg)
		if _, err = authManager.EnsureAuthenticated(); err != nil {
			fmt.Println("Authentication failed")
			os.Exit(1)
		}

		agentID, err := authManager.GetCurrentAgentID()
		if err != nil {
			fmt.Println("Failed to get Agent ID")
			os.Exit(1)
		}
		fmt.Printf("Agent ID: %s\n", agentID)

		if err := TestAPIConnectivity(version, cfg, authManager, agentID); err != nil {
			fmt.Println("Metrics ingestion failed")
			os.Exit(1)
		}
	}

	serviceStatus, available, err := ResolveSystemdServiceStatus(exec.LookPath, func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}, "nannyagent")
	if err == nil && available {
		fmt.Println(serviceStatus)
	}

	os.Exit(0)
}

func RunInteractiveDiagnostics(diagAgent *agent.LinuxDiagnosticAgent) {
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

		if err := ValidateDiagnosisPrompt(input); err != nil {
			if strings.Contains(err.Error(), "too short") {
				logging.Warning("Prompt is too short. Please provide a more detailed description of the problem.")
				logging.Info("Minimum 10 characters required. Example: 'Disk is full on /var partition'")
			} else {
				logging.Warning("Prompt is incomplete. Please describe the problem in more detail.")
				logging.Info("Example: 'Cannot create files in /var filesystem despite showing free space'")
			}
			continue
		}

		logging.Info("Creating investigation record...")
		id, err := diagAgent.CreateInvestigation(input)
		if err != nil {
			logging.Error("Failed to create investigation record: %v", err)
			continue
		}

		logging.Info("Created investigation ID: %s", id)
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

func RunWithStaticToken(version string, cfg *config.Config, cliFlags *config.CLIFlags) {
	staticAuth := auth.NewStaticTokenAuthManager(cfg)

	agentID, err := staticAuth.GetCurrentAgentID()
	if err != nil {
		oauthMgr := auth.NewAuthManager(cfg)
		agentID, err = oauthMgr.GetCurrentAgentID()
		if err != nil {
			logging.Error("Agent ID not found. Register first: sudo nannyagent --register")
			os.Exit(1)
		}
		staticAuth.SetAgentID(agentID)
	}

	if err := staticAuth.EnsureAuthenticated(); err != nil {
		logging.Error("Static token authentication failed: %v", err)
		os.Exit(1)
	}

	logging.Info("Testing connectivity to NannyAPI with static token...")
	if err := TestAPIConnectivity(version, cfg, staticAuth, agentID); err != nil {
		logging.Error("Cannot connect to NannyAPI API: %v", err)
		logging.Error("Endpoint: %s", cfg.APIBaseURL)
		os.Exit(1)
	}
	logging.Info("API connectivity OK (static token mode)")

	diagAgent := agent.NewLinuxDiagnosticAgentWithAuth(staticAuth, cfg.APIBaseURL)
	if cliFlags.Diagnose != "" {
		logging.Info("Running one-off diagnosis...")
		if err := ValidateDiagnosisPrompt(cliFlags.Diagnose); err != nil {
			logging.Error("%v", err)
			os.Exit(1)
		}
		if err := diagAgent.DiagnoseIssue(cliFlags.Diagnose); err != nil {
			logging.Error("Diagnosis failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

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

	go func() {
		logging.Info("Starting metrics ingestion (interval: %ds, static token)...", cfg.MetricsInterval)
		metricsCollector := metrics.NewCollector(version, cfg.APIBaseURL)
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

	proxmoxManager := proxmox.NewManager(cfg, staticAuth)
	proxmoxManager.Start()

	if cliFlags.Daemon {
		if err := logging.EnableSyslogOnly(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize syslog: %v\n", err)
			os.Exit(1)
		}
		logging.Info("Running in daemon mode (static token, no interactive session)")
		select {}
	}

	RunInteractiveDiagnostics(diagAgent)
}

func RunWithOAuth(version string, cfg *config.Config, cliFlags *config.CLIFlags) {
	authManager := auth.NewAuthManager(cfg)

	if _, err := authManager.EnsureAuthenticated(); err != nil {
		logging.Error("Authentication failed: %v", err)
		os.Exit(1)
	}

	agentID, err := authManager.GetCurrentAgentID()
	if err != nil {
		logging.Error("Failed to get Agent ID: %v", err)
		os.Exit(1)
	}

	logging.Info("Testing connectivity to NannyAPI API...")
	if err := TestAPIConnectivity(version, cfg, authManager, agentID); err != nil {
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

	diagAgent := agent.NewLinuxDiagnosticAgentWithAuth(authManager, cfg.APIBaseURL)
	if cliFlags.Diagnose != "" {
		logging.Info("Running one-off diagnosis...")
		if err := ValidateDiagnosisPrompt(cliFlags.Diagnose); err != nil {
			logging.Error("%v", err)
			logging.Info("Example: sudo nannyagent --diagnose %q", "postgresql is slow and using high CPU")
			os.Exit(1)
		}
		if err := diagAgent.DiagnoseIssue(cliFlags.Diagnose); err != nil {
			logging.Error("Diagnosis failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

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

	go func() {
		logging.Info("Starting metrics ingestion (interval: %ds)...", cfg.MetricsInterval)
		metricsCollector := metrics.NewCollector(version, cfg.APIBaseURL)
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

			logging.Info("Refresh token expires in %ds (threshold: %d days) — renewing...", refreshResp.RefreshTokenExpiresIn, cfg.TokenRenewalThresholdDays)
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

	proxmoxManager := proxmox.NewManager(cfg, authManager)
	proxmoxManager.Start()

	if cliFlags.Daemon {
		if err := logging.EnableSyslogOnly(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to initialize syslog: %v\n", err)
			os.Exit(1)
		}

		logging.Info("Running in daemon mode (no interactive session)")
		logging.Info("Logs will be sent to syslog. View with: journalctl -u nannyagent -f")
		select {}
	}

	RunInteractiveDiagnostics(diagAgent)
}
