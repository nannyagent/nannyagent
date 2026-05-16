package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"nannyagent/internal/ebpf"
	"nannyagent/internal/executor"
	"nannyagent/internal/investigations"
	"nannyagent/internal/logging"
	"nannyagent/internal/system"
	"nannyagent/internal/types"
)

// AgentConfig holds configuration for concurrent execution (local to agent)
type AgentConfig struct {
	MaxConcurrentTasks int  `json:"max_concurrent_tasks"`
	CollectiveResults  bool `json:"collective_results"`
}

// DefaultAgentConfig returns default configuration
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		MaxConcurrentTasks: 10,   // Default to 10 concurrent forks
		CollectiveResults:  true, // Send results collectively when all finish
	}
}

// LinuxDiagnosticAgent represents the main diagnostic agent
type LinuxDiagnosticAgent struct {
	model           string
	executor        *executor.CommandExecutor
	episodeID       string                // TensorZero episode ID for conversation continuity
	investigationID string                // Investigation ID for portal-created investigations
	ebpfManager     *ebpf.BCCTraceManager // eBPF tracing manager
	config          *AgentConfig          // Configuration for concurrent execution
	authManager     interface{}           // Authentication manager for TensorZero requests
	logger          *logging.Logger
	apiURL          string // NannyAPI URL
}

// NewLinuxDiagnosticAgent creates a new diagnostic agent
func NewLinuxDiagnosticAgent() *LinuxDiagnosticAgent {
	// Default model for diagnostic and healing
	model := "tensorzero::function_name::diagnose_and_heal"

	agent := &LinuxDiagnosticAgent{
		model:    model,
		executor: executor.NewCommandExecutor(10 * time.Second), // 10 second timeout for commands
		config:   DefaultAgentConfig(),                          // Default concurrent execution config
	}

	// Initialize eBPF manager
	agent.ebpfManager = ebpf.NewBCCTraceManager()
	agent.logger = logging.NewLogger()

	return agent
}

// NewLinuxDiagnosticAgentWithAuth creates a new diagnostic agent with authentication
func NewLinuxDiagnosticAgentWithAuth(authManager interface{}, apiURL string) *LinuxDiagnosticAgent {

	agent := &LinuxDiagnosticAgent{
		executor:    executor.NewCommandExecutor(10 * time.Second), // 10 second timeout for commands
		config:      DefaultAgentConfig(),                          // Default concurrent execution config
		authManager: authManager,                                   // Store auth manager for TensorZero requests
		apiURL:      apiURL,
	}

	// Initialize eBPF manager
	agent.ebpfManager = ebpf.NewBCCTraceManager()
	agent.logger = logging.NewLogger()

	return agent
}

// SetModel sets the model for the diagnostic agent
func (a *LinuxDiagnosticAgent) SetModel(model string) {
	a.model = model
}

// GetEpisodeID returns the current episode ID from TensorZero conversation
func (a *LinuxDiagnosticAgent) GetEpisodeID() string {
	return a.episodeID
}

// SetInvestigationID sets the investigation ID for portal-initiated investigations
func (a *LinuxDiagnosticAgent) SetInvestigationID(id string) {
	a.investigationID = id
}

// GetInvestigationID returns the current investigation ID
func (a *LinuxDiagnosticAgent) GetInvestigationID() string {
	return a.investigationID
}

// CreateInvestigation creates a new investigation record in the backend
func (a *LinuxDiagnosticAgent) CreateInvestigation(issue string) (string, error) {
	if a.authManager == nil {
		return "", fmt.Errorf("authentication required to create investigation")
	}

	// Get Agent ID
	var agentID string

	if authMgr, ok := a.authManager.(interface {
		GetCurrentAgentID() (string, error)
	}); ok {
		var err error
		agentID, err = authMgr.GetCurrentAgentID()
		if err != nil {
			return "", fmt.Errorf("failed to get agent ID: %w", err)
		}
	} else {
		return "", fmt.Errorf("auth manager does not support required interfaces")
	}

	// Get NannyAPI URL
	nannyAPIURL := a.apiURL
	if nannyAPIURL == "" {
		nannyAPIURL = os.Getenv("NANNYAPI_URL")
	}

	// Use investigations client
	auth, ok := a.authManager.(investigations.Authenticator)
	if !ok {
		return "", fmt.Errorf("auth manager does not support authenticated requests")
	}
	client := investigations.NewInvestigationsClient(nannyAPIURL, auth)

	resp, err := client.CreateInvestigation(agentID, issue, "medium")
	if err != nil {
		return "", fmt.Errorf("failed to create investigation: %w", err)
	}

	return resp.ID, nil
}

// DiagnoseIssue starts the diagnostic process for a given issue
// This is used for CLI or direct calls where investigation tracking is not needed
func (a *LinuxDiagnosticAgent) DiagnoseIssue(issue string) error {
	// For CLI mode, we first create an investigation record to get an ID
	// This allows the backend to track the investigation and proxy requests correctly
	logging.Info("Creating investigation record...")
	id, err := a.CreateInvestigation(issue)
	if err != nil {
		return fmt.Errorf("failed to create investigation record: %w", err)
	}

	a.investigationID = id
	logging.Info("Created investigation ID: %s", id)

	return a.diagnoseIssueInternal(issue)
}

// DiagnoseIssueWithInvestigation diagnoses an issue that was initiated by backend/portal
// The investigation_id is tracked externally (websocket handler updates status)
// This prevents creating duplicate investigations
func (a *LinuxDiagnosticAgent) DiagnoseIssueWithInvestigation(issue string) error {
	logging.Info("[DIAGNOSIS_TRACK] Investigation ID: %s", a.investigationID)
	return a.diagnoseIssueInternal(issue)
}

// diagnoseIssueInternal is the core diagnostic logic shared by both methods
func (a *LinuxDiagnosticAgent) diagnoseIssueInternal(issue string) error {
	logging.Info("Diagnosing issue: %s", issue)
	logging.Info("Gathering system information...")

	// Gather system information
	systemInfo := system.GatherSystemInfo()

	// Format the initial prompt with system information
	initialPrompt := system.FormatSystemInfoForPrompt(systemInfo) + "\n" + issue

	// Start conversation with initial issue including system info
	messages := []types.ChatMessage{
		{
			Role:    types.ChatMessageRoleUser,
			Content: initialPrompt,
		},
	}

	// Get NannyAPI URL
	nannyAPIURL := a.apiURL
	if nannyAPIURL == "" {
		nannyAPIURL = os.Getenv("NANNYAPI_URL")
	}

	// Initialize investigations client
	auth, ok := a.authManager.(investigations.Authenticator)
	if !ok {
		return fmt.Errorf("auth manager does not support authenticated requests")
	}
	client := investigations.NewInvestigationsClient(nannyAPIURL, auth)

	for {
		// Send request to TensorZero API via Investigations Client
		content, err := client.SendDiagnosticMessage(a.model, messages, a.investigationID)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}

		logging.Debug("AI Response: %s", content)

		content = stripResponseCodeFence(content)

		// Parse the response to determine next action
		var diagnosticResp types.EBPFEnhancedDiagnosticResponse
		var resolutionResp types.ResolutionResponse

		// Try to parse as diagnostic response first (with eBPF support)
		logging.Debug("Attempting to parse response as diagnostic...")
		if err := json.Unmarshal([]byte(content), &diagnosticResp); err == nil && diagnosticResp.ResponseType == "diagnostic" {
			logging.Debug("Successfully parsed as diagnostic response with %d commands", len(diagnosticResp.Commands))
			// Handle diagnostic phase
			logging.Debug("Reasoning: %s", diagnosticResp.Reasoning)

			// Execute commands and collect results
			commandResults := make([]types.CommandResult, 0, len(diagnosticResp.Commands))
			if len(diagnosticResp.Commands) > 0 {
				logging.Info("Executing %d diagnostic commands", len(diagnosticResp.Commands))
				for i, cmdStr := range diagnosticResp.Commands {
					// Convert string command to Command struct (auto-generate ID and description)
					cmd := types.Command{
						ID:          fmt.Sprintf("cmd_%d", i+1),
						Command:     cmdStr,
						Description: fmt.Sprintf("Diagnostic command: %s", cmdStr),
					}
					result := a.executor.Execute(cmd)
					commandResults = append(commandResults, result)

					if result.ExitCode != 0 {
						logging.Warning("Command '%s' failed with exit code %d", cmd.ID, result.ExitCode)
					}
				}
			}

			// Execute eBPF programs if present - support both old and new formats
			var ebpfResults []map[string]interface{}
			if len(diagnosticResp.EBPFPrograms) > 0 {
				logging.Info("AI requested %d eBPF traces for enhanced diagnostics", len(diagnosticResp.EBPFPrograms))

				// Convert EBPFPrograms to TraceSpecs and execute concurrently using the eBPF service
				traceSpecs := a.ConvertEBPFProgramsToTraceSpecs(diagnosticResp.EBPFPrograms)
				ebpfResults = a.ExecuteEBPFTraces(traceSpecs)
			}

			// Prepare combined results as user message
			allResults := map[string]interface{}{
				"command_results":   commandResults,
				"executed_commands": len(commandResults),
			}

			// Include eBPF results if any were executed
			if len(ebpfResults) > 0 {
				allResults["ebpf_results"] = ebpfResults
				allResults["executed_ebpf_programs"] = len(ebpfResults)

				// Extract evidence summary for TensorZero
				evidenceSummary := make([]string, 0)
				for _, result := range ebpfResults {
					target := result["target"]
					eventCount := result["event_count"]
					summary := result["summary"]
					success := result["success"]

					status := "failed"
					if success == true {
						status = "success"
					}

					summaryStr := fmt.Sprintf("%s: %v events (%s) - %s", target, eventCount, status, summary)
					evidenceSummary = append(evidenceSummary, summaryStr)
				}
				allResults["ebpf_evidence_summary"] = evidenceSummary
			}

			resultsJSON, err := json.MarshalIndent(allResults, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal command results: %w", err)
			}

			// Add AI response and command results to conversation
			messages = append(messages, types.ChatMessage{
				Role:    types.ChatMessageRoleAssistant,
				Content: content,
			})
			messages = append(messages, types.ChatMessage{
				Role:    types.ChatMessageRoleUser,
				Content: string(resultsJSON),
			})

			continue
		} else {
			logging.Debug("Failed to parse as diagnostic. Error: %v, ResponseType: '%s'", err, diagnosticResp.ResponseType)
		}

		// Try to parse as resolution response
		if err := json.Unmarshal([]byte(content), &resolutionResp); err == nil && resolutionResp.ResponseType == "resolution" {
			// Handle resolution phase
			logging.Info("=== DIAGNOSIS COMPLETE ===")
			logging.Info("Root Cause: %s", resolutionResp.RootCause)
			logging.Info("Resolution Plan: %s", resolutionResp.ResolutionPlan)
			logging.Info("Confidence: %s", resolutionResp.Confidence)

			break
		}

		// Ignore unparseable payloads rather than carrying forward legacy fallback handling.
		break
	}

	return nil
}

// ExecuteCommand executes a command using the agent's executor
func (a *LinuxDiagnosticAgent) ExecuteCommand(cmd types.Command) types.CommandResult {
	return a.executor.Execute(cmd)
}

// ConvertEBPFProgramsToTraceSpecs converts old EBPFProgram format to new TraceSpec format
func (a *LinuxDiagnosticAgent) ConvertEBPFProgramsToTraceSpecs(ebpfPrograms []types.EBPFRequest) []ebpf.TraceSpec {
	var traceSpecs []ebpf.TraceSpec

	for _, prog := range ebpfPrograms {
		spec := a.convertToTraceSpec(prog)
		traceSpecs = append(traceSpecs, spec)
	}

	return traceSpecs
}

// convertToTraceSpec converts an EBPFRequest to a TraceSpec for BCC-style tracing
func (a *LinuxDiagnosticAgent) convertToTraceSpec(prog types.EBPFRequest) ebpf.TraceSpec {
	// Set default duration if not specified
	duration := prog.Duration
	if duration <= 0 {
		duration = 10 // default 10 seconds
	}

	// Detect if target contains a full bpftrace script (has curly braces)
	// This handles both type="bpftrace" and cases where AI uses old type but includes script
	if prog.Type == "bpftrace" || strings.Contains(prog.Target, "{") {
		// For bpftrace type, the target contains the full script
		// We'll use a special marker to indicate this is a raw script
		return ebpf.TraceSpec{
			ProbeType: "bpftrace", // Special type for raw bpftrace scripts
			Target:    prog.Target,
			Format:    prog.Description,
			Arguments: []string{},
			Duration:  duration,
			UID:       -1,
		}
	}

	probeType, target := normalizeProbeTarget(prog)

	return ebpf.TraceSpec{
		ProbeType: probeType,
		Target:    target,
		Format:    prog.Description, // Use description as format
		Arguments: []string{},       // Start with no arguments for compatibility
		Duration:  duration,
		UID:       -1, // No UID filter (don't default to 0 which means root only)
	}
}

func stripResponseCodeFence(content string) string {
	content = strings.TrimSpace(content)

	switch {
	case strings.HasPrefix(content, "```json"):
		content = strings.TrimPrefix(content, "```json")
	case strings.HasPrefix(content, "```"):
		content = strings.TrimPrefix(content, "```")
	default:
		return content
	}

	return strings.TrimSpace(strings.TrimSuffix(content, "```"))
}

func normalizeProbeTarget(prog types.EBPFRequest) (string, string) {
	probeType := "p"
	target := prog.Target

	switch {
	case strings.HasPrefix(target, "tracepoint:"):
		return "t", strings.TrimPrefix(target, "tracepoint:")
	case strings.HasPrefix(target, "kprobe:"):
		return "p", strings.TrimPrefix(target, "kprobe:")
	}

	switch prog.Type {
	case "tracepoint":
		probeType = "t"
	case "kretprobe":
		probeType = "r"
	case "syscall":
		target = normalizeSyscallTarget(target)
	}

	return probeType, target
}

func normalizeSyscallTarget(target string) string {
	if strings.Contains(target, ":") || strings.HasPrefix(target, "__x64_sys_") {
		return target
	}

	switch {
	case strings.HasPrefix(target, "sys_"):
		return "__x64_" + target
	default:
		return "__x64_sys_" + target
	}
}

// executeEBPFTraces executes multiple eBPF traces using the eBPF service
func (a *LinuxDiagnosticAgent) ExecuteEBPFTraces(traceSpecs []ebpf.TraceSpec) []map[string]interface{} {
	if len(traceSpecs) == 0 {
		return []map[string]interface{}{}
	}

	a.logger.Info("Executing %d eBPF traces in parallel", len(traceSpecs))

	// Track trace IDs and their specs
	type traceInfo struct {
		index   int
		spec    ebpf.TraceSpec
		traceID string
		err     error
	}
	traces := make([]traceInfo, 0, len(traceSpecs))

	// Start all traces in parallel
	maxDuration := 0
	for i, spec := range traceSpecs {
		a.logger.Debug("Starting trace %d: %s", i, spec.Target)

		traceID, err := a.ebpfManager.StartTrace(spec)
		traces = append(traces, traceInfo{
			index:   i,
			spec:    spec,
			traceID: traceID,
			err:     err,
		})

		if err != nil {
			a.logger.Error("Failed to start trace %d: %v", i, err)
		} else {
			// Track the maximum duration
			if spec.Duration > maxDuration {
				maxDuration = spec.Duration
			}
		}
	}

	// Wait for the longest trace duration + buffer for output capture
	if maxDuration > 0 {
		a.logger.Info("Waiting %d seconds for all traces to complete", maxDuration)
		time.Sleep(time.Duration(maxDuration)*time.Second + 500*time.Millisecond)
	}

	// Collect results from all traces
	results := make([]map[string]interface{}, 0, len(traces))
	for _, trace := range traces {
		if trace.err != nil {
			result := map[string]interface{}{
				"index":   trace.index,
				"target":  trace.spec.Target,
				"success": false,
				"error":   trace.err.Error(),
			}
			results = append(results, result)
			continue
		}

		// Get the trace result
		traceResult, err := a.ebpfManager.GetTraceResult(trace.traceID)
		if err != nil {
			a.logger.Error("Failed to get results for trace %d: %v", trace.index, err)
			result := map[string]interface{}{
				"index":   trace.index,
				"target":  trace.spec.Target,
				"success": false,
				"error":   err.Error(),
			}
			results = append(results, result)
			continue
		}

		// Build successful result
		result := map[string]interface{}{
			"index":             trace.index,
			"target":            trace.spec.Target,
			"success":           true,
			"event_count":       traceResult.EventCount,
			"events_per_second": traceResult.Statistics.EventsPerSecond,
			"duration":          traceResult.EndTime.Sub(traceResult.StartTime).Seconds(),
			"summary":           traceResult.Summary,
		}

		// Include raw output for bpftrace scripts (aggregation results)
		if traceResult.EventCount > 0 {
			// Concatenate all event messages (which contain the raw bpftrace output)
			var rawOutput strings.Builder
			for _, event := range traceResult.Events {
				if event.Message != "" {
					rawOutput.WriteString(event.Message)
					rawOutput.WriteString("\n")
				}
			}
			if rawOutput.Len() > 0 {
				result["output"] = strings.TrimSpace(rawOutput.String())
			}
		}

		results = append(results, result)

		a.logger.Debug("Completed trace %d: %d events", trace.index, traceResult.EventCount)
	}

	a.logger.Info("Completed %d eBPF traces", len(results))
	return results
}
