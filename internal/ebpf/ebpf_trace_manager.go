package ebpf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"nannyagent/internal/logging"
)

// TraceSpec represents a trace specification similar to BCC trace.py
type TraceSpec struct {
	// Probe type: "p" (kprobe), "r" (kretprobe), "t" (tracepoint), "u" (uprobe)
	ProbeType string `json:"probe_type"`

	// Target function/syscall/tracepoint
	Target string `json:"target"`

	// Library for userspace probes (empty for kernel)
	Library string `json:"library,omitempty"`

	// Format string for output (e.g., "read %d bytes", arg3)
	Format string `json:"format"`

	// Arguments to extract (e.g., ["arg1", "arg2", "retval"])
	Arguments []string `json:"arguments"`

	// Filter condition (e.g., "arg3 > 20000")
	Filter string `json:"filter,omitempty"`

	// Duration in seconds
	Duration int `json:"duration"`

	// Process ID filter (optional)
	PID int `json:"pid,omitempty"`

	// Thread ID filter (optional)
	TID int `json:"tid,omitempty"`

	// UID filter (optional)
	UID int `json:"uid,omitempty"`

	// Process name filter (optional)
	ProcessName string `json:"process_name,omitempty"`
}

// TraceEvent represents a captured event from eBPF
type TraceEvent struct {
	Timestamp   int64             `json:"timestamp"`
	PID         int               `json:"pid"`
	TID         int               `json:"tid"`
	UID         int               `json:"uid"`
	ProcessName string            `json:"process_name"`
	Function    string            `json:"function"`
	Message     string            `json:"message"`
	RawArgs     map[string]string `json:"raw_args"`
	CPU         int               `json:"cpu,omitempty"`
}

// TraceResult represents the results of a tracing session
type TraceResult struct {
	TraceID    string       `json:"trace_id"`
	Spec       TraceSpec    `json:"spec"`
	Events     []TraceEvent `json:"events"`
	EventCount int          `json:"event_count"`
	StartTime  time.Time    `json:"start_time"`
	EndTime    time.Time    `json:"end_time"`
	Summary    string       `json:"summary"`
	Statistics TraceStats   `json:"statistics"`
}

// TraceStats provides statistics about the trace
type TraceStats struct {
	TotalEvents     int            `json:"total_events"`
	EventsByProcess map[string]int `json:"events_by_process"`
	EventsByUID     map[int]int    `json:"events_by_uid"`
	EventsPerSecond float64        `json:"events_per_second"`
	TopProcesses    []ProcessStat  `json:"top_processes"`
}

// ProcessStat represents statistics for a process
type ProcessStat struct {
	ProcessName string  `json:"process_name"`
	PID         int     `json:"pid"`
	EventCount  int     `json:"event_count"`
	Percentage  float64 `json:"percentage"`
}

// BCCTraceManager implements advanced eBPF tracing similar to BCC trace.py
type BCCTraceManager struct {
	traces       map[string]*RunningTrace
	tracesLock   sync.RWMutex
	traceCounter int
	capabilities map[string]bool
}

// RunningTrace represents an active trace session
type RunningTrace struct {
	ID        string
	Spec      TraceSpec
	Process   *exec.Cmd
	Events    []TraceEvent
	StartTime time.Time
	Cancel    context.CancelFunc
	Context   context.Context
	Done      chan struct{} // Signal when trace monitoring is complete
}

// NewBCCTraceManager creates a new BCC-style trace manager
func NewBCCTraceManager() *BCCTraceManager {
	manager := &BCCTraceManager{
		traces:       make(map[string]*RunningTrace),
		capabilities: make(map[string]bool),
	}

	manager.testCapabilities()
	return manager
}

// testCapabilities checks what tracing capabilities are available
func (tm *BCCTraceManager) testCapabilities() {
	// Test if bpftrace is available
	if bpftracePath, err := exec.LookPath("bpftrace"); err == nil {
		tm.capabilities["bpftrace"] = true
		logging.Debug("bpftrace found at: %s", bpftracePath)
	} else {
		tm.capabilities["bpftrace"] = false
		logging.Warning("bpftrace not found in PATH")
	}

	// Test if perf is available for fallback
	if _, err := exec.LookPath("perf"); err == nil {
		tm.capabilities["perf"] = true
	} else {
		tm.capabilities["perf"] = false
	}

	// Test root privileges (required for eBPF)
	tm.capabilities["root_access"] = os.Geteuid() == 0

	// Test kernel version
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err == nil {
		version := strings.TrimSpace(string(output))
		// eBPF requires kernel 4.4+
		tm.capabilities["kernel_ebpf"] = !strings.HasPrefix(version, "3.")
	} else {
		tm.capabilities["kernel_ebpf"] = false
	}

	// Test if we can access debugfs
	if _, err := os.Stat("/sys/kernel/debug/tracing/available_events"); err == nil {
		tm.capabilities["debugfs_access"] = true
	} else {
		tm.capabilities["debugfs_access"] = false
	}

	logging.Debug("BCC Trace capabilities: %+v", tm.capabilities)
}

// GetCapabilities returns available tracing capabilities
func (tm *BCCTraceManager) GetCapabilities() map[string]bool {
	tm.tracesLock.RLock()
	defer tm.tracesLock.RUnlock()

	caps := make(map[string]bool)
	for k, v := range tm.capabilities {
		caps[k] = v
	}
	return caps
}

// StartTrace starts a new trace session based on the specification
func (tm *BCCTraceManager) StartTrace(spec TraceSpec) (string, error) {
	if !tm.capabilities["bpftrace"] {
		return "", fmt.Errorf("bpftrace not available - install bpftrace package")
	}

	if !tm.capabilities["root_access"] {
		return "", fmt.Errorf("root access required for eBPF tracing")
	}

	if !tm.capabilities["kernel_ebpf"] {
		return "", fmt.Errorf("kernel version does not support eBPF")
	}

	tm.tracesLock.Lock()
	defer tm.tracesLock.Unlock()

	// Generate trace ID
	tm.traceCounter++
	traceID := fmt.Sprintf("trace_%d", tm.traceCounter)

	var script string
	var err error

	// Check if this is a raw bpftrace script
	if spec.ProbeType == "bpftrace" {
		// Use the target as the raw bpftrace script
		script = spec.Target
		logging.Debug("Using raw bpftrace script for %s", traceID)
	} else {
		// Generate bpftrace script from spec
		script, err = tm.generateBpftraceScript(spec)
		if err != nil {
			return "", fmt.Errorf("failed to generate bpftrace script: %w", err)
		}
		logging.Debug("Generated bpftrace script for %s", spec.Target)
	}

	// Debug: log the script
	logging.Debug("Starting eBPF trace %s with script:\n%s", traceID, script)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(spec.Duration)*time.Second)

	// Start bpftrace process with --unsafe flag for better compatibility
	cmd := exec.CommandContext(ctx, "bpftrace", "-e", script, "--unsafe")

	// Create stdout pipe BEFORE starting
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Create stderr pipe to capture errors
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	trace := &RunningTrace{
		ID:        traceID,
		Spec:      spec,
		Process:   cmd,
		Events:    []TraceEvent{},
		StartTime: time.Now(),
		Cancel:    cancel,
		Context:   ctx,
		Done:      make(chan struct{}), // Initialize completion signal
	}

	// Start the trace
	if err := cmd.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("failed to start bpftrace: %w", err)
	}

	tm.traces[traceID] = trace

	// Monitor the trace in a goroutine
	go tm.monitorTrace(traceID, stdout, stderr)

	logging.Debug("Started BCC-style trace %s for target %s", traceID, spec.Target)
	return traceID, nil
} // generateBpftraceScript generates a bpftrace script based on the trace specification
func (tm *BCCTraceManager) generateBpftraceScript(spec TraceSpec) (string, error) {
	var script strings.Builder

	// Build probe specification
	var probe string
	switch spec.ProbeType {
	case "p", "": // kprobe (default)
		if strings.HasPrefix(spec.Target, "sys_") || strings.HasPrefix(spec.Target, "__x64_sys_") {
			probe = fmt.Sprintf("kprobe:%s", spec.Target)
		} else {
			probe = fmt.Sprintf("kprobe:%s", spec.Target)
		}
	case "r": // kretprobe
		if strings.HasPrefix(spec.Target, "sys_") || strings.HasPrefix(spec.Target, "__x64_sys_") {
			probe = fmt.Sprintf("kretprobe:%s", spec.Target)
		} else {
			probe = fmt.Sprintf("kretprobe:%s", spec.Target)
		}
	case "t": // tracepoint
		// If target already includes tracepoint prefix, use as-is
		if strings.HasPrefix(spec.Target, "tracepoint:") {
			probe = spec.Target
		} else {
			probe = fmt.Sprintf("tracepoint:%s", spec.Target)
		}
	case "u": // uprobe
		if spec.Library == "" {
			return "", fmt.Errorf("library required for uprobe")
		}
		probe = fmt.Sprintf("uprobe:%s:%s", spec.Library, spec.Target)
	default:
		return "", fmt.Errorf("unsupported probe type: %s", spec.ProbeType)
	}

	// Add BEGIN block
	script.WriteString("BEGIN {\n")
	fmt.Fprintf(&script, "  printf(\"Starting trace for %s...\\n\");\n", spec.Target)
	script.WriteString("}\n\n")

	// Build the main probe
	fmt.Fprintf(&script, "%s {\n", probe)

	// Add filters if specified
	if tm.needsFiltering(spec) {
		script.WriteString("  if (")
		filters := tm.buildFilters(spec)
		script.WriteString(strings.Join(filters, " && "))
		script.WriteString(") {\n")
	}

	// Build output format
	outputFormat := tm.buildOutputFormat(spec)
	fmt.Fprintf(&script, "    printf(\"%s\\n\"", outputFormat)

	// Add arguments
	args := tm.buildArgumentList(spec)
	if len(args) > 0 {
		script.WriteString(", ")
		script.WriteString(strings.Join(args, ", "))
	}

	script.WriteString(");\n")

	// Close filter if block
	if tm.needsFiltering(spec) {
		script.WriteString("  }\n")
	}

	script.WriteString("}\n\n")

	// Add END block
	script.WriteString("END {\n")
	fmt.Fprintf(&script, "  printf(\"Trace completed for %s\\n\");\n", spec.Target)
	script.WriteString("}\n")

	return script.String(), nil
}

// needsFiltering checks if any filters are needed
func (tm *BCCTraceManager) needsFiltering(spec TraceSpec) bool {
	return spec.PID != 0 || spec.TID != 0 || spec.UID != -1 ||
		spec.ProcessName != "" || spec.Filter != ""
}

// buildFilters builds the filter conditions
func (tm *BCCTraceManager) buildFilters(spec TraceSpec) []string {
	var filters []string

	if spec.PID != 0 {
		filters = append(filters, fmt.Sprintf("pid == %d", spec.PID))
	}

	if spec.TID != 0 {
		filters = append(filters, fmt.Sprintf("tid == %d", spec.TID))
	}

	if spec.UID != -1 {
		filters = append(filters, fmt.Sprintf("uid == %d", spec.UID))
	}

	if spec.ProcessName != "" {
		filters = append(filters, fmt.Sprintf("strncmp(comm, \"%s\", %d) == 0", spec.ProcessName, len(spec.ProcessName)))
	}

	// Add custom filter
	if spec.Filter != "" {
		// Convert common patterns to bpftrace syntax
		customFilter := strings.ReplaceAll(spec.Filter, "arg", "arg")
		filters = append(filters, customFilter)
	}

	return filters
}

// buildOutputFormat creates the output format string
func (tm *BCCTraceManager) buildOutputFormat(spec TraceSpec) string {
	if spec.Format != "" {
		// Use custom format
		return fmt.Sprintf("TRACE|%%d|%%d|%%d|%%s|%s|%s", spec.Target, spec.Format)
	}

	// Default format
	return fmt.Sprintf("TRACE|%%d|%%d|%%d|%%s|%s|called", spec.Target)
}

// buildArgumentList creates the argument list for printf
func (tm *BCCTraceManager) buildArgumentList(spec TraceSpec) []string {
	// Always include timestamp, pid, tid, comm
	args := []string{"nsecs", "pid", "tid", "comm"}

	// Add custom arguments
	for _, arg := range spec.Arguments {
		switch arg {
		case "arg1", "arg2", "arg3", "arg4", "arg5", "arg6":
			args = append(args, fmt.Sprintf("arg%s", strings.TrimPrefix(arg, "arg")))
		case "retval":
			args = append(args, "retval")
		case "cpu":
			args = append(args, "cpu")
		default:
			// Custom expression
			args = append(args, arg)
		}
	}

	return args
}

// monitorTrace monitors a running trace and collects events
func (tm *BCCTraceManager) monitorTrace(traceID string, stdout io.ReadCloser, stderr io.ReadCloser) {
	tm.tracesLock.Lock()
	trace, exists := tm.traces[traceID]
	if !exists {
		tm.tracesLock.Unlock()
		return
	}
	tm.tracesLock.Unlock()

	// Start reading stdout in a goroutine
	// For raw bpftrace scripts, capture all output as-is
	go func() {
		scanner := bufio.NewScanner(stdout)
		var outputLines []string

		for scanner.Scan() {
			line := scanner.Text()
			outputLines = append(outputLines, line)
		}

		if err := scanner.Err(); err != nil {
			logging.Warning("Trace %s scanner error: %v", traceID, err)
		}

		// Store all output as a single event with raw content
		if len(outputLines) > 0 {
			tm.tracesLock.Lock()
			if t, exists := tm.traces[traceID]; exists {
				// Create a single event with all the raw output
				event := TraceEvent{
					Timestamp:   time.Now().UnixNano(),
					PID:         0,
					TID:         0,
					ProcessName: "bpftrace",
					Function:    trace.Spec.Target,
					Message:     strings.Join(outputLines, "\n"),
					RawArgs:     make(map[string]string),
				}
				t.Events = append(t.Events, event)
				logging.Debug("Trace %s stored event with %d chars", traceID, len(event.Message))
			}
			tm.tracesLock.Unlock()
		}
		_ = stdout.Close()
	}()

	// Start reading stderr in a goroutine to capture errors
	var stderrBuf strings.Builder
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			stderrBuf.WriteString(line + "\n")
			// Log errors immediately for debugging
			if strings.Contains(line, "ERROR") || strings.Contains(line, "cannot attach") {
				logging.Warning("Trace %s bpftrace error: %s", traceID, line)
			}
		}
		_ = stderr.Close()
	}()

	// Wait for the process to complete
	err := trace.Process.Wait()

	// Clean up
	trace.Cancel()

	tm.tracesLock.Lock()
	// Check stderr output for errors
	stderrOutput := stderrBuf.String()
	if err != nil && err.Error() != "signal: killed" {
		if stderrOutput != "" {
			logging.Warning("Trace %s completed with error: %v, stderr: %s", traceID, err, stderrOutput)
		} else {
			logging.Warning("Trace %s completed with error: %v", traceID, err)
		}
	} else if stderrOutput != "" && (strings.Contains(stderrOutput, "ERROR") || strings.Contains(stderrOutput, "cannot attach")) {
		logging.Warning("Trace %s completed with stderr errors: %s", traceID, stderrOutput)
	} else {
		logging.Debug("Trace %s completed successfully with %d events",
			traceID, len(trace.Events))
	}

	// Signal that monitoring is complete
	close(trace.Done)
	tm.tracesLock.Unlock()
}

// GetTraceResult returns the results of a completed trace
func (tm *BCCTraceManager) GetTraceResult(traceID string) (*TraceResult, error) {
	tm.tracesLock.RLock()
	trace, exists := tm.traces[traceID]
	if !exists {
		tm.tracesLock.RUnlock()
		return nil, fmt.Errorf("trace %s not found", traceID)
	}
	tm.tracesLock.RUnlock()

	// Wait for trace monitoring to complete
	select {
	case <-trace.Done:
		// Trace monitoring completed
	case <-time.After(5 * time.Second):
		// Timeout waiting for completion
		return nil, fmt.Errorf("timeout waiting for trace %s to complete", traceID)
	}

	// Now safely read the final results
	tm.tracesLock.RLock()
	defer tm.tracesLock.RUnlock()

	result := &TraceResult{
		TraceID:    traceID,
		Spec:       trace.Spec,
		Events:     make([]TraceEvent, len(trace.Events)),
		EventCount: len(trace.Events),
		StartTime:  trace.StartTime,
		EndTime:    time.Now(),
	}

	copy(result.Events, trace.Events)

	// Calculate statistics
	result.Statistics = tm.calculateStatistics(result.Events, result.EndTime.Sub(result.StartTime))

	// Generate summary
	result.Summary = tm.generateSummary(result)

	return result, nil
}

// calculateStatistics calculates statistics for the trace results
func (tm *BCCTraceManager) calculateStatistics(events []TraceEvent, duration time.Duration) TraceStats {
	stats := TraceStats{
		TotalEvents:     len(events),
		EventsByProcess: make(map[string]int),
		EventsByUID:     make(map[int]int),
	}

	if duration > 0 {
		stats.EventsPerSecond = float64(len(events)) / duration.Seconds()
	}

	// Calculate per-process and per-UID statistics
	for _, event := range events {
		stats.EventsByProcess[event.ProcessName]++
		stats.EventsByUID[event.UID]++
	}

	// Calculate top processes
	for processName, count := range stats.EventsByProcess {
		percentage := float64(count) / float64(len(events)) * 100
		stats.TopProcesses = append(stats.TopProcesses, ProcessStat{
			ProcessName: processName,
			EventCount:  count,
			Percentage:  percentage,
		})
	}

	return stats
}

// generateSummary generates a human-readable summary
func (tm *BCCTraceManager) generateSummary(result *TraceResult) string {
	duration := result.EndTime.Sub(result.StartTime)

	summary := fmt.Sprintf("Traced %s for %v, captured %d events (%.2f events/sec)",
		result.Spec.Target, duration, result.EventCount, result.Statistics.EventsPerSecond)

	if len(result.Statistics.TopProcesses) > 0 {
		summary += fmt.Sprintf(", top process: %s (%d events)",
			result.Statistics.TopProcesses[0].ProcessName,
			result.Statistics.TopProcesses[0].EventCount)
	}

	return summary
}

// StopTrace stops an active trace
func (tm *BCCTraceManager) StopTrace(traceID string) error {
	tm.tracesLock.Lock()
	defer tm.tracesLock.Unlock()

	trace, exists := tm.traces[traceID]
	if !exists {
		return fmt.Errorf("trace %s not found", traceID)
	}

	if trace.Process.ProcessState == nil {
		// Process is still running, kill it
		if err := trace.Process.Process.Kill(); err != nil {
			return fmt.Errorf("failed to stop trace: %w", err)
		}
	}

	trace.Cancel()
	return nil
}

// ListActiveTraces returns a list of active trace IDs
func (tm *BCCTraceManager) ListActiveTraces() []string {
	tm.tracesLock.RLock()
	defer tm.tracesLock.RUnlock()

	var active []string
	for id, trace := range tm.traces {
		if trace.Process.ProcessState == nil {
			active = append(active, id)
		}
	}

	return active
}

// GetSummary returns a summary of the trace manager state
func (tm *BCCTraceManager) GetSummary() map[string]interface{} {
	tm.tracesLock.RLock()
	defer tm.tracesLock.RUnlock()

	activeCount := 0
	completedCount := 0

	for _, trace := range tm.traces {
		if trace.Process.ProcessState == nil {
			activeCount++
		} else {
			completedCount++
		}
	}

	return map[string]interface{}{
		"capabilities":     tm.capabilities,
		"active_traces":    activeCount,
		"completed_traces": completedCount,
		"total_traces":     len(tm.traces),
		"active_trace_ids": tm.ListActiveTraces(),
	}
}
