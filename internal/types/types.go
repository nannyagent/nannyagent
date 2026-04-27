package types

import (
	"time"

	"nannyagent/internal/ebpf"
)

// ChatMessage represents a message in the conversation
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

const (
	ChatMessageRoleSystem    = "system"
	ChatMessageRoleUser      = "user"
	ChatMessageRoleAssistant = "assistant"
)

// SystemMetrics represents comprehensive system performance metrics
type SystemMetrics struct {
	// System Information
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	PlatformFamily  string `json:"platform_family"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	KernelArch      string `json:"kernel_arch"`
	OSType          string `json:"os"`

	// CPU Metrics
	CPUUsage float64 `json:"cpu_usage"`
	CPUCores int     `json:"cpu_cores"`
	CPUModel string  `json:"cpu_model"`

	// Memory Metrics
	MemoryUsage     float64 `json:"memory_usage"`
	MemoryTotal     uint64  `json:"memory_total"`
	MemoryUsed      uint64  `json:"memory_used"`
	MemoryFree      uint64  `json:"memory_free"`
	MemoryAvailable uint64  `json:"memory_available"`
	SwapTotal       uint64  `json:"swap_total"`
	SwapUsed        uint64  `json:"swap_used"`
	SwapFree        uint64  `json:"swap_free"`

	// Disk Metrics
	DiskUsage float64 `json:"disk_usage"`
	DiskTotal uint64  `json:"disk_total"`
	DiskUsed  uint64  `json:"disk_used"`
	DiskFree  uint64  `json:"disk_free"`

	// Network Metrics
	NetworkInGb  float64 `json:"network_in_gb"`
	NetworkOutGb float64 `json:"network_out_gb"`

	// System Load
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	LoadAvg15 float64 `json:"load_avg_15"`

	// Process Information
	ProcessCount int `json:"process_count"`

	// Network Information
	IPAddress string   `json:"ip_address"`
	AllIPs    []string `json:"all_ips"`
	Location  string   `json:"location"`

	// Filesystem Information
	FilesystemInfo []FilesystemInfo `json:"filesystem_info"`
	BlockDevices   []BlockDevice    `json:"block_devices"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// FilesystemInfo represents filesystem information
type FilesystemInfo struct {
	Device       string  `json:"device"`
	Mountpoint   string  `json:"mountpoint"`
	Type         string  `json:"type"`
	Fstype       string  `json:"fstype"`
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Free         uint64  `json:"free"`
	Usage        float64 `json:"usage"`
	UsagePercent float64 `json:"usage_percent"`
}

// BlockDevice represents a block device
type BlockDevice struct {
	Name         string `json:"name"`
	Size         uint64 `json:"size"`
	Type         string `json:"type"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number"`
}

// NetworkStatsInterface represents network interface statistics (deprecated - use NetworkStats for NannyAPI)
type NetworkStatsInterface struct {
	Interface   string `json:"interface"`
	BytesRecv   uint64 `json:"bytes_recv"`
	BytesSent   uint64 `json:"bytes_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	ErrorsIn    uint64 `json:"errors_in"`
	ErrorsOut   uint64 `json:"errors_out"`
	DropsIn     uint64 `json:"drops_in"`
	DropsOut    uint64 `json:"drops_out"`
}

// AuthToken represents an authentication token
type AuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	AgentID      string    `json:"agent_id"`
}

// AgentStatus represents the current status of an agent
type AgentStatus string

const (
	AgentStatusActive   AgentStatus = "active"
	AgentStatusInactive AgentStatus = "inactive"
	AgentStatusRevoked  AgentStatus = "revoked"
)

// AgentHealthStatus represents health check status
type AgentHealthStatus string

const (
	HealthStatusHealthy  AgentHealthStatus = "healthy"
	HealthStatusStale    AgentHealthStatus = "stale"
	HealthStatusInactive AgentHealthStatus = "inactive"
)

// DeviceAuthRequest - anonymous device auth start
type DeviceAuthRequest struct {
	Action string `json:"action"` // "device-auth-start"
}

// DeviceAuthResponse - response with device & user codes (NannyAPI format)
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"` // seconds
}

// AuthorizeRequest - user authorizes device code
type AuthorizeRequest struct {
	Action   string `json:"action"`    // "authorize"
	UserCode string `json:"user_code"` // 8-char code
}

// AuthorizeResponse - confirmation of authorization
type AuthorizeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RegisterRequest - agent registers with device code
type RegisterRequest struct {
	Action         string   `json:"action"`          // "register"
	DeviceCode     string   `json:"device_code"`     // UUID from device-auth-start
	Hostname       string   `json:"hostname"`        // Agent hostname
	Platform       string   `json:"platform"`        // OS platform
	PlatformFamily string   `json:"platform_family"` // OS family (debian, redhat, etc)
	Version        string   `json:"version"`         // Agent version
	PrimaryIP      string   `json:"primary_ip"`      // Primary IP address (WAN/eth0)
	KernelVersion  string   `json:"kernel_version"`  // Kernel version
	AllIPs         []string `json:"all_ips"`         // All IP addresses from all NICs
	OSType         string   `json:"os_type"`         // OS type (linux)
}

// TokenResponse represents the token response (compatible with both old and new)
type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`
	AgentID               string `json:"agent_id,omitempty"`
	Error                 string `json:"error,omitempty"`
	ErrorDescription      string `json:"error_description,omitempty"`
}

// TokenRequest represents the token request for device flow
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	DeviceCode   string `json:"device_code,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
}

// RefreshRequest - refresh access token
type RefreshRequest struct {
	Action       string `json:"action"`        // "refresh"
	RefreshToken string `json:"refresh_token"` // Current refresh token
}

// NetworkStats contains network metrics in GB
type NetworkStats struct {
	InGB  float64 `json:"in_gb"`
	OutGB float64 `json:"out_gb"`
}

// FilesystemStats contains filesystem information
type FilesystemStats struct {
	Device       string  `json:"device"`     // e.g., "/dev/sda1"
	MountPath    string  `json:"mount_path"` // e.g., "/"
	UsedGB       float64 `json:"used_gb"`
	FreeGB       float64 `json:"free_gb"`
	TotalGB      float64 `json:"total_gb"`
	UsagePercent float64 `json:"usage_percent"` // Used / Total * 100
}

// LoadAverage contains load average metrics
type LoadAverage struct {
	OneMin     float64 `json:"one_min"`     // 1 minute load average
	FiveMin    float64 `json:"five_min"`    // 5 minute load average
	FifteenMin float64 `json:"fifteen_min"` // 15 minute load average
}

// NannyAgentSystemMetrics contains all system metrics for NannyAPI
type NannyAgentSystemMetrics struct {
	CPUPercent       float64           `json:"cpu_percent"`
	CPUCores         int               `json:"cpu_cores"`
	MemoryUsedGB     float64           `json:"memory_used_gb"`
	MemoryTotalGB    float64           `json:"memory_total_gb"`
	MemoryPercent    float64           `json:"memory_percent"` // Computed: used/total*100
	DiskUsedGB       float64           `json:"disk_used_gb"`
	DiskTotalGB      float64           `json:"disk_total_gb"`
	DiskUsagePercent float64           `json:"disk_usage_percent"` // Computed: used/total*100
	Filesystems      []FilesystemStats `json:"filesystems"`        // List of filesystems
	LoadAverage      LoadAverage       `json:"load_average"`
	NetworkStats     NetworkStats      `json:"network_stats"`
	KernelVersion    string            `json:"kernel_version"`
}

// IngestMetricsRequest - agent sends metrics to NannyAPI
type IngestMetricsRequest struct {
	Action        string                  `json:"action"`         // "ingest-metrics"
	SystemMetrics NannyAgentSystemMetrics `json:"system_metrics"` // System metrics (new format)

	// Agent metadata updates
	OSInfo         string   `json:"os_info,omitempty"`
	OSVersion      string   `json:"os_version,omitempty"`
	OSType         string   `json:"os_type,omitempty"`
	PlatformFamily string   `json:"platform_family,omitempty"` // Required for patch management
	Version        string   `json:"version,omitempty"`
	PrimaryIP      string   `json:"primary_ip,omitempty"`
	KernelVersion  string   `json:"kernel_version,omitempty"`
	Arch           string   `json:"arch,omitempty"`
	AllIPs         []string `json:"all_ips,omitempty"`
}

// IngestMetricsResponse - confirmation
type IngestMetricsResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ListAgentsRequest - list user's agents
type ListAgentsRequest struct {
	Action string `json:"action"` // "list"
}

// AgentListItem - single agent in list
type AgentListItem struct {
	ID            string            `json:"id"`
	Hostname      string            `json:"hostname"`
	Platform      string            `json:"platform"`
	Version       string            `json:"version"`
	Status        AgentStatus       `json:"status"`
	Health        AgentHealthStatus `json:"health"`
	LastSeen      *time.Time        `json:"last_seen"`
	Created       time.Time         `json:"created"`
	KernelVersion string            `json:"kernel_version"`
}

// ListAgentsResponse - list of agents
type ListAgentsResponse struct {
	Agents []AgentListItem `json:"agents"`
}

// RevokeAgentRequest - revoke agent access
type RevokeAgentRequest struct {
	Action  string `json:"action"`   // "revoke"
	AgentID string `json:"agent_id"` // Agent to revoke
}

// RevokeAgentResponse - confirmation
type RevokeAgentResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// HealthRequest - get agent health & latest metrics
type HealthRequest struct {
	Action  string `json:"action"`   // "health"
	AgentID string `json:"agent_id"` // Agent to check
}

// HealthResponse - agent health status with metrics
type HealthResponse struct {
	AgentID       string                   `json:"agent_id"`
	Status        AgentStatus              `json:"status"`
	Health        AgentHealthStatus        `json:"health"`
	LastSeen      *time.Time               `json:"last_seen"`
	LatestMetrics *NannyAgentSystemMetrics `json:"latest_metrics"` // nil if no metrics
}

// ErrorResponse - standard error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// HeartbeatRequest represents the agent heartbeat request
type HeartbeatRequest struct {
	AgentID string        `json:"agent_id"`
	Status  string        `json:"status"`
	Metrics SystemMetrics `json:"metrics"`
}

// MetricsRequest represents the flattened metrics payload expected by agent-auth-api
type MetricsRequest struct {
	// Agent identification
	AgentID string `json:"agent_id"`

	// Basic metrics
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`

	// Network metrics
	NetworkInGb  float64 `json:"network_in_gb"`
	NetworkOutGb float64 `json:"network_out_gb"`

	// System information
	Hostname          string `json:"hostname"`
	IPAddress         string `json:"ip_address"`
	Location          string `json:"location"`
	AgentVersion      string `json:"agent_version"`
	KernelVersion     string `json:"kernel_version"`
	DeviceFingerprint string `json:"device_fingerprint"`

	// Structured data (JSON fields in database)
	LoadAverages   map[string]float64 `json:"load_averages"`
	OSInfo         map[string]string  `json:"os_info"`
	FilesystemInfo []FilesystemInfo   `json:"filesystem_info"`
	BlockDevices   []BlockDevice      `json:"block_devices"`
}

// Agent types for TensorZero integration
type DiagnosticResponse struct {
	ResponseType string    `json:"response_type"`
	Reasoning    string    `json:"reasoning"`
	Commands     []Command `json:"commands"`
}

// ResolutionResponse represents a resolution response
type ResolutionResponse struct {
	ResponseType   string `json:"response_type"`
	RootCause      string `json:"root_cause"`
	ResolutionPlan string `json:"resolution_plan"`
	Confidence     string `json:"confidence"`
}

// Command represents a command to execute
type Command struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// CommandResult represents the result of an executed command
type CommandResult struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
	Output      string `json:"output"`
	ExitCode    int    `json:"exit_code"`
	Error       string `json:"error,omitempty"`
}

// EBPFRequest represents an eBPF trace request from external API
type EBPFRequest struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`              // "tracepoint", "kprobe", "kretprobe", "bpftrace"
	Target      string                 `json:"target"`            // tracepoint path, function name, or full bpftrace script
	Duration    int                    `json:"duration"`          // seconds
	Filters     map[string]interface{} `json:"filters,omitempty"` // Changed to interface{} for flexibility
	Description string                 `json:"description"`
}

// EBPFEnhancedDiagnosticResponse represents enhanced diagnostic response with eBPF
type EBPFEnhancedDiagnosticResponse struct {
	ResponseType string        `json:"response_type"`
	Reasoning    string        `json:"reasoning"`
	Commands     []string      `json:"commands"` // Changed to []string to match current prompt format
	EBPFPrograms []EBPFRequest `json:"ebpf_programs"`
	NextActions  []string      `json:"next_actions,omitempty"`
}

// TensorZeroRequest represents a request to TensorZero
type TensorZeroRequest struct {
	Model     string                   `json:"model"`
	Messages  []map[string]interface{} `json:"messages"`
	EpisodeID string                   `json:"tensorzero::episode_id,omitempty"`
}

// TensorZeroResponse represents a response from TensorZero
type TensorZeroResponse struct {
	Choices   []map[string]interface{} `json:"choices"`
	EpisodeID string                   `json:"episode_id"`
}

// SystemInfo represents system information (for compatibility)
type SystemInfo struct {
	Hostname      string              `json:"hostname"`
	Platform      string              `json:"platform"`
	PlatformInfo  map[string]string   `json:"platform_info"`
	KernelVersion string              `json:"kernel_version"`
	OSType        string              `json:"os_type"`
	Uptime        string              `json:"uptime"`
	LoadAverage   []float64           `json:"load_average"`
	CPUInfo       map[string]string   `json:"cpu_info"`
	MemoryInfo    map[string]string   `json:"memory_info"`
	DiskInfo      []map[string]string `json:"disk_info"`
}

// AgentConfig represents agent configuration
type AgentConfig struct {
	TensorZeroAPIKey string `json:"tensorzero_api_key"`
	APIURL           string `json:"api_url"`
	Timeout          int    `json:"timeout"`
	Debug            bool   `json:"debug"`
	MaxRetries       int    `json:"max_retries"`
	BackoffFactor    int    `json:"backoff_factor"`
	EpisodeID        string `json:"episode_id,omitempty"`
}

// PendingInvestigation represents a pending investigation from the database
type PendingInvestigation struct {
	ID                string                 `json:"id"`
	InvestigationID   string                 `json:"investigation_id"`
	AgentID           string                 `json:"agent_id"`
	DiagnosticPayload map[string]interface{} `json:"diagnostic_payload"`
	EpisodeID         *string                `json:"episode_id"`
	Status            string                 `json:"status"`
	CreatedAt         time.Time              `json:"created_at"`
}

// PatchTask represents a patch management task
type PatchTask struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// PatchExecution represents a patch execution task from the database
type PatchExecution struct {
	ID            string    `json:"id"`
	AgentID       string    `json:"agent_id"`
	ScriptID      *string   `json:"script_id"`
	ExecutionType string    `json:"execution_type"` // Allowed values: "dry_run", "apply". If a reboot is required after applying, set ShouldReboot to true.
	Status        string    `json:"status"`         // pending, executing, completed, failed
	Command       string    `json:"command"`
	ShouldReboot  bool      `json:"should_reboot"` // Indicates if a reboot should be performed after execution. Used in conjunction with ExecutionType="apply".
	CreatedAt     time.Time `json:"created_at"`
}

// DiagnosticAgent interface for agent functionality needed by other packages
type DiagnosticAgent interface {
	DiagnoseIssue(issue string) error
	DiagnoseIssueWithInvestigation(issue string) error
	GetEpisodeID() string
	SetInvestigationID(id string)
	GetInvestigationID() string
	// Exported method names to match what websocket client calls
	ConvertEBPFProgramsToTraceSpecs(ebpfRequests []EBPFRequest) []ebpf.TraceSpec
	ExecuteEBPFTraces(traceSpecs []ebpf.TraceSpec) []map[string]interface{}
	ExecuteCommand(cmd Command) CommandResult
}

// Investigation Status
type InvestigationStatus string

const (
	InvestigationStatusPending    InvestigationStatus = "pending"
	InvestigationStatusInProgress InvestigationStatus = "in_progress"
	InvestigationStatusCompleted  InvestigationStatus = "completed"
	InvestigationStatusFailed     InvestigationStatus = "failed"
)

// InvestigationRequest is sent by agent to initiate investigation
type InvestigationRequest struct {
	AgentID  string `json:"agent_id" validate:"required,uuid4"`
	Issue    string `json:"issue" validate:"required,min=10,max=2000"`
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high"` // Defaults to medium
}

// InvestigationResponse is returned when investigation is created or retrieved
type InvestigationResponse struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	AgentID        string                 `json:"agent_id"`
	EpisodeID      string                 `json:"episode_id"`
	UserPrompt     string                 `json:"user_prompt"`
	Priority       string                 `json:"priority"`
	Status         InvestigationStatus    `json:"status"`
	ResolutionPlan string                 `json:"resolution_plan"` // AI-generated resolution from TensorZero
	InitiatedAt    time.Time              `json:"initiated_at"`
	CompletedAt    *time.Time             `json:"completed_at"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Metadata       map[string]interface{} `json:"metadata"`
	InferenceCount int                    `json:"inference_count"` // Count from ClickHouse
}

// InvestigationUpdateRequest is used to update investigation status
type InvestigationUpdateRequest struct {
	Status         InvestigationStatus    `json:"status"`
	ResolutionPlan string                 `json:"resolution_plan,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	EpisodeID      string                 `json:"episode_id,omitempty"`
}

// Patch Management Types
// PatchMode represents patch operation mode
type PatchMode string

const (
	PatchModeDryRun PatchMode = "dry-run"
	PatchModeApply  PatchMode = "apply"
)

// PatchStatus represents patch operation lifecycle
type PatchStatus string

const (
	PatchStatusPending    PatchStatus = "pending"
	PatchStatusRunning    PatchStatus = "running"
	PatchStatusCompleted  PatchStatus = "completed"
	PatchStatusFailed     PatchStatus = "failed"
	PatchStatusRolledBack PatchStatus = "rolled_back"
)

// AgentPatchPayload is sent to agent via realtime for execution
type AgentPatchPayload struct {
	OperationID string `json:"operation_id"`
	Mode        string `json:"mode"` // dry-run or apply
	ScriptID    string `json:"script_id"`
	ScriptURL   string `json:"script_url"`
	ScriptArgs  string `json:"script_args"`
	LXCID       string `json:"lxc_id,omitempty"`
	VMID        string `json:"vmid,omitempty"`
	Timestamp   string `json:"timestamp"`
}

// AgentPatchResult is received from agent after execution
type AgentPatchResult struct {
	OperationID string             `json:"operation_id"`
	Success     bool               `json:"success"`
	OutputPath  string             `json:"output_path"` // Where agent stored output
	ErrorMsg    string             `json:"error_msg"`
	PackageList []PatchPackageInfo `json:"package_list"` // Packages that were changed
	Duration    int64              `json:"duration_ms"`
	LXCID       string             `json:"lxc_id,omitempty"`
	Timestamp   string             `json:"timestamp"`
}

// PatchPackageInfo represents package info from agent response
type PatchPackageInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	UpdateType string `json:"update_type"` // install, update, remove
	Details    string `json:"details"`
}

// Reboot Management Types

// RebootStatus represents reboot operation lifecycle
type RebootStatus string

const (
	RebootStatusPending   RebootStatus = "pending"
	RebootStatusSent      RebootStatus = "sent"
	RebootStatusRebooting RebootStatus = "rebooting"
	RebootStatusCompleted RebootStatus = "completed"
	RebootStatusFailed    RebootStatus = "failed"
	RebootStatusTimeout   RebootStatus = "timeout"
)

// AgentRebootPayload is sent to agent via realtime for execution
type AgentRebootPayload struct {
	RebootID       string `json:"reboot_id"`
	AgentID        string `json:"agent_id"`
	LXCID          string `json:"lxc_id,omitempty"`
	VMID           string `json:"vmid,omitempty"`
	Reason         string `json:"reason,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RequestedAt    string `json:"requested_at"`
}

// RebootHandler is a callback function that processes a reboot operation request
type RebootHandler func(payload AgentRebootPayload)
