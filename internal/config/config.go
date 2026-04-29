package config

import (
	"flag"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"

	"nannyagent/internal/logging"

	"gopkg.in/yaml.v3"
)

// Validation limits — protect against typos, overflow, and unreasonable values.
const (
	// Interval bounds (seconds)
	MinInterval = 5         // 5 seconds
	MaxInterval = 7 * 86400 // 7 days in seconds (604 800)

	// Token renewal bounds
	MaxRenewalThresholdDays = 365        // 1 year
	MaxRenewalIntervalSecs  = 30 * 86400 // 30 days in seconds

	// HTTP transport bounds
	MaxIdleConns            = 1000
	MaxIdleConnTimeoutSec   = 3600  // 1 hour
	MaxResponseHeaderSec    = 300   // 5 minutes
	MaxRetryDelay           = 86400 // 1 day
	MaxTransportResetThresh = 100

	// String length limits
	MaxURLLength       = 2048
	MaxTokenPathLength = 4096
	MaxStaticTokenLen  = 512
	MinStaticTokenLen  = 5 // "nsk_" + at least 1 char
	MaxAgentIDLength   = 256
)

type Config struct {
	// NannyAPI Configuration (primary)
	APIBaseURL string `yaml:"nannyapi_url"`

	// Portal URL for device authorization
	PortalURL string `yaml:"portal_url"`

	// Agent Configuration
	TokenPath       string `yaml:"token_path"`
	MetricsInterval int    `yaml:"metrics_interval"`
	ProxmoxInterval int    `yaml:"proxmox_interval"`

	// Static Token Authentication (alternative to OAuth2)
	// When set, bypasses the OAuth2 device flow entirely.
	// The token must be a valid NannyAPI static token (prefixed with nsk_).
	StaticToken string `yaml:"static_token"`

	// Agent ID (required when using static token, auto-populated after registration)
	AgentID string `yaml:"agent_id"`

	// HTTP Transport Configuration - for tuning connection behavior
	// These help address HTTP/2 connection issues with long-running agents.
	// See docs/CONFIGURATION.md for details on when to adjust these.
	HTTPTransport HTTPTransportConfig `yaml:"http_transport"`

	// Token renewal: start renewing when refresh token has fewer than this many days left.
	// If renewal fails, the agent retries every TokenRenewalRetryIntervalSecs seconds.
	TokenRenewalThresholdDays     int `yaml:"token_renewal_threshold_days"`
	TokenRenewalCheckIntervalSecs int `yaml:"token_renewal_check_interval_secs"`
	TokenRenewalRetryIntervalSecs int `yaml:"token_renewal_retry_interval_secs"`

	// Debug/Development
	Debug bool `yaml:"debug"`
}

// CLIFlags holds all command-line flag values for merging into Config.
type CLIFlags struct {
	// Commands
	Register bool
	Status   bool
	Diagnose string
	Daemon   bool
	Version  bool
	Help     bool

	// Config overrides (nil/empty means not set)
	APIBaseURL      string
	PortalURL       string
	TokenPath       string
	MetricsInterval int
	ProxmoxInterval int
	AgentID         string
	Debug           bool
	DebugSet        bool // tracks whether --debug was explicitly passed
}

// ParseCLIFlags parses command-line arguments and returns structured flags.
// CLI arguments have the highest priority and override YAML and env config.
func ParseCLIFlags() *CLIFlags {
	f := &CLIFlags{}

	flag.BoolVar(&f.Register, "register", false, "Register agent with NannyAI")
	flag.BoolVar(&f.Status, "status", false, "Show agent status")
	flag.StringVar(&f.Diagnose, "diagnose", "", "Run one-off diagnosis (e.g., --diagnose \"postgresql is slow\")")
	flag.BoolVar(&f.Daemon, "daemon", false, "Run as daemon (systemd)")
	flag.BoolVar(&f.Version, "version", false, "Show version")
	flag.BoolVar(&f.Help, "help", false, "Show help")

	flag.StringVar(&f.APIBaseURL, "api-url", "", "NannyAPI endpoint URL (overrides config)")
	flag.StringVar(&f.PortalURL, "portal-url", "", "Portal URL for device authorization")
	flag.StringVar(&f.TokenPath, "token-path", "", "Token storage path")
	flag.IntVar(&f.MetricsInterval, "metrics-interval", 0, "Metrics collection interval in seconds")
	flag.IntVar(&f.ProxmoxInterval, "proxmox-interval", 0, "Proxmox data collection interval in seconds")
	flag.StringVar(&f.AgentID, "agent-id", "", "Agent ID (for static token registration)")
	flag.BoolVar(&f.Debug, "debug", false, "Enable debug mode")

	flag.Parse()

	// Track whether --debug was explicitly set
	flag.Visit(func(fl *flag.Flag) {
		if fl.Name == "debug" {
			f.DebugSet = true
		}
	})

	return f
}

// ApplyCLIFlags merges CLI flag values into the config. CLI flags have the
// highest priority and override both YAML and environment variable settings.
// Note: static_token is intentionally NOT exposed as a CLI flag for security
// (it would be visible in the process list). Use config.yaml or env var only.
func (c *Config) ApplyCLIFlags(f *CLIFlags) {
	if f.APIBaseURL != "" {
		c.APIBaseURL = f.APIBaseURL
	}
	if f.PortalURL != "" {
		c.PortalURL = f.PortalURL
	}
	if f.TokenPath != "" {
		c.TokenPath = f.TokenPath
	}
	if f.MetricsInterval > 0 {
		c.MetricsInterval = f.MetricsInterval
	}
	if f.ProxmoxInterval > 0 {
		c.ProxmoxInterval = f.ProxmoxInterval
	}
	if f.AgentID != "" {
		c.AgentID = f.AgentID
	}
	if f.DebugSet {
		c.Debug = f.Debug
	}
}

// UseStaticToken returns true if a static token is configured.
func (c *Config) UseStaticToken() bool {
	return c.StaticToken != "" && strings.HasPrefix(c.StaticToken, "nsk_")
}

// HTTPTransportConfig contains settings for the HTTP client transport.
// These settings help prevent stale connection issues that occur when:
// - The API server restarts
// - Network disruptions cause connection state mismatch
// - Cloudflare or reverse proxies close idle connections
type HTTPTransportConfig struct {
	// MaxIdleConns is the maximum number of idle connections across all hosts.
	// Lower values reduce memory usage but may cause more connection churn.
	// Default: 10
	MaxIdleConns int `yaml:"max_idle_conns"`

	// MaxIdleConnsPerHost is the maximum idle connections per host.
	// Default: 5
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`

	// IdleConnTimeout is how long an idle connection stays in the pool (seconds).
	// Set lower than the server/proxy's idle timeout to prevent stale connections.
	// Default: 30
	IdleConnTimeoutSec int `yaml:"idle_conn_timeout_sec"`

	// ResponseHeaderTimeout is max time waiting for response headers (seconds).
	// Helps detect dead connections faster. Default: 30
	ResponseHeaderTimeoutSec int `yaml:"response_header_timeout_sec"`

	// DisableHTTP2 forces HTTP/1.1 which uses separate connections per request.
	// This avoids HTTP/2 multiplexing issues at the cost of efficiency.
	// Only enable if HTTP/2 issues persist despite other tuning. Default: false
	DisableHTTP2 bool `yaml:"disable_http2"`

	// TransportResetThreshold is how many consecutive connection errors
	// trigger a full HTTP transport reset (creating fresh connections).
	// This is a RECOVERY mechanism, not a give-up mechanism.
	// The agent will NEVER stop trying - it just creates new connections to recover.
	// Default: 3
	TransportResetThreshold int `yaml:"transport_reset_threshold"`

	// InitialRetryDelaySec is the initial delay between retries on connection errors (seconds).
	// Used as the base for exponential backoff.
	// Default: 30
	InitialRetryDelaySec int `yaml:"initial_retry_delay_sec"`

	// MaxRetryDelaySec is the maximum delay between retries (seconds).
	// Exponential backoff will cap at this value.
	// The agent will NEVER give up, just waits longer between attempts.
	// Default: 1800 (30 minutes)
	MaxRetryDelaySec int `yaml:"max_retry_delay_sec"`
}

var DefaultConfig = Config{
	TokenPath:                     "/var/lib/nannyagent/token.json", // Default to system directory
	PortalURL:                     "https://nannyai.dev",            // Default portal URL
	MetricsInterval:               30,
	ProxmoxInterval:               5 * 60, // Default to 300 seconds (5 minutes)
	TokenRenewalThresholdDays:     7,      // Renew refresh token when < 7 days remain
	TokenRenewalCheckIntervalSecs: 21600,  // Check every 6 hours (21600s) normally
	TokenRenewalRetryIntervalSecs: 3600,   // Retry every 1 hour (3600s) if renewal failed
	Debug:                         false,
	HTTPTransport:                 DefaultHTTPTransportConfig,
}

// DefaultHTTPTransportConfig provides sensible defaults for HTTP transport.
// These are tuned for typical cloud environments (Cloudflare, AWS ALB, etc.)
// that often close idle connections after 60-120 seconds.
var DefaultHTTPTransportConfig = HTTPTransportConfig{
	MaxIdleConns:             10,
	MaxIdleConnsPerHost:      5,
	IdleConnTimeoutSec:       30, // Keep lower than server/proxy idle timeout
	ResponseHeaderTimeoutSec: 30,
	DisableHTTP2:             false,
	TransportResetThreshold:  3,    // Reset transport after 3 consecutive errors (recovery, not give-up)
	InitialRetryDelaySec:     30,   // Start retries at 30s
	MaxRetryDelaySec:         1800, // Max backoff 30 minutes, agent NEVER stops trying
}

// LoadConfig loads configuration from YAML or environment variables
func LoadConfig() (*Config, error) {
	config := DefaultConfig

	// Priority order for loading configuration:
	// 1. /etc/nannyagent/config.yaml (system-wide YAML)
	// 2. Environment variables (highest priority overrides)

	configLoaded := false

	// Try system-wide YAML config first
	if err := loadYAMLConfig(&config, "/etc/nannyagent/config.yaml"); err == nil {
		logging.Info("Loaded configuration from /etc/nannyagent/config.yaml")
		configLoaded = true
	}

	if !configLoaded {
		logging.Warning("No configuration file found at /etc/nannyagent/config.yaml. Using environment variables only.")
	}

	// Load from environment variables (overrides file config, but CLI overrides env)
	// NannyAPI configuration (primary)
	if url := os.Getenv("NANNYAPI_URL"); url != "" {
		config.APIBaseURL = url
	}

	if tokenPath := os.Getenv("TOKEN_PATH"); tokenPath != "" {
		config.TokenPath = tokenPath
	}

	if portalURL := os.Getenv("NANNYAI_PORTAL_URL"); portalURL != "" {
		config.PortalURL = portalURL
	}

	if debug := os.Getenv("DEBUG"); debug == "true" || debug == "1" {
		config.Debug = true
	}

	// Static token from environment variable (e.g. from .env or shell)
	if staticToken := os.Getenv("NANNYAI_STATIC_TOKEN"); staticToken != "" {
		config.StaticToken = staticToken
	}

	// Agent ID from environment variable
	if agentID := os.Getenv("NANNYAI_AGENT_ID"); agentID != "" {
		config.AgentID = agentID
	}

	// Apply defaults for any zero-value HTTP transport settings
	// This ensures partial YAML configs work correctly
	config.HTTPTransport.ApplyDefaults()

	// Apply defaults for token renewal settings
	config.ApplyTokenRenewalDefaults()

	// Validate required configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// ApplyDefaults fills in zero values with defaults for HTTPTransportConfig.
// This allows users to specify only the settings they want to override in YAML.
// Convention: a zero value means "use default". To explicitly disable a timeout,
// set it to -1 (which will be caught by ValidateHTTPTransport if not allowed).
func (h *HTTPTransportConfig) ApplyDefaults() {
	if h.MaxIdleConns == 0 {
		h.MaxIdleConns = DefaultHTTPTransportConfig.MaxIdleConns
	}
	if h.MaxIdleConnsPerHost == 0 {
		h.MaxIdleConnsPerHost = DefaultHTTPTransportConfig.MaxIdleConnsPerHost
	}
	if h.IdleConnTimeoutSec == 0 {
		h.IdleConnTimeoutSec = DefaultHTTPTransportConfig.IdleConnTimeoutSec
	}
	if h.ResponseHeaderTimeoutSec == 0 {
		h.ResponseHeaderTimeoutSec = DefaultHTTPTransportConfig.ResponseHeaderTimeoutSec
	}
	if h.TransportResetThreshold == 0 {
		h.TransportResetThreshold = DefaultHTTPTransportConfig.TransportResetThreshold
	}
	if h.InitialRetryDelaySec == 0 {
		h.InitialRetryDelaySec = DefaultHTTPTransportConfig.InitialRetryDelaySec
	}
	if h.MaxRetryDelaySec == 0 {
		h.MaxRetryDelaySec = DefaultHTTPTransportConfig.MaxRetryDelaySec
	}
	// DisableHTTP2 is intentionally not defaulted - false is a valid explicit setting
}

// ApplyTokenRenewalDefaults fills in zero values for token renewal settings with their defaults.
func (c *Config) ApplyTokenRenewalDefaults() {
	if c.TokenRenewalThresholdDays <= 0 {
		c.TokenRenewalThresholdDays = DefaultConfig.TokenRenewalThresholdDays
	}
	if c.TokenRenewalCheckIntervalSecs <= 0 {
		c.TokenRenewalCheckIntervalSecs = DefaultConfig.TokenRenewalCheckIntervalSecs
	}
	if c.TokenRenewalRetryIntervalSecs <= 0 {
		c.TokenRenewalRetryIntervalSecs = DefaultConfig.TokenRenewalRetryIntervalSecs
	}
}

// validateTokenRenewal checks token renewal config fields are sane.
func (c *Config) validateTokenRenewal() error {
	if c.TokenRenewalThresholdDays <= 0 {
		return fmt.Errorf("token_renewal_threshold_days must be > 0 (got %d)", c.TokenRenewalThresholdDays)
	}
	if c.TokenRenewalThresholdDays > MaxRenewalThresholdDays {
		return fmt.Errorf("token_renewal_threshold_days must be <= %d (got %d)", MaxRenewalThresholdDays, c.TokenRenewalThresholdDays)
	}
	if c.TokenRenewalCheckIntervalSecs <= 0 {
		return fmt.Errorf("token_renewal_check_interval_secs must be > 0 (got %d)", c.TokenRenewalCheckIntervalSecs)
	}
	if c.TokenRenewalCheckIntervalSecs > MaxRenewalIntervalSecs {
		return fmt.Errorf("token_renewal_check_interval_secs must be <= %d (got %d)", MaxRenewalIntervalSecs, c.TokenRenewalCheckIntervalSecs)
	}
	if c.TokenRenewalRetryIntervalSecs <= 0 {
		return fmt.Errorf("token_renewal_retry_interval_secs must be > 0 (got %d)", c.TokenRenewalRetryIntervalSecs)
	}
	if c.TokenRenewalRetryIntervalSecs > MaxRenewalIntervalSecs {
		return fmt.Errorf("token_renewal_retry_interval_secs must be <= %d (got %d)", MaxRenewalIntervalSecs, c.TokenRenewalRetryIntervalSecs)
	}
	return nil
}

// loadYAMLConfig loads configuration from a YAML file
func loadYAMLConfig(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return nil
}

// Validate checks if all required configuration is present and all values are
// within acceptable bounds.  This is called after YAML + env loading, and again
// after CLI flags are merged (via ValidateAfterMerge).
func (c *Config) Validate() error {
	// ── Required fields ──────────────────────────────────────────────────
	if c.APIBaseURL == "" {
		return fmt.Errorf("missing required configuration: NANNYAPI_URL (for NannyAPI) must be set")
	}

	// ── URL validation ───────────────────────────────────────────────────
	if err := validateURL(c.APIBaseURL, "nannyapi_url"); err != nil {
		return err
	}
	if c.PortalURL != "" {
		if err := validateURL(c.PortalURL, "portal_url"); err != nil {
			return err
		}
	}

	// ── Token path ──────────────────────────────────────────────────────
	if c.TokenPath != "" {
		if len(c.TokenPath) > MaxTokenPathLength {
			return fmt.Errorf("token_path is too long (%d chars, max %d)", len(c.TokenPath), MaxTokenPathLength)
		}
		if !strings.HasPrefix(c.TokenPath, "/") {
			return fmt.Errorf("token_path must be an absolute path (got %q)", c.TokenPath)
		}
	}

	// ── Static token ────────────────────────────────────────────────────
	if c.StaticToken != "" {
		if !strings.HasPrefix(c.StaticToken, "nsk_") {
			return fmt.Errorf("static_token must start with 'nsk_' prefix")
		}
		if len(c.StaticToken) < MinStaticTokenLen {
			return fmt.Errorf("static_token is too short (must be at least %d characters)", MinStaticTokenLen)
		}
		if len(c.StaticToken) > MaxStaticTokenLen {
			return fmt.Errorf("static_token is too long (%d chars, max %d)", len(c.StaticToken), MaxStaticTokenLen)
		}
	}

	// ── Agent ID ────────────────────────────────────────────────────────
	if c.AgentID != "" {
		if len(c.AgentID) > MaxAgentIDLength {
			return fmt.Errorf("agent_id is too long (%d chars, max %d)", len(c.AgentID), MaxAgentIDLength)
		}
		if strings.TrimSpace(c.AgentID) == "" {
			return fmt.Errorf("agent_id must not be blank/whitespace-only")
		}
	}

	// ── Intervals ───────────────────────────────────────────────────────
	if err := validateInterval(c.MetricsInterval, "metrics_interval"); err != nil {
		return err
	}
	if err := validateInterval(c.ProxmoxInterval, "proxmox_interval"); err != nil {
		return err
	}

	// ── Subsystem validations ───────────────────────────────────────────
	if err := c.HTTPTransport.Validate(); err != nil {
		return err
	}

	if err := c.validateTokenRenewal(); err != nil {
		return err
	}

	return nil
}

// ValidateAfterMerge should be called after ApplyCLIFlags to re-validate the
// final merged configuration.  It is a convenience wrapper around Validate().
func (c *Config) ValidateAfterMerge() error {
	return c.Validate()
}

// validateURL checks that a URL string is well-formed and uses http or https.
func validateURL(raw, field string) error {
	if len(raw) > MaxURLLength {
		return fmt.Errorf("%s is too long (%d chars, max %d)", field, len(raw), MaxURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must use http or https scheme (got %q)", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s is missing a host", field)
	}
	return nil
}

// validateInterval checks that a collection interval is within [MinInterval, MaxInterval].
func validateInterval(value int, field string) error {
	if value <= 0 {
		return fmt.Errorf("%s must be > 0 (got %d)", field, value)
	}
	if value < MinInterval {
		return fmt.Errorf("%s must be >= %d seconds (got %d)", field, MinInterval, value)
	}
	if value > MaxInterval {
		return fmt.Errorf("%s must be <= %d seconds (got %d)", field, MaxInterval, value)
	}
	return nil
}

// Validate checks that HTTPTransportConfig values are sensible and not internally inconsistent.
func (h *HTTPTransportConfig) Validate() error {
	if h.InitialRetryDelaySec <= 0 {
		return fmt.Errorf("http_transport.initial_retry_delay_sec must be > 0 (got %d)", h.InitialRetryDelaySec)
	}
	if h.InitialRetryDelaySec > MaxRetryDelay {
		return fmt.Errorf("http_transport.initial_retry_delay_sec must be <= %d (got %d)", MaxRetryDelay, h.InitialRetryDelaySec)
	}
	if h.MaxRetryDelaySec <= 0 {
		return fmt.Errorf("http_transport.max_retry_delay_sec must be > 0 (got %d)", h.MaxRetryDelaySec)
	}
	if h.MaxRetryDelaySec > MaxRetryDelay {
		return fmt.Errorf("http_transport.max_retry_delay_sec must be <= %d (got %d)", MaxRetryDelay, h.MaxRetryDelaySec)
	}
	if h.MaxRetryDelaySec < h.InitialRetryDelaySec {
		return fmt.Errorf("http_transport.max_retry_delay_sec (%d) must be >= initial_retry_delay_sec (%d)", h.MaxRetryDelaySec, h.InitialRetryDelaySec)
	}
	if h.TransportResetThreshold < 1 {
		return fmt.Errorf("http_transport.transport_reset_threshold must be >= 1 (got %d)", h.TransportResetThreshold)
	}
	if h.TransportResetThreshold > MaxTransportResetThresh {
		return fmt.Errorf("http_transport.transport_reset_threshold must be <= %d (got %d)", MaxTransportResetThresh, h.TransportResetThreshold)
	}
	if h.IdleConnTimeoutSec < 0 {
		return fmt.Errorf("http_transport.idle_conn_timeout_sec must be >= 0 (got %d)", h.IdleConnTimeoutSec)
	}
	if h.IdleConnTimeoutSec > MaxIdleConnTimeoutSec {
		return fmt.Errorf("http_transport.idle_conn_timeout_sec must be <= %d (got %d)", MaxIdleConnTimeoutSec, h.IdleConnTimeoutSec)
	}
	if h.ResponseHeaderTimeoutSec < 0 {
		return fmt.Errorf("http_transport.response_header_timeout_sec must be >= 0 (got %d)", h.ResponseHeaderTimeoutSec)
	}
	if h.ResponseHeaderTimeoutSec > MaxResponseHeaderSec {
		return fmt.Errorf("http_transport.response_header_timeout_sec must be <= %d (got %d)", MaxResponseHeaderSec, h.ResponseHeaderTimeoutSec)
	}
	if h.MaxIdleConns < 0 {
		return fmt.Errorf("http_transport.max_idle_conns must be >= 0 (got %d)", h.MaxIdleConns)
	}
	if h.MaxIdleConns > MaxIdleConns {
		return fmt.Errorf("http_transport.max_idle_conns must be <= %d (got %d)", MaxIdleConns, h.MaxIdleConns)
	}
	if h.MaxIdleConnsPerHost < 0 {
		return fmt.Errorf("http_transport.max_idle_conns_per_host must be >= 0 (got %d)", h.MaxIdleConnsPerHost)
	}
	if h.MaxIdleConnsPerHost > MaxIdleConns {
		return fmt.Errorf("http_transport.max_idle_conns_per_host must be <= %d (got %d)", MaxIdleConns, h.MaxIdleConnsPerHost)
	}
	// Consistency: per-host should not exceed total
	if h.MaxIdleConns > 0 && h.MaxIdleConnsPerHost > h.MaxIdleConns {
		return fmt.Errorf("http_transport.max_idle_conns_per_host (%d) must be <= max_idle_conns (%d)", h.MaxIdleConnsPerHost, h.MaxIdleConns)
	}
	// Guard against integer overflow when values are used in time.Duration multiplication
	if h.MaxRetryDelaySec > math.MaxInt64/int(1e9) {
		return fmt.Errorf("http_transport.max_retry_delay_sec would overflow time.Duration")
	}
	return nil
}

// findEnvFile is removed as we no longer support .env files
func findEnvFile() string {
	return ""
}

// PrintConfig prints the current configuration (masking sensitive values)
func (c *Config) PrintConfig() {
	if !c.Debug {
		return
	}

	logging.Debug("Configuration:")
	logging.Debug("  API Base URL: %s", c.APIBaseURL)
	logging.Debug("  Metrics Interval: %d seconds", c.MetricsInterval)
	if c.UseStaticToken() {
		logging.Debug("  Auth Mode: static token (nsk_***)")
		if c.AgentID != "" {
			logging.Debug("  Agent ID: %s", c.AgentID)
		}
	} else {
		logging.Debug("  Auth Mode: OAuth2 device flow")
	}
	logging.Debug("  Debug: %v", c.Debug)
}

// SaveAgentID writes the agent_id field back to /etc/nannyagent/config.yaml.
// This is used after static-token registration to persist the assigned agent ID.
func (c *Config) SaveAgentID(agentID string) error {
	c.AgentID = agentID

	configPath := "/etc/nannyagent/config.yaml"

	// Read existing file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	content := string(data)

	// Check if agent_id line already exists
	if strings.Contains(content, "agent_id:") {
		// Replace existing agent_id line
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "agent_id:") || strings.HasPrefix(trimmed, "# agent_id:") {
				lines[i] = fmt.Sprintf("agent_id: \"%s\"", agentID)
				break
			}
		}
		content = strings.Join(lines, "\n")
	} else {
		// Append agent_id
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += fmt.Sprintf("\nagent_id: \"%s\"\n", agentID)
	}

	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
