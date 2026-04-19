package config

import (
	"fmt"
	"os"

	"nannyagent/internal/logging"

	"gopkg.in/yaml.v3"
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

	// HTTP Transport Configuration - for tuning connection behavior
	// These help address HTTP/2 connection issues with long-running agents.
	// See docs/CONFIGURATION.md for details on when to adjust these.
	HTTPTransport HTTPTransportConfig `yaml:"http_transport"`

	// Debug/Development
	Debug bool `yaml:"debug"`
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
	TokenPath:       "/var/lib/nannyagent/token.json", // Default to system directory
	PortalURL:       "https://nannyai.dev",            // Default portal URL
	MetricsInterval: 30,
	ProxmoxInterval: 5 * 60, // Default to 300 seconds (5 minutes)
	Debug:           false,
	HTTPTransport:   DefaultHTTPTransportConfig,
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

	// Load from environment variables (highest priority - overrides file config)
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

	// Apply defaults for any zero-value HTTP transport settings
	// This ensures partial YAML configs work correctly
	config.HTTPTransport.ApplyDefaults()

	// Validate required configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// ApplyDefaults fills in zero values with defaults for HTTPTransportConfig.
// This allows users to specify only the settings they want to override.
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

// Validate checks if all required configuration is present
func (c *Config) Validate() error {
	if c.APIBaseURL == "" {
		return fmt.Errorf("missing required configuration: NANNYAPI_URL (for NannyAPI) must be set")
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
	logging.Debug("  Debug: %v", c.Debug)
}
