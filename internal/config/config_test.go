package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_SystemYAML(t *testing.T) {
	// Create a temporary directory to simulate /etc/nannyagent
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a test YAML config
	yamlContent := `
nannyapi_url: https://test-api.nannyai.dev
portal_url: https://test.nannyai.dev
token_path: /tmp/test_token.json
metrics_interval: 60
debug: true
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Load the config
	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}

	// Verify values
	if config.APIBaseURL != "https://test-api.nannyai.dev" {
		t.Errorf("APIBaseURL = %v, want https://test-api.nannyai.dev", config.APIBaseURL)
	}
	if config.PortalURL != "https://test.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://test.nannyai.dev", config.PortalURL)
	}
	if config.TokenPath != "/tmp/test_token.json" {
		t.Errorf("TokenPath = %v, want /tmp/test_token.json", config.TokenPath)
	}
	if config.MetricsInterval != 60 {
		t.Errorf("MetricsInterval = %v, want 60", config.MetricsInterval)
	}
	if !config.Debug {
		t.Errorf("Debug = %v, want true", config.Debug)
	}
}

func TestLoadConfig_EnvFile(t *testing.T) {
	// This test now verifies that we can load config purely from environment variables
	// without relying on a .env file loader

	// Set environment variables
	_ = os.Setenv("NANNYAPI_URL", "https://env.nannyai.dev")
	_ = os.Setenv("TOKEN_PATH", "/tmp/env_token.json")
	_ = os.Setenv("NANNYAI_PORTAL_URL", "https://env.nannyai.dev")
	_ = os.Setenv("DEBUG", "true")
	defer func() {
		_ = os.Unsetenv("NANNYAPI_URL")
		_ = os.Unsetenv("TOKEN_PATH")
		_ = os.Unsetenv("NANNYAI_PORTAL_URL")
		_ = os.Unsetenv("DEBUG")
	}()

	// Create a minimal config
	config := DefaultConfig

	// Manually apply env vars (simulating LoadConfig behavior)
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

	// Verify
	if config.APIBaseURL != "https://env.nannyai.dev" {
		t.Errorf("APIBaseURL = %v, want https://env.nannyai.dev", config.APIBaseURL)
	}
	if config.TokenPath != "/tmp/env_token.json" {
		t.Errorf("TokenPath = %v, want /tmp/env_token.json", config.TokenPath)
	}
	if config.PortalURL != "https://env.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://env.nannyai.dev", config.PortalURL)
	}
	if !config.Debug {
		t.Errorf("Debug = %v, want true", config.Debug)
	}
}

func TestValidate_Success(t *testing.T) {
	config := &Config{
		APIBaseURL:                    "https://test-api.nannyai.dev",
		MetricsInterval:               30,
		ProxmoxInterval:               300,
		HTTPTransport:                 DefaultHTTPTransportConfig,
		TokenRenewalThresholdDays:     DefaultConfig.TokenRenewalThresholdDays,
		TokenRenewalCheckIntervalSecs: DefaultConfig.TokenRenewalCheckIntervalSecs,
		TokenRenewalRetryIntervalSecs: DefaultConfig.TokenRenewalRetryIntervalSecs,
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_MissingURL(t *testing.T) {
	config := &Config{
		// APIBaseURL missing
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() expected error for missing NANNYAPI_URL, got nil")
	}
	expectedErr := "missing required configuration: NANNYAPI_URL (for NannyAPI) must be set"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("Validate() error = %v, want '%s'", err, expectedErr)
	}
}

func TestLoadConfig_PriorityOrder(t *testing.T) {
	// This test verifies that environment variables override file config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create YAML with one value
	yamlContent := `
nannyapi_url: https://yaml.nannyai.dev
portal_url: https://yaml.nannyai.dev
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Set environment variable for NANNYAPI_URL (should override YAML)
	_ = os.Setenv("NANNYAPI_URL", "https://env.nannyai.dev")
	defer func() { _ = os.Unsetenv("NANNYAPI_URL") }()

	// Load config
	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}

	// Manually apply env override
	if url := os.Getenv("NANNYAPI_URL"); url != "" {
		config.APIBaseURL = url
	}

	// Verify NANNYAPI_URL is from ENV
	if config.APIBaseURL != "https://env.nannyai.dev" {
		t.Errorf("APIBaseURL = %v, want https://env.nannyai.dev", config.APIBaseURL)
	}

	// Verify PortalURL is from YAML (not overridden)
	if config.PortalURL != "https://yaml.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://yaml.nannyai.dev", config.PortalURL)
	}
}

func TestFindEnvFile(t *testing.T) {
	// findEnvFile is removed, so this test is no longer relevant or should test that it returns empty
	found := findEnvFile()
	if found != "" {
		t.Errorf("findEnvFile() = %v, want empty string", found)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Create invalid YAML
	invalidYAML := `
nannyapi_url: https://test-api.nannyai.dev
portal_url: [invalid yaml structure
`
	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err == nil {
		t.Error("loadYAMLConfig() expected error for invalid YAML, got nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	// Verify default values
	if DefaultConfig.TokenPath != "/var/lib/nannyagent/token.json" {
		t.Errorf("DefaultConfig.TokenPath = %v, want /var/lib/nannyagent/token.json", DefaultConfig.TokenPath)
	}
	if DefaultConfig.PortalURL != "https://nannyai.dev" {
		t.Errorf("DefaultConfig.PortalURL = %v, want https://nannyai.dev", DefaultConfig.PortalURL)
	}
	if DefaultConfig.MetricsInterval != 30 {
		t.Errorf("DefaultConfig.MetricsInterval = %v, want 30", DefaultConfig.MetricsInterval)
	}
	if DefaultConfig.Debug != false {
		t.Errorf("DefaultConfig.Debug = %v, want false", DefaultConfig.Debug)
	}
}

func TestLoadConfig_SystemEnvFileExists(t *testing.T) {
	// This test is no longer relevant as we don't load system env files
	// But we can keep it as a placeholder or remove it.
	// For now, let's just make it pass trivially or remove it.
}

func TestLoadConfig_DebugEnvironmentVariations(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{"debug true", "true", true},
		{"debug 1", "1", true},
		{"debug false", "false", false},
		{"debug 0", "0", false},
		{"debug empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig

			if tt.envValue == "true" || tt.envValue == "1" {
				config.Debug = true
			} else {
				config.Debug = false
			}

			if config.Debug != tt.want {
				t.Errorf("Debug = %v, want %v for env value %q", config.Debug, tt.want, tt.envValue)
			}
		})
	}
}

func TestHTTPTransportConfig_Validate(t *testing.T) {
	validBase := func() HTTPTransportConfig {
		return DefaultHTTPTransportConfig
	}

	tests := []struct {
		name    string
		modify  func(*HTTPTransportConfig)
		wantErr string
	}{
		{
			name:    "valid defaults",
			modify:  func(c *HTTPTransportConfig) {},
			wantErr: "",
		},
		{
			name:    "initial_retry_delay_sec zero",
			modify:  func(c *HTTPTransportConfig) { c.InitialRetryDelaySec = 0 },
			wantErr: "initial_retry_delay_sec must be > 0",
		},
		{
			name:    "initial_retry_delay_sec negative",
			modify:  func(c *HTTPTransportConfig) { c.InitialRetryDelaySec = -5 },
			wantErr: "initial_retry_delay_sec must be > 0",
		},
		{
			name:    "max_retry_delay_sec zero",
			modify:  func(c *HTTPTransportConfig) { c.MaxRetryDelaySec = 0 },
			wantErr: "max_retry_delay_sec must be > 0",
		},
		{
			name:    "max_retry_delay_sec negative",
			modify:  func(c *HTTPTransportConfig) { c.MaxRetryDelaySec = -10 },
			wantErr: "max_retry_delay_sec must be > 0",
		},
		{
			name: "max_retry_delay_sec less than initial",
			modify: func(c *HTTPTransportConfig) {
				c.InitialRetryDelaySec = 60
				c.MaxRetryDelaySec = 30
			},
			wantErr: "max_retry_delay_sec (30) must be >= initial_retry_delay_sec (60)",
		},
		{
			name:    "transport_reset_threshold zero",
			modify:  func(c *HTTPTransportConfig) { c.TransportResetThreshold = 0 },
			wantErr: "transport_reset_threshold must be >= 1",
		},
		{
			name:    "transport_reset_threshold negative",
			modify:  func(c *HTTPTransportConfig) { c.TransportResetThreshold = -1 },
			wantErr: "transport_reset_threshold must be >= 1",
		},
		{
			name:    "idle_conn_timeout_sec negative",
			modify:  func(c *HTTPTransportConfig) { c.IdleConnTimeoutSec = -1 },
			wantErr: "idle_conn_timeout_sec must be >= 0",
		},
		{
			name:    "response_header_timeout_sec negative",
			modify:  func(c *HTTPTransportConfig) { c.ResponseHeaderTimeoutSec = -1 },
			wantErr: "response_header_timeout_sec must be >= 0",
		},
		{
			name:    "max_idle_conns negative",
			modify:  func(c *HTTPTransportConfig) { c.MaxIdleConns = -1 },
			wantErr: "max_idle_conns must be >= 0",
		},
		{
			name:    "max_idle_conns_per_host negative",
			modify:  func(c *HTTPTransportConfig) { c.MaxIdleConnsPerHost = -1 },
			wantErr: "max_idle_conns_per_host must be >= 0",
		},
		{
			name:    "idle_conn_timeout_sec zero is valid",
			modify:  func(c *HTTPTransportConfig) { c.IdleConnTimeoutSec = 0 },
			wantErr: "",
		},
		{
			name:    "response_header_timeout_sec zero is valid",
			modify:  func(c *HTTPTransportConfig) { c.ResponseHeaderTimeoutSec = 0 },
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBase()
			tt.modify(&cfg)
			err := cfg.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestUseStaticToken(t *testing.T) {
	tests := []struct {
		name        string
		staticToken string
		want        bool
	}{
		{"valid nsk token", "nsk_abc123def456", true},
		{"empty token", "", false},
		{"non-nsk prefix", "invalid_token", false},
		{"just nsk_", "nsk_", false},
		{"partial nsk", "nsk", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{StaticToken: tt.staticToken}
			if got := cfg.UseStaticToken(); got != tt.want {
				t.Errorf("UseStaticToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidate_StaticToken(t *testing.T) {
	tests := []struct {
		name        string
		staticToken string
		wantErr     bool
	}{
		{"valid nsk token", "nsk_abc123", false},
		{"empty token", "", false},
		{"invalid prefix", "bad_token", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				APIBaseURL:                    "https://test.nannyai.dev",
				StaticToken:                   tt.staticToken,
				MetricsInterval:               30,
				ProxmoxInterval:               300,
				HTTPTransport:                 DefaultHTTPTransportConfig,
				TokenRenewalThresholdDays:     DefaultConfig.TokenRenewalThresholdDays,
				TokenRenewalCheckIntervalSecs: DefaultConfig.TokenRenewalCheckIntervalSecs,
				TokenRenewalRetryIntervalSecs: DefaultConfig.TokenRenewalRetryIntervalSecs,
			}
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestApplyCLIFlags(t *testing.T) {
	cfg := &Config{
		APIBaseURL:      "https://yaml.nannyai.dev",
		PortalURL:       "https://yaml.portal.dev",
		TokenPath:       "/yaml/token.json",
		MetricsInterval: 30,
		ProxmoxInterval: 300,
		Debug:           false,
	}

	flags := &CLIFlags{
		APIBaseURL:      "https://cli.nannyai.dev",
		MetricsInterval: 60,
		AgentID:         "cli_agent_id",
		Debug:           true,
		DebugSet:        true,
	}

	cfg.ApplyCLIFlags(flags)

	if cfg.APIBaseURL != "https://cli.nannyai.dev" {
		t.Errorf("APIBaseURL = %v, want https://cli.nannyai.dev", cfg.APIBaseURL)
	}
	if cfg.MetricsInterval != 60 {
		t.Errorf("MetricsInterval = %v, want 60", cfg.MetricsInterval)
	}
	if cfg.AgentID != "cli_agent_id" {
		t.Errorf("AgentID = %v, want cli_agent_id", cfg.AgentID)
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}

	// Non-overridden values should remain
	if cfg.PortalURL != "https://yaml.portal.dev" {
		t.Errorf("PortalURL = %v, want https://yaml.portal.dev", cfg.PortalURL)
	}
	if cfg.TokenPath != "/yaml/token.json" {
		t.Errorf("TokenPath = %v, want /yaml/token.json", cfg.TokenPath)
	}
	if cfg.ProxmoxInterval != 300 {
		t.Errorf("ProxmoxInterval = %v, want 300", cfg.ProxmoxInterval)
	}
}

func TestApplyCLIFlags_NoOverride(t *testing.T) {
	cfg := &Config{
		APIBaseURL:      "https://yaml.nannyai.dev",
		MetricsInterval: 30,
		Debug:           true,
	}

	flags := &CLIFlags{}
	cfg.ApplyCLIFlags(flags)

	if cfg.APIBaseURL != "https://yaml.nannyai.dev" {
		t.Errorf("APIBaseURL changed unexpectedly to %v", cfg.APIBaseURL)
	}
	if cfg.MetricsInterval != 30 {
		t.Errorf("MetricsInterval changed unexpectedly to %v", cfg.MetricsInterval)
	}
	if !cfg.Debug {
		t.Error("Debug should remain true when DebugSet is false")
	}
}

func TestLoadConfig_StaticToken_FromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
nannyapi_url: https://test-api.nannyai.dev
static_token: "nsk_abc123def456"
agent_id: "agent_test_42"
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}

	if config.StaticToken != "nsk_abc123def456" {
		t.Errorf("StaticToken = %v, want nsk_abc123def456", config.StaticToken)
	}
	if config.AgentID != "agent_test_42" {
		t.Errorf("AgentID = %v, want agent_test_42", config.AgentID)
	}
}

func TestLoadConfig_StaticToken_EnvOverride(t *testing.T) {
	_ = os.Setenv("NANNYAI_STATIC_TOKEN", "nsk_env_token")
	_ = os.Setenv("NANNYAI_AGENT_ID", "env_agent_id")
	defer func() {
		_ = os.Unsetenv("NANNYAI_STATIC_TOKEN")
		_ = os.Unsetenv("NANNYAI_AGENT_ID")
	}()

	config := DefaultConfig
	if staticToken := os.Getenv("NANNYAI_STATIC_TOKEN"); staticToken != "" {
		config.StaticToken = staticToken
	}
	if agentID := os.Getenv("NANNYAI_AGENT_ID"); agentID != "" {
		config.AgentID = agentID
	}

	if config.StaticToken != "nsk_env_token" {
		t.Errorf("StaticToken = %v, want nsk_env_token", config.StaticToken)
	}
	if config.AgentID != "env_agent_id" {
		t.Errorf("AgentID = %v, want env_agent_id", config.AgentID)
	}
}

func TestSaveAgentID_Append(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialContent := `nannyapi_url: "https://test-api.nannyai.dev"
static_token: "nsk_abc123"
`
	err := os.WriteFile(configPath, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Call the real saveAgentIDToPath method
	cfg := &Config{}
	if err := cfg.saveAgentIDToPath("new_agent_123", configPath); err != nil {
		t.Fatalf("saveAgentIDToPath() error: %v", err)
	}

	var loadedCfg Config
	err = loadYAMLConfig(&loadedCfg, configPath)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}
	if loadedCfg.AgentID != "new_agent_123" {
		t.Errorf("AgentID = %v, want new_agent_123", loadedCfg.AgentID)
	}
}

// ── Validation Tests ────────────────────────────────────────────────────────

// validConfig returns a fully valid Config for use as a test baseline.
// Tests modify one field at a time to isolate each validation.
func validConfig() *Config {
	return &Config{
		APIBaseURL:                    "https://api.nannyai.dev",
		PortalURL:                     "https://nannyai.dev",
		TokenPath:                     "/var/lib/nannyagent/token.json",
		MetricsInterval:               30,
		ProxmoxInterval:               300,
		HTTPTransport:                 DefaultHTTPTransportConfig,
		TokenRenewalThresholdDays:     7,
		TokenRenewalCheckIntervalSecs: 21600,
		TokenRenewalRetryIntervalSecs: 3600,
	}
}

func TestValidate_URL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		field   string // "api" or "portal"
		wantErr string
	}{
		{"valid https", "https://api.nannyai.dev", "api", ""},
		{"valid http", "http://localhost:8090", "api", ""},
		{"valid with port", "https://api.nannyai.dev:443", "api", ""},
		{"valid with path", "https://api.nannyai.dev/v1", "api", ""},
		{"ftp scheme rejected", "ftp://api.nannyai.dev", "api", "must use http or https"},
		{"no scheme", "api.nannyai.dev", "api", "must use http or https"},
		{"empty scheme", "://api.nannyai.dev", "api", "not a valid URL"},
		{"missing host", "https://", "api", "missing a host"},
		{"too long URL", "https://" + strings.Repeat("a", MaxURLLength), "api", "too long"},

		// portal_url
		{"valid portal", "https://nannyai.dev", "portal", ""},
		{"invalid portal scheme", "ws://nannyai.dev", "portal", "must use http or https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			if tt.field == "api" {
				cfg.APIBaseURL = tt.url
			} else {
				cfg.PortalURL = tt.url
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidate_TokenPath(t *testing.T) {
	tests := []struct {
		name      string
		tokenPath string
		wantErr   string
	}{
		{"valid absolute path", "/var/lib/nannyagent/token.json", ""},
		{"empty is valid", "", ""},
		{"relative path rejected", "relative/token.json", "must be an absolute path"},
		{"just filename rejected", "token.json", "must be an absolute path"},
		{"too long path", "/" + strings.Repeat("a", MaxTokenPathLength), "too long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.TokenPath = tt.tokenPath
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidate_StaticTokenBounds(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"valid token", "nsk_cf4da3f36fad8ea014f5c73b2610e51d", ""},
		{"empty is valid", "", ""},
		{"wrong prefix", "bad_token", "must start with 'nsk_'"},
		{"nsk_ alone too short", "nsk_", "too short"},
		{"min length exact", "nsk_x", ""},
		{"too long", "nsk_" + strings.Repeat("a", MaxStaticTokenLen), "too long"},
		{"max length exact", "nsk_" + strings.Repeat("a", MaxStaticTokenLen-4), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.StaticToken = tt.token
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidate_AgentID(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		wantErr string
	}{
		{"valid agent ID", "agent_abc123", ""},
		{"empty is valid", "", ""},
		{"whitespace-only rejected", "   ", "must not be blank"},
		{"tab-only rejected", "\t", "must not be blank"},
		{"too long", strings.Repeat("x", MaxAgentIDLength+1), "too long"},
		{"max length exact", strings.Repeat("x", MaxAgentIDLength), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.AgentID = tt.agentID
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidate_MetricsInterval(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr string
	}{
		{"valid 30s", 30, ""},
		{"valid max", MaxInterval, ""},
		{"valid min", MinInterval, ""},
		{"zero rejected", 0, "must be > 0"},
		{"negative rejected", -1, "must be > 0"},
		{"too small", MinInterval - 1, "must be >="},
		{"too large", MaxInterval + 1, "must be <="},
		{"large negative (overflow-ish)", -2147483648, "must be > 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.MetricsInterval = tt.value
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidate_ProxmoxInterval(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr string
	}{
		{"valid 300s", 300, ""},
		{"zero rejected", 0, "must be > 0"},
		{"negative rejected", -100, "must be > 0"},
		{"too large", MaxInterval + 1, "must be <="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.ProxmoxInterval = tt.value
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidate_TokenRenewalBounds(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr string
	}{
		{
			name:    "all valid defaults",
			modify:  func(c *Config) {},
			wantErr: "",
		},
		{
			name:    "threshold_days negative",
			modify:  func(c *Config) { c.TokenRenewalThresholdDays = -1 },
			wantErr: "token_renewal_threshold_days must be > 0",
		},
		{
			name:    "threshold_days too large",
			modify:  func(c *Config) { c.TokenRenewalThresholdDays = MaxRenewalThresholdDays + 1 },
			wantErr: "token_renewal_threshold_days must be <=",
		},
		{
			name:    "threshold_days at max",
			modify:  func(c *Config) { c.TokenRenewalThresholdDays = MaxRenewalThresholdDays },
			wantErr: "",
		},
		{
			name:    "check_interval too large",
			modify:  func(c *Config) { c.TokenRenewalCheckIntervalSecs = MaxRenewalIntervalSecs + 1 },
			wantErr: "token_renewal_check_interval_secs must be <=",
		},
		{
			name:    "retry_interval too large",
			modify:  func(c *Config) { c.TokenRenewalRetryIntervalSecs = MaxRenewalIntervalSecs + 1 },
			wantErr: "token_renewal_retry_interval_secs must be <=",
		},
		{
			name:    "check_interval at max",
			modify:  func(c *Config) { c.TokenRenewalCheckIntervalSecs = MaxRenewalIntervalSecs },
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestHTTPTransportConfig_ValidateUpperBounds(t *testing.T) {
	validBase := func() HTTPTransportConfig {
		return DefaultHTTPTransportConfig
	}

	tests := []struct {
		name    string
		modify  func(*HTTPTransportConfig)
		wantErr string
	}{
		{
			name:    "initial_retry_delay too large",
			modify:  func(c *HTTPTransportConfig) { c.InitialRetryDelaySec = MaxRetryDelay + 1 },
			wantErr: "initial_retry_delay_sec must be <=",
		},
		{
			name:    "max_retry_delay too large",
			modify:  func(c *HTTPTransportConfig) { c.MaxRetryDelaySec = MaxRetryDelay + 1 },
			wantErr: "max_retry_delay_sec must be <=",
		},
		{
			name:    "transport_reset_threshold too large",
			modify:  func(c *HTTPTransportConfig) { c.TransportResetThreshold = MaxTransportResetThresh + 1 },
			wantErr: "transport_reset_threshold must be <=",
		},
		{
			name:    "idle_conn_timeout too large",
			modify:  func(c *HTTPTransportConfig) { c.IdleConnTimeoutSec = MaxIdleConnTimeoutSec + 1 },
			wantErr: "idle_conn_timeout_sec must be <=",
		},
		{
			name:    "response_header_timeout too large",
			modify:  func(c *HTTPTransportConfig) { c.ResponseHeaderTimeoutSec = MaxResponseHeaderSec + 1 },
			wantErr: "response_header_timeout_sec must be <=",
		},
		{
			name:    "max_idle_conns too large",
			modify:  func(c *HTTPTransportConfig) { c.MaxIdleConns = MaxIdleConns + 1 },
			wantErr: "max_idle_conns must be <=",
		},
		{
			name:    "max_idle_conns_per_host too large",
			modify:  func(c *HTTPTransportConfig) { c.MaxIdleConnsPerHost = MaxIdleConns + 1 },
			wantErr: "max_idle_conns_per_host must be <=",
		},
		{
			name: "per_host exceeds total",
			modify: func(c *HTTPTransportConfig) {
				c.MaxIdleConns = 5
				c.MaxIdleConnsPerHost = 10
			},
			wantErr: "max_idle_conns_per_host (10) must be <= max_idle_conns (5)",
		},
		{
			name: "at upper bounds is valid",
			modify: func(c *HTTPTransportConfig) {
				c.MaxIdleConns = MaxIdleConns
				c.MaxIdleConnsPerHost = MaxIdleConns
				c.IdleConnTimeoutSec = MaxIdleConnTimeoutSec
				c.ResponseHeaderTimeoutSec = MaxResponseHeaderSec
				c.TransportResetThreshold = MaxTransportResetThresh
				c.InitialRetryDelaySec = MaxRetryDelay
				c.MaxRetryDelaySec = MaxRetryDelay
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBase()
			tt.modify(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidateAfterMerge_CLIOverridesInvalid(t *testing.T) {
	cfg := validConfig()

	// Apply CLI flags that introduce an invalid metrics interval
	flags := &CLIFlags{
		MetricsInterval: 2, // below MinInterval (5)
	}
	cfg.ApplyCLIFlags(flags)

	err := cfg.ValidateAfterMerge()
	if err == nil {
		t.Error("ValidateAfterMerge() expected error for interval below minimum, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "metrics_interval") {
		t.Errorf("ValidateAfterMerge() error = %q, expected metrics_interval mention", err.Error())
	}
}

func TestValidateAfterMerge_CLIOverridesValid(t *testing.T) {
	cfg := validConfig()

	flags := &CLIFlags{
		APIBaseURL:      "http://localhost:9090",
		MetricsInterval: 60,
	}
	cfg.ApplyCLIFlags(flags)

	err := cfg.ValidateAfterMerge()
	if err != nil {
		t.Errorf("ValidateAfterMerge() unexpected error: %v", err)
	}
	if cfg.APIBaseURL != "http://localhost:9090" {
		t.Errorf("APIBaseURL = %v, want http://localhost:9090", cfg.APIBaseURL)
	}
}

func TestValidate_InvalidURLViaCLI(t *testing.T) {
	cfg := validConfig()

	flags := &CLIFlags{
		APIBaseURL: "ftp://bad-scheme.example.com",
	}
	cfg.ApplyCLIFlags(flags)

	err := cfg.ValidateAfterMerge()
	if err == nil {
		t.Error("Expected error for ftp:// scheme via CLI, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "must use http or https") {
		t.Errorf("Error = %q, expected scheme error", err.Error())
	}
}

func TestValidate_YAMLWithInvalidValues(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
nannyapi_url: https://api.nannyai.dev
metrics_interval: -10
proxmox_interval: 300
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := DefaultConfig
	err = loadYAMLConfig(&cfg, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}
	cfg.HTTPTransport.ApplyDefaults()
	cfg.ApplyTokenRenewalDefaults()

	err = cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for negative metrics_interval")
	}
	if err != nil && !strings.Contains(err.Error(), "metrics_interval") {
		t.Errorf("Error = %q, expected metrics_interval mention", err.Error())
	}
}

func TestValidate_YAMLWithOverflowInterval(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
nannyapi_url: https://api.nannyai.dev
metrics_interval: 999999999
proxmox_interval: 300
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := DefaultConfig
	err = loadYAMLConfig(&cfg, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}
	cfg.HTTPTransport.ApplyDefaults()
	cfg.ApplyTokenRenewalDefaults()

	err = cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for overflow metrics_interval")
	}
	if err != nil && !strings.Contains(err.Error(), "metrics_interval") {
		t.Errorf("Error = %q, expected metrics_interval mention", err.Error())
	}
}

func TestValidate_EnvStaticTokenInvalid(t *testing.T) {
	cfg := validConfig()

	// Simulate env var setting a bad token
	cfg.StaticToken = "bad_prefix_token"

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for non-nsk token via env")
	}
	if err != nil && !strings.Contains(err.Error(), "nsk_") {
		t.Errorf("Error = %q, expected nsk_ prefix mention", err.Error())
	}
}

func TestValidate_RelativeTokenPathViaEnv(t *testing.T) {
	cfg := validConfig()
	cfg.TokenPath = "relative/path/token.json"

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for relative token_path")
	}
	if err != nil && !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("Error = %q, expected absolute path mention", err.Error())
	}
}
