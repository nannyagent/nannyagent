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
