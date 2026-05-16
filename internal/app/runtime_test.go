package app

import (
	"path/filepath"
	"testing"

	"nannyagent/internal/config"
)

func TestLoadRegisterConfig_UsesResolvedTokenPath(t *testing.T) {
	dataDir := t.TempDir()
	overridePath := filepath.Join(t.TempDir(), "custom-token.json")
	t.Setenv("NANNYAPI_URL", "https://example.invalid")

	cfg, tokenPath, err := loadRegisterConfig(dataDir, &config.CLIFlags{TokenPath: overridePath})
	if err != nil {
		t.Fatalf("loadRegisterConfig() error = %v", err)
	}

	if cfg.TokenPath != overridePath {
		t.Fatalf("cfg.TokenPath = %q, want %q", cfg.TokenPath, overridePath)
	}
	if tokenPath != overridePath {
		t.Fatalf("token path = %q, want %q", tokenPath, overridePath)
	}
	if TokenPath(cfg.TokenPath, dataDir) != overridePath {
		t.Fatalf("resolved token path did not honor CLI override")
	}
}
