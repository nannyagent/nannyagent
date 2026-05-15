package app

import (
	"fmt"

	"nannyagent/internal/config"
	"nannyagent/internal/metrics"
)

type ConnectivityAuthManager interface {
	AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}

func TestAPIConnectivity(version string, cfg *config.Config, authManager ConnectivityAuthManager, agentID string) error {
	metricsCollector := metrics.NewCollector(version, cfg.APIBaseURL)
	systemMetrics, err := metricsCollector.GatherSystemMetrics()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	if err := metricsCollector.IngestMetrics(agentID, authManager, systemMetrics); err != nil {
		return fmt.Errorf("metrics ingestion failed: %w", err)
	}

	return nil
}
