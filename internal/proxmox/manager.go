package proxmox

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"nannyagent/internal/config"
	"nannyagent/internal/logging"
)

// Authenticator defines the interface for authenticated requests
type Authenticator interface {
	AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}

type Manager struct {
	collector *Collector
	auth      Authenticator
	config    *config.Config
	stopChan  chan struct{}
	stopOnce  sync.Once
}

func NewManager(cfg *config.Config, auth Authenticator) *Manager {
	return NewManagerWithCollector(cfg, auth, NewCollector(&RealCommandExecutor{}))
}

// NewManagerWithCollector creates a new manager with a custom collector (useful for testing)
func NewManagerWithCollector(cfg *config.Config, auth Authenticator, collector *Collector) *Manager {
	return &Manager{
		collector: collector,
		auth:      auth,
		config:    cfg,
		stopChan:  make(chan struct{}),
	}
}

func (m *Manager) Start() {
	if !m.collector.IsProxmoxInstalled() {
		logging.Info("Proxmox VE not detected, skipping Proxmox collector")
		return
	}

	logging.Info("Proxmox VE detected, starting collector")
	go m.runLoop()
}

func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
}

func (m *Manager) runLoop() {
	// Initial delay to allow agent to start up properly
	time.Sleep(10 * time.Second)

	// Run immediately
	m.collectAndSend()

	ticker := time.NewTicker(time.Duration(m.config.ProxmoxInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectAndSend()
		case <-m.stopChan:
			return
		}
	}
}

func (m *Manager) collectAndSend() {
	if !m.collector.IsPartOfCluster() {
		logging.Info("Node is not part of a cluster, skipping cluster collection")
		// Proceed with node collection as standalone
	}

	// Collect Node Info
	nodeInfo, err := m.collector.CollectNodeInfo()
	if err != nil {
		logging.Error("Failed to collect node info: %v", err)
		return
	}

	// Send Node Info
	if err := m.sendData("/api/proxmox/node", nodeInfo); err != nil {
		logging.Error("Failed to send node info: %v", err)
	}

	// Collect Cluster Info (only if node ID is 1)
	// we have to find a better way to stop sending duplicate cluster info
	// from other nodes, for now disable it
	//if nodeInfo.NodeID == 1 {
	clusterInfo, err := m.collector.CollectClusterInfo()
	if err != nil {
		logging.Error("Failed to collect cluster info: %v", err)
	} else {
		if err := m.sendData("/api/proxmox/cluster", clusterInfo); err != nil {
			logging.Error("Failed to send cluster info: %v", err)
		}
	}
	//}

	// Collect LXC Info
	lxcs, err := m.collector.CollectLXCInfo(nodeInfo.Name)
	if err != nil {
		logging.Error("Failed to collect LXC info: %v", err)
	} else {
		for _, lxc := range lxcs {
			if err := m.sendData("/api/proxmox/lxc", lxc); err != nil {
				logging.Error("Failed to send LXC info for %s: %v", lxc.Name, err)
			}
		}
	}

	// Collect QEMU Info
	vms, err := m.collector.CollectQemuInfo(nodeInfo.Name)
	if err != nil {
		logging.Error("Failed to collect QEMU info: %v", err)
	} else {
		for _, vm := range vms {
			if err := m.sendData("/api/proxmox/qemu", vm); err != nil {
				logging.Error("Failed to send QEMU info for %s: %v", vm.Name, err)
			}
		}
	}
}

func (m *Manager) sendData(endpoint string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	url := fmt.Sprintf("%s%s", m.config.APIBaseURL, endpoint)
	statusCode, _, err := m.auth.AuthenticatedRequest("POST", url, jsonData, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	if statusCode >= 400 {
		return fmt.Errorf("server returned status %d", statusCode)
	}

	return nil
}
