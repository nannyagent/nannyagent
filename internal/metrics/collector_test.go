package metrics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nannyagent/internal/hostinfo"
	"nannyagent/internal/nannyapi"
	"nannyagent/internal/types"
)

func TestNewCollector(t *testing.T) {
	version := "v1.0.0"
	apiURL := "http://localhost:8090"
	collector := NewCollector(version, apiURL)

	if collector == nil {
		t.Fatal("Expected collector to be created")
	}

	if collector.agentVersion != version {
		t.Errorf("Expected version %s, got %s", version, collector.agentVersion)
	}
	if collector.apiBaseURL != apiURL {
		t.Errorf("Expected API URL %s, got %s", apiURL, collector.apiBaseURL)
	}
}

func TestGatherSystemMetrics(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	metrics, err := collector.GatherSystemMetrics()
	if err != nil {
		t.Fatalf("Failed to gather system metrics: %v", err)
	}

	if metrics == nil {
		t.Fatal("Expected metrics to be returned")
	}

	// Check timestamp
	if metrics.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}

	// Verify timestamp is recent (within last minute)
	if time.Since(metrics.Timestamp) > time.Minute {
		t.Error("Timestamp should be recent")
	}

	// Basic sanity checks on metrics
	t.Run("SystemInfo", func(t *testing.T) {
		if metrics.Hostname == "" {
			t.Error("Hostname should not be empty")
		}
		if metrics.Platform == "" {
			t.Error("Platform should not be empty")
		}
		if metrics.KernelVersion == "" {
			t.Error("KernelVersion should not be empty")
		}
		if metrics.OSType == "" {
			t.Error("OSType should not be empty")
		}
	})

	t.Run("CPUMetrics", func(t *testing.T) {
		// CPU usage should be between 0 and 100
		if metrics.CPUUsage < 0 || metrics.CPUUsage > 100 {
			t.Errorf("CPUUsage should be between 0 and 100, got %.2f", metrics.CPUUsage)
		}

		if metrics.CPUCores <= 0 {
			t.Error("CPUCores should be > 0")
		}
	})

	t.Run("MemoryMetrics", func(t *testing.T) {
		if metrics.MemoryTotal == 0 {
			t.Error("MemoryTotal should be > 0")
		}
	})

	t.Run("DiskMetrics", func(t *testing.T) {
		if metrics.DiskTotal == 0 {
			t.Error("DiskTotal should be > 0")
		}
	})

	t.Run("NetworkMetrics", func(t *testing.T) {
		if metrics.NetworkInGb < 0.0 {
			t.Errorf("NetworkInKbps should be >= 0, got %.2f", metrics.NetworkInGb)
		}
	})

	t.Run("IPAddress", func(t *testing.T) {
		if metrics.IPAddress == "" {
			t.Error("IPAddress should not be empty")
		}
	})

	t.Run("AllIPs", func(t *testing.T) {
		if metrics.AllIPs == nil {
			t.Error("AllIPs should not be nil")
		}
	})

	t.Run("FilesystemInfo", func(t *testing.T) {
		if len(metrics.FilesystemInfo) == 0 {
			t.Log("No filesystems found")
		}
	})

	t.Run("BlockDevices", func(t *testing.T) {
		if len(metrics.BlockDevices) == 0 {
			t.Log("No block devices found")
		}
	})
}

func TestConvertSystemMetrics(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	// Create a sample SystemMetrics
	sysMetrics := &types.SystemMetrics{
		CPUUsage:      15.5,
		CPUCores:      4,
		MemoryUsed:    8 * 1024 * 1024 * 1024,   // 8 GB
		MemoryTotal:   16 * 1024 * 1024 * 1024,  // 16 GB
		DiskUsed:      50 * 1024 * 1024 * 1024,  // 50 GB
		DiskTotal:     100 * 1024 * 1024 * 1024, // 100 GB
		NetworkInGb:   1.5,
		NetworkOutGb:  0.5,
		LoadAvg1:      0.5,
		LoadAvg5:      0.4,
		LoadAvg15:     0.3,
		KernelVersion: "5.15.0",
		OSType:        "linux",
		FilesystemInfo: []types.FilesystemInfo{
			{
				Device:       "/dev/sda1",
				Mountpoint:   "/",
				Used:         50 * 1024 * 1024 * 1024,
				Total:        100 * 1024 * 1024 * 1024,
				UsagePercent: 50.0,
			},
		},
	}

	pbMetrics := collector.convertSystemMetrics(sysMetrics)

	if pbMetrics.CPUPercent != 15.5 {
		t.Errorf("Expected CPUPercent 15.5, got %.2f", pbMetrics.CPUPercent)
	}
	if pbMetrics.CPUCores != 4 {
		t.Errorf("Expected CPUCores 4, got %d", pbMetrics.CPUCores)
	}
	if pbMetrics.MemoryUsedGB != 8.0 {
		t.Errorf("Expected MemoryUsedGB 8.0, got %.2f", pbMetrics.MemoryUsedGB)
	}
	if pbMetrics.MemoryTotalGB != 16.0 {
		t.Errorf("Expected MemoryTotalGB 16.0, got %.2f", pbMetrics.MemoryTotalGB)
	}
	if pbMetrics.MemoryPercent != 50.0 {
		t.Errorf("Expected MemoryPercent 50.0, got %.2f", pbMetrics.MemoryPercent)
	}
	if pbMetrics.NetworkStats.InGB != 1.5 {
		t.Errorf("Expected NetworkStats.InGB 1.5, got %.2f", pbMetrics.NetworkStats.InGB)
	}
	if pbMetrics.KernelVersion != "5.15.0" {
		t.Errorf("Expected KernelVersion 5.15.0, got %s", pbMetrics.KernelVersion)
	}
}

func TestGetAllIPs(t *testing.T) {
	_, ips := hostinfo.IPAddresses()

	if ips == nil {
		t.Error("Expected IPs slice to be initialized")
	}

	// If we have IPs, check they are not loopback
	for _, ip := range ips {
		if ip == "127.0.0.1" || ip == "::1" {
			t.Errorf("Should not include loopback IP: %s", ip)
		}
	}
}

func TestSafeCastUint64(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected uint64
	}{
		{"Normal value", 1024, 1024},
		{"Zero", 0, 0},
		{"Large value", 1 << 40, 1 << 40},                                   // 1 TB
		{"Max uint64 (capped)", ^uint64(0), maxSafeJSONInt},                 // Should be capped to maxSafeInt
		{"Value above max safe int", maxSafeJSONInt + 1000, maxSafeJSONInt}, // Should be capped
		{"Value at max safe int", maxSafeJSONInt, maxSafeJSONInt},           // Should not be capped
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeCastUint64(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetNetworkStatsMbps(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	inGB, outGB, err := collector.getNetworkStatsGbps()
	if err != nil {
		t.Fatalf("Failed to get network stats: %v", err)
	}

	// Currently returns 0.0 as a placeholder since rate calculation isn't implemented
	if inGB < 0.0 {
		t.Errorf("Expected 0.0 for GB, got %.2f", inGB)
	}
	if outGB < 0.0 {
		t.Errorf("Expected 0.0 for GB, got %.2f", outGB)
	}
}

func TestGetIPAddress(t *testing.T) {
	ip, _ := hostinfo.IPAddresses()

	if ip == "" {
		t.Error("IP address should not be empty")
	}

	// Should not be loopback
	if ip == "127.0.0.1" || ip == "::1" {
		t.Error("Should not return loopback address")
	}

	// Should be either a valid IP or "unknown"
	if ip != "unknown" {
		// Basic IP validation (not exhaustive)
		if len(ip) == 0 {
			t.Error("IP address should not be empty if not 'unknown'")
		}
	}
}

func TestGetLocation(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	location := collector.getLocation()

	// Currently returns "unknown" as a placeholder
	if location != "unknown" {
		t.Logf("Location: %s (may be implemented in the future)", location)
	}
}

func TestGetFilesystemInfo(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	filesystems := collector.getFilesystemInfo()

	// May be empty in some test environments
	if len(filesystems) == 0 {
		t.Log("No filesystems found (may be expected in test environment)")
		return
	}

	// Validate each filesystem entry
	for i, fs := range filesystems {
		if fs.Mountpoint == "" {
			t.Errorf("Filesystem %d: Mountpoint should not be empty", i)
		}

		// Should be one of the whitelisted types
		if !isAllowedFilesystemType(fs.Fstype) {
			t.Errorf("Filesystem %d: Unexpected fstype %s", i, fs.Fstype)
		}

		if fs.Total == 0 {
			t.Errorf("Filesystem %d: Total should be > 0", i)
		}

		if fs.Used > fs.Total {
			t.Errorf("Filesystem %d: Used (%d) should not exceed Total (%d)", i, fs.Used, fs.Total)
		}

		if fs.UsagePercent < 0 || fs.UsagePercent > 100 {
			t.Errorf("Filesystem %d: UsagePercent should be between 0 and 100, got %.2f", i, fs.UsagePercent)
		}
	}
}

func TestCollectorHelpers(t *testing.T) {
	t.Run("round2", func(t *testing.T) {
		if got := round2(1.235); got != 1.24 {
			t.Fatalf("round2() = %.2f, want 1.24", got)
		}
	})

	t.Run("bytesToGB", func(t *testing.T) {
		if got := bytesToGB(3*bytesPerGB + bytesPerGB/2); got != 3.5 {
			t.Fatalf("bytesToGB() = %.2f, want 3.50", got)
		}
	})

	t.Run("calculateUsagePercent", func(t *testing.T) {
		if got := calculateUsagePercent(1, 3); got != 33.33 {
			t.Fatalf("calculateUsagePercent() = %.2f, want 33.33", got)
		}
	})

	t.Run("isAllowedBlockDevice", func(t *testing.T) {
		if !isAllowedBlockDevice("/dev/nvme0n1") {
			t.Fatal("expected NVMe device to be allowed")
		}
		if isAllowedBlockDevice("tmpfs") {
			t.Fatal("expected non-device path to be rejected")
		}
	})
}

func TestGetBlockDevices(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	devices := collector.getBlockDevices()

	// May be empty in some test environments
	if len(devices) == 0 {
		t.Log("No block devices found (may be expected in test environment)")
		return
	}

	// Validate each device
	for i, device := range devices {
		if device.Name == "" {
			t.Errorf("Device %d: Name should not be empty", i)
		}

		// Type should not be empty
		if device.Type == "" {
			t.Log("Device type is empty (may be normal for some devices)")
		}
	}
}

func TestMetricsConsistency(t *testing.T) {
	collector := NewCollector("v1.0.0", "http://localhost:8090")

	// Gather metrics twice
	metrics1, err1 := collector.GatherSystemMetrics()
	if err1 != nil {
		t.Fatalf("Failed to gather first metrics: %v", err1)
	}

	time.Sleep(100 * time.Millisecond)

	metrics2, err2 := collector.GatherSystemMetrics()
	if err2 != nil {
		t.Fatalf("Failed to gather second metrics: %v", err2)
	}

	// Some values should remain constant
	if metrics1.Hostname != metrics2.Hostname {
		t.Error("Hostname should be consistent across calls")
	}

	if metrics1.CPUCores != metrics2.CPUCores {
		t.Error("CPUCores should be consistent across calls")
	}

	if metrics1.MemoryTotal != metrics2.MemoryTotal {
		t.Error("MemoryTotal should be consistent across calls")
	}

	// Timestamps should be different
	if metrics1.Timestamp.Equal(metrics2.Timestamp) {
		t.Error("Timestamps should be different for separate calls")
	}

	// Second timestamp should be after first
	if !metrics2.Timestamp.After(metrics1.Timestamp) {
		t.Error("Second timestamp should be after first timestamp")
	}
}

func TestFilesystemInfoType(t *testing.T) {
	// Test the FilesystemInfo type structure
	fs := types.FilesystemInfo{
		Device:       "/dev/sda1",
		Mountpoint:   "/",
		Type:         "disk",
		Fstype:       "ext4",
		Total:        100000000,
		Used:         50000000,
		Free:         50000000,
		Usage:        50000000,
		UsagePercent: 50.0,
	}

	if fs.Device != "/dev/sda1" {
		t.Error("Device field not set correctly")
	}
	if fs.Mountpoint != "/" {
		t.Error("Mountpoint field not set correctly")
	}
	if fs.Fstype != "ext4" {
		t.Error("Fstype field not set correctly")
	}
	if fs.UsagePercent != 50.0 {
		t.Error("UsagePercent field not set correctly")
	}
}

func TestBlockDeviceType(t *testing.T) {
	// Test the BlockDevice type structure
	bd := types.BlockDevice{
		Name:         "sda",
		Size:         1000000000,
		Type:         "disk",
		Model:        "Test Model",
		SerialNumber: "12345",
	}

	if bd.Name != "sda" {
		t.Error("Name field not set correctly")
	}
	if bd.Size != 1000000000 {
		t.Error("Size field not set correctly")
	}
	if bd.Type != "disk" {
		t.Error("Type field not set correctly")
	}
}

func TestIngestMetricsRequestMarshaling(t *testing.T) {
	req := types.IngestMetricsRequest{
		Action: nannyapi.ActionIngestMetrics,
		OSType: "linux",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), `"os_type":"linux"`) {
		t.Errorf("JSON does not contain os_type: %s", string(data))
	}
}
