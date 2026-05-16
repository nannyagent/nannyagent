package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"

	"nannyagent/internal/hostinfo"
	"nannyagent/internal/logging"
	"nannyagent/internal/nannyapi"
	"nannyagent/internal/types"
)

const (
	collectorHTTPTimeout = 30 * time.Second
	defaultLocation      = "unknown"
	defaultProcessCount  = 0
	roundScale           = 100.0
	bytesPerMB           = 1024 * 1024
	bytesPerGB           = 1024 * 1024 * 1024
	maxSafeJSONInt       = 9007199254740991 // 2^53 - 1 (max safe integer in JSON/JavaScript)
)

var allowedFilesystemTypes = map[string]struct{}{
	"ext2":  {},
	"ext3":  {},
	"ext4":  {},
	"xfs":   {},
	"btrfs": {},
	"zfs":   {},
	"ntfs":  {},
	"vfat":  {},
	"exfat": {},
}

var allowedBlockDevicePrefixes = []string{
	"/dev/sd",     // SCSI/SATA disks
	"/dev/hd",     // IDE disks
	"/dev/vd",     // Virtual disks (KVM/QEMU)
	"/dev/xvd",    // Xen virtual disks
	"/dev/nvme",   // NVMe disks
	"/dev/mmcblk", // SD/MMC cards
}

// Collector handles system metrics collection
type Collector struct {
	agentVersion string
	apiBaseURL   string
	client       *http.Client
}

// NewCollector creates a new metrics collector
func NewCollector(agentVersion string, apiBaseURL string) *Collector {
	return &Collector{
		agentVersion: agentVersion,
		apiBaseURL:   apiBaseURL,
		client: &http.Client{
			Timeout: collectorHTTPTimeout,
		},
	}
}

// GatherSystemMetrics collects comprehensive system metrics
func (c *Collector) GatherSystemMetrics() (*types.SystemMetrics, error) {
	metadata := hostinfo.Collect()

	metrics := &types.SystemMetrics{
		Timestamp:      time.Now(),
		Hostname:       metadata.Hostname,
		OSType:         metadata.Platform,
		AllIPs:         metadata.AllIPs,
		IPAddress:      metadata.PrimaryIP,
		KernelVersion:  metadata.KernelVersion,
		PlatformFamily: metadata.PlatformFamily,
	}

	// System Information
	if hostInfo, err := host.Info(); err == nil {
		if hostInfo.Hostname != "" {
			metrics.Hostname = hostInfo.Hostname
		}
		metrics.Platform = hostInfo.Platform
		if hostInfo.PlatformFamily != "" {
			metrics.PlatformFamily = hostInfo.PlatformFamily
		}
		metrics.PlatformVersion = hostInfo.PlatformVersion
		if hostInfo.KernelVersion != "" {
			metrics.KernelVersion = hostInfo.KernelVersion
		}
		metrics.KernelArch = hostInfo.KernelArch
		if hostInfo.OS != "" {
			metrics.OSType = hostInfo.OS
		}
	}

	// CPU Metrics
	if percentages, err := cpu.Percent(time.Second, false); err == nil && len(percentages) > 0 {
		metrics.CPUUsage = round2(percentages[0])
	}

	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		metrics.CPUCores = len(cpuInfo)
		metrics.CPUModel = cpuInfo[0].ModelName
	}

	// Memory Metrics
	if memInfo, err := mem.VirtualMemory(); err == nil {
		metrics.MemoryUsage = bytesToMB(memInfo.Used)
		metrics.MemoryTotal = safeCastUint64(memInfo.Total)
		metrics.MemoryUsed = safeCastUint64(memInfo.Used)
		metrics.MemoryFree = safeCastUint64(memInfo.Free)
		metrics.MemoryAvailable = safeCastUint64(memInfo.Available)
	}

	if swapInfo, err := mem.SwapMemory(); err == nil {
		metrics.SwapTotal = safeCastUint64(swapInfo.Total)
		metrics.SwapUsed = safeCastUint64(swapInfo.Used)
		metrics.SwapFree = safeCastUint64(swapInfo.Free)
	}

	// Disk Metrics
	if diskInfo, err := disk.Usage("/"); err == nil {
		metrics.DiskUsage = round2(diskInfo.UsedPercent)
		metrics.DiskTotal = safeCastUint64(diskInfo.Total)
		metrics.DiskUsed = safeCastUint64(diskInfo.Used)
		metrics.DiskFree = safeCastUint64(diskInfo.Free)
	}

	// Load Averages
	if loadAvg, err := LoadAvgParse(); err == nil {
		metrics.LoadAvg1 = loadAvg.LoadAverage1
		metrics.LoadAvg5 = loadAvg.LoadAverage5
		metrics.LoadAvg15 = loadAvg.LoadAverage10
	}

	// Process Count (simplified - using a constant for now)
	// Note: gopsutil doesn't have host.Processes(), would need process.Processes()
	metrics.ProcessCount = defaultProcessCount

	// Network Metrics - convert cumulative bytes to Mbps (rounded to reasonable values)
	totalRxGB, totalTxGB, err := c.getNetworkStatsGbps()
	if err != nil {
		return nil, err
	}

	if totalRxGB > 0.0 && totalTxGB > 0.0 {
		metrics.NetworkInGb = round2(totalRxGB)
		metrics.NetworkOutGb = round2(totalTxGB)
	} else {
		metrics.NetworkInGb = 0.0
		metrics.NetworkOutGb = 0.0
	}

	// IP Address and Location
	metrics.Location = c.getLocation() // Placeholder

	// Filesystem Information
	metrics.FilesystemInfo = c.getFilesystemInfo()

	// Block Devices
	metrics.BlockDevices = c.getBlockDevices()

	return metrics, nil
}

// getNetworkStatsMbps returns network rates in Mbps (safe values that won't overflow)
// Since we don't track deltas over time, we return 0 to avoid massive cumulative values
func (c *Collector) getNetworkStatsGbps() (totalRxGB, totalTxGB float64, err error) {
	// Get aggregate stats for ALL interfaces
	stats, err := net.IOCounters(false) // false = sum of all interfaces
	if err != nil {
		return 0, 0, err
	}

	if len(stats) == 0 {
		return 0, 0, fmt.Errorf("no network interfaces found")
	}

	// Convert bytes to gigabytes (1 GB = 1024³ bytes)
	totalRxGB = float64(stats[0].BytesRecv) / bytesPerGB
	totalTxGB = float64(stats[0].BytesSent) / bytesPerGB

	return totalRxGB, totalTxGB, nil
}

// getLocation returns basic location information (placeholder)
func (c *Collector) getLocation() string {
	return defaultLocation // Would integrate with GeoIP service
}

// getFilesystemInfo returns information about mounted filesystems
// Only includes important persistent filesystems (whitelist approach)
func (c *Collector) getFilesystemInfo() []types.FilesystemInfo {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return []types.FilesystemInfo{}
	}

	var filesystems []types.FilesystemInfo
	for _, partition := range partitions {
		// Only include whitelisted filesystem types
		if !isAllowedFilesystemType(partition.Fstype) {
			continue
		}

		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			continue
		}

		fs := types.FilesystemInfo{
			Mountpoint:   partition.Mountpoint,
			Fstype:       partition.Fstype,
			Total:        usage.Total,
			Used:         usage.Used,
			Free:         usage.Free,
			UsagePercent: round2(usage.UsedPercent),
		}
		filesystems = append(filesystems, fs)
	}

	return filesystems
}

// getBlockDevices returns information about block devices
// Includes physical and virtual block devices (whitelist approach)
func (c *Collector) getBlockDevices() []types.BlockDevice {
	partitions, err := disk.Partitions(true)
	if err != nil {
		return []types.BlockDevice{}
	}

	var devices []types.BlockDevice
	deviceMap := make(map[string]bool)

	for _, partition := range partitions {
		if !isAllowedBlockDevice(partition.Device) {
			continue
		}

		deviceName := partition.Device
		if !deviceMap[deviceName] {
			deviceMap[deviceName] = true

			device := types.BlockDevice{
				Name:         deviceName,
				Model:        "unknown",
				Size:         0,
				SerialNumber: "unknown",
			}
			devices = append(devices, device)
		}
	}

	return devices
}

// IngestMetrics sends system metrics to NannyAPI /api/agent endpoint
// agentID is required for upsert operation - metrics will be updated for same agent
func (c *Collector) IngestMetrics(agentID string, authManager interface {
	AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}, systemMetrics *types.SystemMetrics) error {
	logging.Debug("Ingesting metrics for agent %s", agentID)

	// Convert SystemMetrics to NannyAPISystemMetrics format
	pbMetrics := c.convertSystemMetrics(systemMetrics)

	// Create the ingest request payload with agent_id for upsert
	payload := types.IngestMetricsRequest{
		Action:        nannyapi.ActionIngestMetrics,
		SystemMetrics: pbMetrics,
		// Populate agent metadata updates
		OSInfo:         systemMetrics.Platform,
		OSVersion:      systemMetrics.PlatformVersion,
		OSType:         systemMetrics.OSType,
		PlatformFamily: systemMetrics.PlatformFamily, // Required for patch management
		Version:        c.agentVersion,
		PrimaryIP:      systemMetrics.IPAddress,
		KernelVersion:  systemMetrics.KernelVersion,
		Arch:           systemMetrics.KernelArch,
		AllIPs:         systemMetrics.AllIPs,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics payload: %w", err)
	}

	// Send request to NannyAPI /api/agent endpoint with authorization
	url := c.apiBaseURL + nannyapi.EndpointAgent

	statusCode, body, err := authManager.AuthenticatedRequest("POST", url, jsonData, nil)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	// Check for authorization errors
	if statusCode == http.StatusUnauthorized {
		return fmt.Errorf("metrics ingestion failed: unauthorized - token may be expired")
	}

	// Check for other errors
	if statusCode != http.StatusOK && statusCode != http.StatusCreated && statusCode != http.StatusNoContent {
		return fmt.Errorf("metrics ingestion failed with status %d: %s", statusCode, string(body))
	}

	// Parse response
	var metricsResp types.IngestMetricsResponse
	if err := json.Unmarshal(body, &metricsResp); err != nil {
		// If response doesn't parse as IngestMetricsResponse, check for generic error
		logging.Warning("Could not parse metrics response: %v", err)
		// Still consider it a success if status was OK
		if statusCode == http.StatusOK || statusCode == http.StatusCreated {
			logging.Debug("Metrics ingested successfully (unparsed response)")
			return nil
		}
		// If status is not OK and response didn't parse, it's an error
		return fmt.Errorf("metrics ingestion failed with status %d: invalid response format", statusCode)
	}

	if !metricsResp.Success {
		logging.Warning("Metrics ingestion response: %s", metricsResp.Message)
		return fmt.Errorf("metrics ingestion failed: %s", metricsResp.Message)
	}

	logging.Debug("Metrics ingested successfully for agent %s", agentID)
	return nil
}

// convertSystemMetrics converts internal SystemMetrics to NannyAPI format
func (c *Collector) convertSystemMetrics(systemMetrics *types.SystemMetrics) types.NannyAgentSystemMetrics {
	// Convert filesystems to NannyAPI format
	filesystems := c.convertFilesystems(systemMetrics.FilesystemInfo)

	// Calculate memory percentage
	memoryPercent := calculateUsagePercent(systemMetrics.MemoryUsed, systemMetrics.MemoryTotal)

	// Calculate disk usage percentage
	diskUsagePercent := calculateUsagePercent(systemMetrics.DiskUsed, systemMetrics.DiskTotal)

	// Convert memory from bytes to GB
	memoryUsedGB := bytesToGB(systemMetrics.MemoryUsed)
	memoryTotalGB := bytesToGB(systemMetrics.MemoryTotal)
	diskUsedGB := bytesToGB(systemMetrics.DiskUsed)
	diskTotalGB := bytesToGB(systemMetrics.DiskTotal)

	return types.NannyAgentSystemMetrics{
		CPUPercent:       round2(systemMetrics.CPUUsage),
		CPUCores:         systemMetrics.CPUCores,
		MemoryUsedGB:     memoryUsedGB,
		MemoryTotalGB:    memoryTotalGB,
		MemoryPercent:    memoryPercent,
		DiskUsedGB:       diskUsedGB,
		DiskTotalGB:      diskTotalGB,
		DiskUsagePercent: diskUsagePercent,
		Filesystems:      filesystems,
		LoadAverage: types.LoadAverage{
			OneMin:     round2(systemMetrics.LoadAvg1),
			FiveMin:    round2(systemMetrics.LoadAvg5),
			FifteenMin: round2(systemMetrics.LoadAvg15),
		},
		NetworkStats: types.NetworkStats{
			InGB:  systemMetrics.NetworkInGb,
			OutGB: systemMetrics.NetworkOutGb,
		},
		KernelVersion: systemMetrics.KernelVersion,
	}
}

// convertFilesystems converts filesystem info to NannyAPI format
func (c *Collector) convertFilesystems(filesystemInfo []types.FilesystemInfo) []types.FilesystemStats {
	if len(filesystemInfo) == 0 {
		return []types.FilesystemStats{}
	}

	filesystems := make([]types.FilesystemStats, 0, len(filesystemInfo))
	for _, fs := range filesystemInfo {
		filesystems = append(filesystems, types.FilesystemStats{
			Device:       fs.Device,
			MountPath:    fs.Mountpoint,
			UsedGB:       bytesToGB(fs.Used),
			FreeGB:       bytesToGB(fs.Free),
			TotalGB:      bytesToGB(fs.Total),
			UsagePercent: round2(fs.UsagePercent),
		})
	}

	return filesystems
}

// safeCastUint64 caps uint64 values to prevent database numeric overflow
// PostgreSQL numeric can handle very large numbers, but we cap at 2^53-1 for JSON safety
func safeCastUint64(val uint64) uint64 {
	if val > maxSafeJSONInt {
		return maxSafeJSONInt
	}
	return val
}

func round2(value float64) float64 {
	return math.Round(value*roundScale) / roundScale
}

func bytesToMB(value uint64) float64 {
	return round2(float64(value) / bytesPerMB)
}

func bytesToGB(value uint64) float64 {
	return round2(float64(value) / bytesPerGB)
}

func calculateUsagePercent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}

	return round2((float64(used) / float64(total)) * 100)
}

func isAllowedFilesystemType(fsType string) bool {
	_, ok := allowedFilesystemTypes[fsType]
	return ok
}

func isAllowedBlockDevice(device string) bool {
	if !strings.HasPrefix(device, "/dev/") {
		return false
	}

	for _, prefix := range allowedBlockDevicePrefixes {
		if strings.HasPrefix(device, prefix) {
			return true
		}
	}

	return false
}

// Computes load average
type Loadavg struct {
	LoadAverage1     float64
	LoadAverage5     float64
	LoadAverage10    float64
	RunningProcesses int
	TotalProcesses   int
	LastProcessId    int
}

func LoadAvgParse() (*Loadavg, error) {
	switch runtime.GOOS {
	case "linux":
		return parse_linux()
	default:
		return nil, errors.New("loadavg unimplemented on " + runtime.GOOS)
	}
}

func parse_linux() (*Loadavg, error) {
	self := new(Loadavg)

	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return self, err
	}

	_, err = fmt.Sscanf(string(raw), "%f %f %f %d/%d %d",
		&self.LoadAverage1, &self.LoadAverage5, &self.LoadAverage10,
		&self.RunningProcesses, &self.TotalProcesses,
		&self.LastProcessId)

	if err != nil {
		return self, err
	}

	return self, nil
}
