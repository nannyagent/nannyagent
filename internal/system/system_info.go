package system

import (
	"fmt"
	"math"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"

	"nannyagent/internal/hostinfo"
)

// SystemInfo represents basic system information
type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	CPUCores     string `json:"cpu_cores"`
	Memory       string `json:"memory"`
	Uptime       string `json:"uptime"`
	PrivateIPs   string `json:"private_ips"`
	LoadAverage  string `json:"load_average"`
	DiskUsage    string `json:"disk_usage"`
}

// GatherSystemInfo collects basic system information
func GatherSystemInfo() *SystemInfo {
	metadata := hostinfo.Collect()
	info := &SystemInfo{
		Hostname:     metadata.Hostname,
		OS:           metadata.Platform,
		Kernel:       metadata.KernelVersion,
		Architecture: runtime.GOARCH,
		CPUCores:     strconv.Itoa(runtime.NumCPU()),
		Memory:       "unknown",
		Uptime:       "unknown",
		PrivateIPs:   getPrivateIPs(),
		LoadAverage:  "unknown",
		DiskUsage:    "unknown",
	}

	if hostInfo, err := host.Info(); err == nil {
		if hostInfo.Hostname != "" {
			info.Hostname = hostInfo.Hostname
		}
		if description := formatOS(hostInfo.Platform, hostInfo.PlatformVersion); description != "" {
			info.OS = description
		}
		if hostInfo.KernelVersion != "" {
			info.Kernel = hostInfo.KernelVersion
		}
		if hostInfo.KernelArch != "" {
			info.Architecture = hostInfo.KernelArch
		}
		if hostInfo.Uptime > 0 {
			info.Uptime = formatUptime(hostInfo.Uptime)
		}
	}

	if virtualMemory, err := mem.VirtualMemory(); err == nil && virtualMemory.Total > 0 {
		info.Memory = formatBytes(virtualMemory.Total)
	}

	if averages, err := load.Avg(); err == nil {
		info.LoadAverage = fmt.Sprintf("%.2f, %.2f, %.2f", averages.Load1, averages.Load5, averages.Load15)
	}

	if usage, err := disk.Usage("/"); err == nil && usage.Total > 0 {
		info.DiskUsage = fmt.Sprintf("Root: %s/%s (%s used)", formatBytes(usage.Used), formatBytes(usage.Total), formatPercent(usage.UsedPercent))
	}

	return info
}

func formatOS(platform, version string) string {
	platform = strings.TrimSpace(platform)
	version = strings.TrimSpace(version)

	switch {
	case platform == "" && version == "":
		return ""
	case platform == "":
		return version
	case version == "":
		return platform
	default:
		return platform + " " + version
	}
}

func formatUptime(seconds uint64) string {
	if seconds == 0 {
		return "unknown"
	}

	units := []struct {
		name  string
		value uint64
	}{
		{name: "day", value: 24 * 60 * 60},
		{name: "hour", value: 60 * 60},
		{name: "minute", value: 60},
	}

	remaining := seconds
	parts := make([]string, 0, 2)
	for _, unit := range units {
		if remaining < unit.value {
			continue
		}
		count := remaining / unit.value
		remaining %= unit.value
		parts = append(parts, pluralize(count, unit.name))
		if len(parts) == 2 {
			break
		}
	}

	if len(parts) == 0 {
		return pluralize(seconds, "second")
	}

	return "up " + strings.Join(parts, ", ")
}

func pluralize(value uint64, singular string) string {
	if value == 1 {
		return fmt.Sprintf("%d %s", value, singular)
	}
	return fmt.Sprintf("%d %ss", value, singular)
}

func formatBytes(size uint64) string {
	if size == 0 {
		return "0B"
	}

	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	value := float64(size)
	unitIndex := 0
	for value >= 1024 && unitIndex < len(units)-1 {
		value /= 1024
		unitIndex++
	}

	precision := 0
	if unitIndex > 0 && value < 10 {
		precision = 1
	}

	return fmt.Sprintf("%.*f%s", precision, value, units[unitIndex])
}

func formatPercent(value float64) string {
	rounded := math.Round(value*10) / 10
	if rounded == math.Trunc(rounded) {
		return fmt.Sprintf("%.0f%%", rounded)
	}
	return fmt.Sprintf("%.1f%%", rounded)
}

// getPrivateIPs returns private IP addresses
func getPrivateIPs() string {
	var privateIPs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return "Unable to determine"
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if isPrivateIP(ipnet.IP) {
					privateIPs = append(privateIPs, fmt.Sprintf("%s (%s)", ipnet.IP.String(), iface.Name))
				}
			}
		}
	}

	sort.Strings(privateIPs)

	if len(privateIPs) == 0 {
		return "No private IPs found"
	}

	return strings.Join(privateIPs, ", ")
}

// isPrivateIP checks if an IP address is private
func isPrivateIP(ip net.IP) bool {
	return ip != nil && ip.IsPrivate()
}

// FormatSystemInfoForPrompt formats system information for inclusion in diagnostic prompts
func FormatSystemInfoForPrompt(info *SystemInfo) string {
	return fmt.Sprintf(`SYSTEM INFORMATION:
- Hostname: %s
- Operating System: %s
- Kernel Version: %s
- Architecture: %s
- CPU Cores: %s
- Total Memory: %s
- System Uptime: %s
- Current Load Average: %s
- Root Disk Usage: %s
- Private IP Addresses: %s
- Go Runtime: %s

ISSUE DESCRIPTION:`,
		info.Hostname,
		info.OS,
		info.Kernel,
		info.Architecture,
		info.CPUCores,
		info.Memory,
		info.Uptime,
		info.LoadAverage,
		info.DiskUsage,
		info.PrivateIPs,
		runtime.Version())
}
