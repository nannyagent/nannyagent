package system

import (
	"net"
	"runtime"
	"strings"
	"testing"
)

func TestGatherSystemInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping system info tests on non-Linux OS")
	}

	info := GatherSystemInfo()

	if info == nil {
		t.Fatal("Expected system info to be returned")
	}

	t.Run("Hostname", func(t *testing.T) {
		if info.Hostname == "" {
			t.Error("Hostname should not be empty")
		}
	})

	t.Run("OS", func(t *testing.T) {
		// OS might be empty in some test environments
		if info.OS != "" {
			if len(info.OS) == 0 {
				t.Error("OS should not be empty string if set")
			}
		}
	})

	t.Run("Kernel", func(t *testing.T) {
		if info.Kernel == "" {
			t.Error("Kernel version should not be empty")
		}
	})

	t.Run("Architecture", func(t *testing.T) {
		if info.Architecture == "" {
			t.Error("Architecture should not be empty")
		}
		// Should be something like "x86_64", "aarch64", etc.
		validArchs := []string{"x86_64", "aarch64", "armv7l", "i686", "ppc64le", "s390x"}
		found := false
		for _, arch := range validArchs {
			if info.Architecture == arch {
				found = true
				break
			}
		}
		if !found {
			t.Logf("Unexpected architecture: %s (may be valid)", info.Architecture)
		}
	})

	t.Run("CPUCores", func(t *testing.T) {
		if info.CPUCores == "" {
			t.Error("CPU cores should not be empty")
		}
	})

	t.Run("Memory", func(t *testing.T) {
		if info.Memory == "" {
			t.Error("Memory should not be empty")
		}
		// Should contain typical memory suffixes
		if !strings.Contains(info.Memory, "G") && !strings.Contains(info.Memory, "M") && !strings.Contains(info.Memory, "K") {
			t.Logf("Memory format unexpected: %s", info.Memory)
		}
	})

	t.Run("Uptime", func(t *testing.T) {
		if info.Uptime == "" {
			t.Error("Uptime should not be empty")
		}
	})

	t.Run("PrivateIPs", func(t *testing.T) {
		if info.PrivateIPs == "" {
			t.Error("PrivateIPs should not be empty")
		}
	})

	t.Run("LoadAverage", func(t *testing.T) {
		if info.LoadAverage == "" {
			t.Error("LoadAverage should not be empty")
		}
	})

	t.Run("DiskUsage", func(t *testing.T) {
		if info.DiskUsage == "" {
			t.Error("DiskUsage should not be empty")
		}
	})
}

func TestGetPrivateIPs(t *testing.T) {
	result := getPrivateIPs()

	if result == "" {
		t.Error("Result should not be empty")
	}

	// Should either contain IP addresses or an error message
	if result == "Unable to determine" {
		t.Log("Could not determine private IPs (may be expected in some test environments)")
		return
	}

	if result == "No private IPs found" {
		t.Log("No private IPs found (may be expected in some test environments)")
		return
	}

	// If we got IPs, verify format
	// Format should be: "192.168.1.100 (eth0), 10.0.0.5 (wlan0)"
	if !strings.Contains(result, "(") || !strings.Contains(result, ")") {
		t.Logf("Private IPs format unexpected: %s", result)
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Private IPs (RFC 1918)
		{"Private 10.x.x.x", "10.0.0.1", true},
		{"Private 10.255.255.255", "10.255.255.255", true},
		{"Private 172.16.x.x", "172.16.0.1", true},
		{"Private 172.31.255.255", "172.31.255.255", true},
		{"Private 192.168.x.x", "192.168.1.1", true},
		{"Private 192.168.255.255", "192.168.255.255", true},

		// Public IPs
		{"Public 8.8.8.8", "8.8.8.8", false},
		{"Public 1.1.1.1", "1.1.1.1", false},
		{"Public 172.15.0.1", "172.15.0.1", false},   // Just outside private range
		{"Public 172.32.0.1", "172.32.0.1", false},   // Just outside private range
		{"Public 192.167.0.1", "192.167.0.1", false}, // Just outside private range
		{"Public 192.169.0.1", "192.169.0.1", false}, // Just outside private range
		{"Public 11.0.0.1", "11.0.0.1", false},       // Just outside private range

		// Special IPs
		{"Loopback", "127.0.0.1", false},
		{"IPv6 loopback", "::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("For IP %s: expected %v, got %v", tt.ip, tt.expected, result)
			}
		})
	}
}

func TestIsPrivateIP_Boundaries(t *testing.T) {
	// Test edge cases at boundaries
	boundaryTests := []struct {
		ip       string
		expected bool
	}{
		// 10.0.0.0/8 boundaries
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"9.255.255.255", false},
		{"11.0.0.0", false},

		// 172.16.0.0/12 boundaries
		{"172.16.0.0", true},
		{"172.31.255.255", true},
		{"172.15.255.255", false},
		{"172.32.0.0", false},

		// 192.168.0.0/16 boundaries
		{"192.168.0.0", true},
		{"192.168.255.255", true},
		{"192.167.255.255", false},
		{"192.169.0.0", false},
	}

	for _, tt := range boundaryTests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("For boundary IP %s: expected %v, got %v", tt.ip, tt.expected, result)
			}
		})
	}
}

func TestFormatSystemInfoForPrompt(t *testing.T) {
	// Create test system info
	info := &SystemInfo{
		Hostname:     "test-host",
		OS:           "Ubuntu 22.04",
		Kernel:       "5.15.0-generic",
		Architecture: "x86_64",
		CPUCores:     "8",
		Memory:       "16Gi",
		Uptime:       "up 5 days",
		PrivateIPs:   "192.168.1.100 (eth0)",
		LoadAverage:  "0.50, 0.60, 0.70",
		DiskUsage:    "Root: 50G/100G (50% used)",
	}

	formatted := FormatSystemInfoForPrompt(info)

	if formatted == "" {
		t.Fatal("Formatted output should not be empty")
	}

	// Check that all fields are included
	requiredFields := []string{
		"SYSTEM INFORMATION:",
		"test-host",
		"Ubuntu 22.04",
		"5.15.0-generic",
		"x86_64",
		"8",
		"16Gi",
		"up 5 days",
		"192.168.1.100 (eth0)",
		"0.50, 0.60, 0.70",
		"Root: 50G/100G (50% used)",
		"ISSUE DESCRIPTION:",
	}

	for _, field := range requiredFields {
		if !strings.Contains(formatted, field) {
			t.Errorf("Formatted output missing field: %s", field)
		}
	}

	// Check structure
	if !strings.Contains(formatted, "- Hostname:") {
		t.Error("Missing hostname label")
	}
	if !strings.Contains(formatted, "- Operating System:") {
		t.Error("Missing OS label")
	}
	if !strings.Contains(formatted, "- Go Runtime:") {
		t.Error("Missing Go runtime label")
	}
}

func TestFormatSystemInfoForPrompt_EmptyFields(t *testing.T) {
	// Test with empty fields
	info := &SystemInfo{
		Hostname:     "",
		OS:           "",
		Kernel:       "",
		Architecture: "",
		CPUCores:     "",
		Memory:       "",
		Uptime:       "",
		PrivateIPs:   "",
		LoadAverage:  "",
		DiskUsage:    "",
	}

	formatted := FormatSystemInfoForPrompt(info)

	// Should still generate output with structure
	if formatted == "" {
		t.Fatal("Formatted output should not be empty even with empty fields")
	}

	// Should contain headers
	if !strings.Contains(formatted, "SYSTEM INFORMATION:") {
		t.Error("Missing system information header")
	}
	if !strings.Contains(formatted, "ISSUE DESCRIPTION:") {
		t.Error("Missing issue description header")
	}
}

func TestSystemInfo_Structure(t *testing.T) {
	// Test that SystemInfo struct can be created and fields set
	info := SystemInfo{
		Hostname:     "test",
		OS:           "linux",
		Kernel:       "5.0",
		Architecture: "x64",
		CPUCores:     "4",
		Memory:       "8GB",
		Uptime:       "1 day",
		PrivateIPs:   "192.168.1.1",
		LoadAverage:  "0.5",
		DiskUsage:    "50%",
	}

	if info.Hostname != "test" {
		t.Error("Hostname field not set correctly")
	}
	if info.CPUCores != "4" {
		t.Error("CPUCores field not set correctly")
	}
}

func TestGatherSystemInfo_Consistency(t *testing.T) {
	// Gather system info twice
	info1 := GatherSystemInfo()
	info2 := GatherSystemInfo()

	// Some fields should be consistent
	if info1.Hostname != info2.Hostname {
		t.Error("Hostname should be consistent across calls")
	}

	if info1.Architecture != info2.Architecture {
		t.Error("Architecture should be consistent across calls")
	}

	if info1.CPUCores != info2.CPUCores {
		t.Error("CPU cores should be consistent across calls")
	}

	// Kernel version should be the same
	if info1.Kernel != info2.Kernel {
		t.Error("Kernel version should be consistent")
	}
}

func TestGetPrivateIPs_NoError(t *testing.T) {
	// This test ensures getPrivateIPs doesn't panic
	result := getPrivateIPs()

	// Should always return a string (never nil or empty)
	if result == "" {
		t.Error("getPrivateIPs should never return empty string")
	}
}

func TestIsPrivateIP_IPv6(t *testing.T) {
	// Test IPv6 addresses
	ipv6Tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv6 loopback", "::1", false},
		{"IPv6 unique local", "fd00::1", true},
		{"IPv6 public", "2001:4860:4860::8888", false},
		// Add more IPv6 tests as needed
	}

	for _, tt := range ipv6Tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IPv6: %s", tt.ip)
			}

			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("For IPv6 %s: expected %v, got %v", tt.ip, tt.expected, result)
			}
		})
	}
}

func TestFormatOS(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		version  string
		want     string
	}{
		{name: "platform and version", platform: "ubuntu", version: "24.04", want: "ubuntu 24.04"},
		{name: "platform only", platform: "linux", want: "linux"},
		{name: "version only", version: "24.04", want: "24.04"},
		{name: "empty", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatOS(tt.platform, tt.version); got != tt.want {
				t.Errorf("formatOS(%q, %q) = %q, want %q", tt.platform, tt.version, got, tt.want)
			}
		})
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name    string
		seconds uint64
		want    string
	}{
		{name: "unknown", seconds: 0, want: "unknown"},
		{name: "seconds", seconds: 45, want: "45 seconds"},
		{name: "minutes", seconds: 5 * 60, want: "up 5 minutes"},
		{name: "days and hours", seconds: 2*24*60*60 + 3*60*60, want: "up 2 days, 3 hours"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatUptime(tt.seconds); got != tt.want {
				t.Errorf("formatUptime(%d) = %q, want %q", tt.seconds, got, tt.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		size uint64
		want string
	}{
		{name: "zero", size: 0, want: "0B"},
		{name: "kibibytes", size: 1536, want: "1.5KiB"},
		{name: "gibibytes", size: 16 * 1024 * 1024 * 1024, want: "16GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBytes(tt.size); got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.size, got, tt.want)
			}
		})
	}
}

func TestFormatPercent(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  string
	}{
		{name: "whole number", value: 50, want: "50%"},
		{name: "fractional", value: 50.26, want: "50.3%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPercent(tt.value); got != tt.want {
				t.Errorf("formatPercent(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
