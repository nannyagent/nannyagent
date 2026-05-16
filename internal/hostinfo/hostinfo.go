package hostinfo

import (
	"net"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v3/host"
)

const unknownValue = "unknown"

type Metadata struct {
	Hostname       string
	Platform       string
	PlatformFamily string
	KernelVersion  string
	PrimaryIP      string
	AllIPs         []string
}

func Collect() Metadata {
	primaryIP, allIPs := IPAddresses()

	return Metadata{
		Hostname:       Hostname(),
		Platform:       Platform(),
		PlatformFamily: PlatformFamily(),
		KernelVersion:  KernelVersion(),
		PrimaryIP:      primaryIP,
		AllIPs:         allIPs,
	}
}

func Hostname() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return unknownValue
}

func Platform() string {
	if platform := strings.TrimSpace(os.Getenv("GOOS")); platform != "" {
		return platform
	}
	if runtime.GOOS != "" {
		return runtime.GOOS
	}
	return unknownValue
}

func PlatformFamily() string {
	platform, family, _, err := host.PlatformInformation()
	if err != nil {
		return unknownValue
	}
	if family == "" {
		if platform == "" {
			return unknownValue
		}
		return platform
	}
	return family
}

func KernelVersion() string {
	version, err := host.KernelVersion()
	if err != nil || version == "" {
		return unknownValue
	}
	return version
}

func IPAddresses() (string, []string) {
	var primaryIP string
	var allIPs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return unknownValue, []string{}
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip := extractIP(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}

			ipStr := ip.String()
			allIPs = append(allIPs, ipStr)
			if primaryIP == "" && ip.To4() != nil {
				primaryIP = ipStr
			}
		}
	}

	if len(allIPs) == 0 {
		return unknownValue, []string{}
	}

	sort.Strings(allIPs)
	if primaryIP == "" {
		primaryIP = allIPs[0]
	}

	return primaryIP, allIPs
}

func extractIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}
