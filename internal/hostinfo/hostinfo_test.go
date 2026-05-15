package hostinfo

import "testing"

func TestCollect(t *testing.T) {
	metadata := Collect()

	if metadata.Hostname == "" {
		t.Fatal("hostname should not be empty")
	}
	if metadata.Platform == "" {
		t.Fatal("platform should not be empty")
	}
	if metadata.PlatformFamily == "" {
		t.Fatal("platform family should not be empty")
	}
	if metadata.KernelVersion == "" {
		t.Fatal("kernel version should not be empty")
	}
	if metadata.AllIPs == nil {
		t.Fatal("all IPs should be initialized")
	}
}

func TestIPAddresses(t *testing.T) {
	primaryIP, allIPs := IPAddresses()

	if primaryIP == "" {
		t.Fatal("primary IP should not be empty")
	}
	if allIPs == nil {
		t.Fatal("all IPs should be initialized")
	}
	for _, ip := range allIPs {
		if ip == "127.0.0.1" || ip == "::1" {
			t.Fatalf("loopback IP should be excluded: %s", ip)
		}
	}
}
