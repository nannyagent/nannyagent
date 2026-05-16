package safety

var AllowedExecUses = map[string]map[string]bool{
	"main.go": {
		"LookPath": true,
	},
	"internal/ebpf/ebpf_trace_manager.go": {
		"CommandContext": true,
		"Cmd":            true,
		"LookPath":       true,
	},
	"internal/executor/executor.go": {
		"CommandContext": true,
		"ExitError":      true,
	},
	"internal/app/runtime.go": {
		"Command":  true,
		"LookPath": true,
	},
	"internal/patches/patch_manager.go": {
		"Cmd":       true,
		"Command":   true,
		"ExitError": true,
	},
	"internal/proxmox/collector.go": {
		"Command": true,
	},
	"internal/reboot/reboot_manager.go": {
		"Command": true,
	},
	"internal/patches/patch_manager_lxc_test.go": {
		"Cmd":     true,
		"Command": true,
	},
	"internal/reboot/reboot_manager_test.go": {
		"Cmd":     true,
		"Command": true,
	},
}
