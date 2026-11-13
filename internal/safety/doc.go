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
}
