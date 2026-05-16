# NannyAgent - AI-Powered Linux Diagnostic Agent

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <p><em>Deep kernel-level diagnostics powered by eBPF and AI</em></p>
</div>

A sophisticated Go-based agent that combines AI-powered diagnostics with eBPF kernel monitoring for comprehensive Linux system analysis.

## Features

- **AI-Powered Diagnostics** - Intelligent issue analysis and resolution planning
- **eBPF Deep Monitoring** - Real-time kernel-level tracing (network, processes, files, I/O)
- **Safe Command Execution** - Validated execution with timeouts and security checks (no changes made to the system)
- **System Metrics Collection** - Comprehensive CPU, memory, disk, network metrics every 30s
- **Proxmox Integration** - Automatic cluster, node, LXC, and QEMU-VM ingestion
- **Realtime Communication** - Server-Sent Events for instant investigation dispatch
- **Patch Management** - Update OS & system packages of both hosts & LXCs (including scheduling)
- **OAuth Device Flow** - Secure agent registration and authentication
- **Comprehensive Testing** - Unit tests and integration tests for all components

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- **[Installation Guide](docs/INSTALLATION.md)** - Installation steps, system requirements, and troubleshooting
- **[Configuration Guide](docs/CONFIGURATION.md)** - Configuration options and environment variables
- **[Architecture](docs/ARCHITECTURE.md)** - System design, components, and data flows
- **[API Integration](docs/API_INTEGRATION.md)** - REST API, SSE, OAuth, and all backend endpoints
- **[eBPF Monitoring](docs/EBPF_MONITORING.md)** - Kernel-level tracing with bpftrace
- **[Proxmox Integration](docs/PROXMOX_INTEGRATION.md)** - Cluster, node, LXC, QEMU info ingestion
- **[Contributing](CONTRIBUTORS.md)** - How to contribute to NannyAgent
- **[Security Policy](SECURITY.md)** - Security practices and vulnerability reporting

## Requirements

- **Operating System**: Linux only (no Docker/LXC containers)
- **Architecture**: amd64 (x86_64) or arm64 (aarch64)
- **Kernel Version**: Linux kernel 5.x or higher
- **Privileges**: root access required for eBPF functionality & patching
- **Dependencies**: bpftrace (automatically installed by installer)
- **Network**: Connectivity to NannyAPI backend (defaults to https://api.nannyai.dev)

## Quick Installation

### One-Line Install (Recommended)

```bash
# Download and run the installer
curl -fsSL https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

### Manual Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/nannyagent/nannyagent.git
   cd nannyagent
   ```

2. Build and install:
   ```bash
   make build
   sudo make install-system
   ```

The installer will:
- Verify system requirements (OS, architecture, kernel version)
- Check for existing installations
- Install eBPF tools (bpftrace)
- Download pre-built binary or build from source
- Install to `/usr/sbin/nannyagent`
- Create configuration `/etc/nannyagent/config.yaml`
- Create secure data directory `/var/lib/nannyagent`
- Install systemd service

## Configuration

After installation, configure the NannyAPI URL:

```bash
# Edit the configuration file
sudo nano /etc/nannyagent/config.yaml
```

Minimal configuration:

```yaml
# NannyAPI Backend URL (required)
nannyapi_url: https://api.nannyai.dev

# Portal URL for device authorization
portal_url: https://nannyai.dev

# Optional: Token storage path (default: /var/lib/nannyagent/token.json)
token_path: /var/lib/nannyagent/token.json

# Optional: Metrics collection interval in seconds (default: 30)
metrics_interval: 30

# Optional: Proxmox data collection interval in seconds (default: 300)
proxmox_interval: 300

# Optional: Debug logging (default: false)
debug: false
```

See [Configuration Guide](docs/CONFIGURATION.md) for all options.
See [Logging Guide](docs/LOGGING.md) for log levels, daemon output behavior, and repeated-failure escalation.

## Command-Line Options

```bash
# Show version
nannyagent --version
nannyagent -v

# Show help
nannyagent --help
nannyagent -h

# Run the agent
sudo nannyagent
```

## Usage

1. **First-time Setup** - Authenticate the agent:
   ```bash
   sudo nannyagent
   ```
   
   The agent will display a verification URL and code. Visit the URL and enter the code to authorize the agent.

2. **Interactive Diagnostics** - After authentication, enter system issues:
   ```
   > On /var filesystem I cannot create any file but df -h shows 30% free space available.
   ```

3. **The agent will**:
   - Gather comprehensive system information automatically
   - Send the issue to AI for analysis via TensorZero
   - Execute diagnostic commands safely
   - Run eBPF traces for deep kernel-level monitoring
   - Provide AI-generated root cause analysis and resolution plan

4. **Exit the agent**:
   ```
   > quit
   ```
   or
   ```
   > exit
   ```

## How It Works

1. **User Input**: Submit a description of the system issue you're experiencing
2. **System Info Gathering**: Agent automatically collects comprehensive system information and eBPF capabilities
3. **AI Analysis**: Sends the issue description + system info to NannyAPI for analysis
4. **Diagnostic Phase**: AI returns structured commands and eBPF monitoring requests for investigation
5. **Command Execution**: Agent safely executes diagnostic commands and runs eBPF traces in parallel
6. **eBPF Monitoring**: Real-time system tracing (network, processes, files, syscalls) provides deep insights
7. **Iterative Analysis**: Command results and eBPF trace data are sent back to AI for further analysis
8. **Resolution**: AI provides root cause analysis and step-by-step resolution plan based on comprehensive data

## Testing & Integration Tests

The agent includes comprehensive integration tests that simulate realistic Linux problems:

### Available Test Scenarios:
1. **Disk Space Issues** - Inode exhaustion scenarios
2. **Memory Problems** - OOM killer and memory pressure
3. **Network Issues** - DNS resolution problems
4. **Performance Issues** - High load averages and I/O bottlenecks
5. **Web Server Problems** - Permission and configuration issues
6. **Hardware/Boot Issues** - Kernel module and device problems
7. **Database Performance** - Slow queries and I/O contention
8. **Service Failures** - Startup and configuration problems

### Run Integration Tests:
```bash
# Run unit tests
make test

## Installation Exit Codes

The installer uses specific exit codes for different failure scenarios:

| Exit Code | Description |
|-----------|-------------|
| 0 | Success |
| 1 | Not running as root |
| 2 | Unsupported operating system (non-Linux) |
| 3 | Unsupported architecture (not amd64/arm64) |
| 4 | Container/LXC environment detected |
| 5 | Kernel version < 5.x |
| 6 | Existing installation detected |
| 7 | eBPF tools installation failed |
| 8 | Go not installed |
| 9 | Binary build failed |
| 10 | Directory creation failed |
| 11 | Binary installation failed |

## Troubleshooting

### Installation Issues

**Error: "Kernel version X.X is not supported"**
- NannyAgent requires Linux kernel 5.x or higher
- Upgrade your kernel or use a different system

**Error: "Another instance may already be installed"**
- Check if `/var/lib/nannyagent` exists
- Remove it if you're sure: `sudo rm -rf /var/lib/nannyagent` (agent removed & recreated)
- Then retry installation

**Warning: "Cannot connect to NannyAPI"**
- Check your network connectivity
- Verify firewall settings allow HTTPS connections
- Ensure nannyapi_url is correctly configured in `/etc/nannyagent/config.yaml`
- Test connectivity: `curl -I https://api.nannyai.dev`

### Runtime Issues

**Error: "This program must be run as root"**
- eBPF requires root privileges
- Always run with: `sudo nannyagent`

**Error: "Cannot determine kernel version"**
- Ensure `uname` command is available
- Check system integrity

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/nannyagent/nannyagent.git
cd nannyagent

# Install Go dependencies
go mod tidy

# Build binary
make build

# Run locally (requires sudo)
sudo ./nannyagent
```

### Running Tests

```bash
# Run unit tests
make test
```

## Safety & Security

- **Command Validation**: All commands are validated before execution
- **Read-Only Focus**: Diagnostic commands are read-only by default
- **Timeout Protection**: Commands have timeouts to prevent hanging
- **eBPF Safety**: eBPF programs are verified by kernel, read-only, and time-limited
- **Secure Token Storage**: Tokens stored with 0600 permissions in `/var/lib/nannyagent/`
- **OAuth Authentication**: OAuth 2.0 Device Flow
- **TLS/HTTPS**: All API communication over HTTPS
- **No Shell Injection**: Commands constructed safely without shell expansion
- **Patch Validation**: SHA256 hash validation before script execution
- **Root Privilege Checks**: Validated at startup with clear error messages

## System Metrics Collection

The agent automatically collects and sends comprehensive system metrics every 30 seconds:

**Metrics Collected:**
- **System**: Hostname, platform, kernel version, architecture
- **CPU**: Usage %, core count, model name
- **Memory**: Total, used, free, available, swap metrics
- **Disk**: Usage %, total/used/free space, filesystem info, block devices
- **Network**: Total RX/TX (GB), IP addresses, network interfaces
- **Load**: 1min, 5min, 15min load averages
- **Processes**: Active process count

All metrics are sent to `/api/agent` endpoint with authentication.

## Proxmox VE Monitoring

For Proxmox VE environments, the agent automatically:

1. **Detects Proxmox installation** via `/usr/bin/pveversion`
2. **Collects cluster data** every 5 minutes:
   - Cluster configuration (name, node count, quorum status)
   - Node information (status, version, resources)
   - LXC container details (config, networking, resources)
   - QEMU VM details (disks, CPU, memory, network)

Data is sent to dedicated Proxmox endpoints:
- `/api/proxmox/cluster` - Cluster information
- `/api/proxmox/node` - Node status and metrics
- `/api/proxmox/lxc` - LXC container data
- `/api/proxmox/qemu` - QEMU VM data

See [Proxmox Integration Guide](docs/PROXMOX_INTEGRATION.md) for details.

## eBPF Monitoring

Deep kernel-level monitoring using bpftrace:

**Trace Types:**
- **Tracepoints**: Stable kernel tracing (`syscalls`, `sched`, `block`, etc.)
- **Kprobes**: Dynamic function tracing (`tcp_connect`, `vfs_read`, etc.)
- **Kretprobes**: Return value monitoring

**Use Cases:**
- Network connectivity debugging (TCP connections, retransmissions)
- Disk I/O performance analysis (latency distribution)
- File access monitoring (which processes accessing what files)
- Process lifecycle tracking (creation, execution, termination)
- Memory allocation patterns
- System call frequency analysis

The AI automatically requests appropriate eBPF monitoring based on the issue type. See [eBPF Monitoring Guide](docs/EBPF_MONITORING.md) for comprehensive documentation.

## Patch Management

Secure script execution for system remediation:

**Features:**
- SHA256 validation before execution
- Dry-run mode for testing changes
- Host and LXC container execution
- Output capture (stdout/stderr)
- Package list tracking
- Automatic cleanup

**Execution Flow:**
1. Receive patch operation via SSE
2. Download script from backend
3. Validate SHA256 hash
4. Execute (dry-run or apply mode)
5. Capture results and package changes
6. Upload results to backend

## Architecture Overview

```flowchart
┌─────────────────────────────────────────────────────────┐
│                    NannyAI Platform                     │
│  (Web Portal + NannyAPI + TensorZero AI)                │
└───────────────────────┬─────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        │ Device Auth   │ REST/SSE      │ AI Inference
        │               │               │
        ▼               ▼               ▼
┌───────────────────────────────────────────────────────────┐
│                    NannyAgent                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ Core Components:                                    │  │
│  │ • Auth Manager (OAuth Device Flow)                  │  │
│  │ • Diagnostic Agent (AI orchestration)               │  │
│  │ • eBPF Trace Manager (kernel monitoring)            │  │
│  │ • Metrics Collector (system metrics)                │  │
│  │ • Proxmox Manager (infrastructure monitoring)       │  │
│  │ • Patch Manager (secure remediation)                │  │
│  │ • Realtime Client (SSE for instant dispatch)        │  │
│  │ • Investigations Client (TensorZero proxy)          │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │  Linux Kernel & System        │
        │  • eBPF (bpftrace)            │
        │  • System Metrics (gopsutil)  │
        │  • Proxmox APIs (pvesh, pct)  │
        └───────────────────────────────┘
```

For detailed architecture documentation, see [Architecture Guide](docs/ARCHITECTURE.md).

## Example Diagnostic Session

```bash
$ sudo nannyagent

[INFO] NannyAgent version 1.0.0
[INFO] Linux kernel 5.15.0-56-generic detected
[INFO] eBPF capabilities: OK
[INFO] Authenticated as agent-550e8400-e29b-41d4

Enter system issue (or 'quit' to exit):
> PostgreSQL queries are extremely slow

[INFO] Creating investigation...
[INFO] Investigation ID: inv-abc123
[INFO] Gathering system information...
[INFO] Sending to AI for analysis...

[AI DIAGNOSTIC]
Reasoning: Need to monitor disk I/O and PostgreSQL file access to identify bottleneck

Commands to execute:
1. Check PostgreSQL statistics
2. Monitor disk I/O stats

eBPF Traces to run (15 seconds):
1. disk_io_latency - Track disk I/O completion latency
2. postgres_reads - Monitor file reads by PostgreSQL

[INFO] Executing 2 commands and 2 eBPF traces in parallel...
[INFO] Command results collected
[INFO] eBPF traces completed: 1247 events captured
[INFO] Sending results to AI...

[AI RESOLUTION]
Root Cause: Slow disk I/O latency (avg 400μs) combined with high read volume 
(856 reads/15s). eBPF trace shows PostgreSQL reading multiple data files sequentially.

Resolution Plan:
1. Increase shared_buffers to reduce disk reads
2. Enable huge pages for better memory performance
3. Consider moving to faster storage (SSD)
4. Optimize queries to reduce sequential scans

Confidence: High

[INFO] Investigation completed
```

## License

See [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

---
