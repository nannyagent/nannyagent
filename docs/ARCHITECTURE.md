# NannyAgent Architecture

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>System Architecture & Design</h1>
</div>

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Component Interactions](#component-interactions)
- [Design Patterns](#design-patterns)

## Overview

NannyAgent is a Linux diagnostic agent built in Go that combines AI-powered diagnostics with deep eBPF kernel monitoring. It runs as a daemon on Linux hosts, providing:

- **AI-Powered Diagnostics**: Real-time issue analysis using AI APIs behind Tensorzero gateway
- **eBPF Monitoring**: Kernel-level tracing for network, processes, files, and security events
- **Metrics Collection**: Comprehensive system metrics ingestion

## System Architecture

```flowchart
┌─────────────────────────────────────────────────────────────────────┐
│                          NannyAI Platform                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │  Web Portal  │  │   NannyAPI   │  │  TensorZero AI Engine    │   │
│  │              │  │  (REST/SSE)  │  │  (Diagnostic Intelligence)│  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬──────────────┘   │
└─────────┼──────────────────┼──────────────────────┼─────────────────┘
          │                  │                      │
          │ Device Auth      │ REST API             │ AI Inference
          │                  │ Realtime SSE         │
          │                  │ Investigations       │
          └──────────────────┼──────────────────────┘
                             │
                             ▼
          ┌──────────────────────────────────────────────────────┐
          │              NannyAgent (This Component)             │
          │  ┌────────────────────────────────────────────────┐  │
          │  │           Agent Core                           │  │
          │  │  - Daemon Management                           │  │
          │  │  - Command-line Interface                      │  │
          │  │  - Lifecycle Management                        │  │
          │  └─────────────────┬──────────────────────────────┘  │
          │                    │                                 │
          │  ┌─────────────────┴──────────────────────────────┐  │
          │  │                                                │  │
┌─────────┼──▼─────────┬──────────┬──────────┬────────────────┼──┼─────────┐
│         │  Auth      │  Config  │  Logging │  System Info   │  │         │
│         │  Manager   │  Manager │  Manager │  Collector     │  │         │
│         └────────────┴──────────┴──────────┴────────────────┘  │         │
│                                                                │         │
│  ┌──────────────────────────────────────────────────────────┐  │         │
│  │              Diagnostic Agent                            │  │         │
│  │  - AI Conversation Management                            │  │         │
│  │  - Investigation Lifecycle                               │  │         │
│  │  - Command Execution Orchestration                       │  │         │
│  └──────────┬───────────────────────────────────────────────┘  │         │
│             │                                                  │         │
│  ┌──────────┴───────────────────────────────────────────────┐  │         │
│  │                                                          │  │         │
│  ▼                    ▼                  ▼                  ▼  │         │
│ ┌────────────┐  ┌──────────┐  ┌─────────────┐  ┌──────────┐    │         │
│ │  eBPF      │  │ Command  │  │Investigations│ │ Realtime │    │         │
│ │  Trace     │  │ Executor │  │   Client     │ │  Client  │    │         │
│ │  Manager   │  │          │  │              │ │  (SSE)   │    │         │
│ └────────────┘  └──────────┘  └─────────────┘  └──────────┘    │         │
│                                                                │         │
│  ┌──────────────┐                                             │         │
│  │   Metrics    │                                             │         │
│  │  Collector   │                                             │         │
│  └──────────────┘                                             │         │
└─────────────────────────────────────────────────────────────────────────-┘
                             │
                             ▼
          ┌──────────────────────────────────────────────────────┐
          │              Linux Kernel & System                   │
          │  - eBPF Subsystem (bpftrace)                         │
          │  - System Metrics (gopsutil)                         │
          └──────────────────────────────────────────────────────┘
```

## Core Components

### 1. Agent Core

The entry point and orchestrator of the entire agent.

**Responsibilities:**
- CLI argument parsing (`--register`, `--status`, `--diagnose`, `--daemon`)
- System requirements validation (root privileges, kernel version >= 5.x)
- eBPF capability checks
- Component initialization and lifecycle management
- Interactive mode for diagnostics

### 2. Authentication Manager

Implements OAuth 2.0 Device Flow for secure agent registration.

**Responsibilities:**
- Device code generation and user authorization
- Agent registration with backend
- Token management (access/refresh tokens)
- Automatic token refresh with exponential backoff
- Authenticated HTTP request handling

**Flow:**
```flowchart
┌────────────┐                ┌────────────┐                ┌────────────┐
│   Agent    │                │  NannyAPI  │                │   Portal   │
└──────┬─────┘                └──────┬─────┘                └──────┬─────┘
       │                             │                             │
       │ 1. Request device code      │                             │
       ├────────────────────────────>│                             │
       │ 2. device_code + user_code  │                             │
       │<────────────────────────────┤                             │
       │                             │                             │
       │ 3. Display user_code        │                             │
       │                             │                             │
       │                             │ 4. User visits portal       │
       │                             │    & enters user_code       │
       │                             │<────────────────────────────┤
       │                             │ 5. Authorize device         │
       │                             │────────────────────────────>│
       │                             │                             │
       │ 6. Poll for token           │                             │
       ├────────────────────────────>│                             │
       │ 7. access_token +           │                             │
       │    refresh_token + agent_id │                             │
       │<────────────────────────────┤                             │
       │                             │                             │
       │ 8. Store token              │                             │
       │                             │                             │
```

### 3. Configuration Manager

Centralized configuration management with environment variable overrides.

**Configuration Hierarchy:**
1. `/etc/nannyagent/config.yaml` (lowest priority)
2. Environment variables (highest priority)

**Required Settings:**
- `NANNYAPI_URL`: Backend API endpoint
- `NANNYAI_PORTAL_URL`: Portal URL for device authorization (default: `https://nannyai.dev`)

**Optional Settings:**
- `TOKEN_PATH`: Token storage location (default: `/var/lib/nannyagent/token.json`)
- `DEBUG`: Enable debug logging
- `METRICS_INTERVAL`: Metrics collection interval (default: 30s)

### 4. Diagnostic Agent

The brain of the diagnostic system that orchestrates AI-powered issue resolution.

**Key Features:**
- Conversation state management (episode IDs)
- Investigation lifecycle tracking
- Parallel command and eBPF trace execution
- Response parsing and validation
- Iterative diagnostic loops

**Agent Workflow:**
```flowchart
┌──────────────────────────────────────────────────────────────────┐
│ 1. User Input: "PostgreSQL is slow"                              │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. Gather System Information                                     │
│    - OS info, kernel version, architecture                       │
│    - CPU, memory, disk metrics                                   │
│    - Network configuration                                       │
│    - eBPF capabilities                                           │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. Create Investigation (POST /api/investigations)               │
│    - Returns investigation_id                                    │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. Send to TensorZero AI (via /api/investigations)               │
│    Request:                                                      │
│    {                                                             │
│      "model": "tensorzero::function_name::diagnose_and_heal",    │
│      "messages": [                                               │
│        {                                                         │
│          "role": "user",                                         │
│          "content": "<system_info>\n<issue>"                     │
│        }                                                         │
│      ],                                                          │
│      "investigation_id": "<uuid>"                                │
│    }                                                             │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. AI Response (Diagnostic Phase)                                │
│    {                                                             │
│      "response_type": "diagnostic",                              │
│      "reasoning": "Need to check disk I/O and query patterns",   │
│      "commands": [                                               │
│        {                                                         │
│          "id": "pg_stats",                                       │
│          "command": "psql -c 'SELECT * FROM pg_stat_database'",  │
│          "description": "Check PostgreSQL stats"                 │
│        }                                                         │
│      ],                                                          │
│      "ebpf_programs": [                                          │
│        {                                                         │
│          "name": "disk_io_trace",                                │
│          "type": "tracepoint",                                   │
│          "target": "block:block_rq_complete",                    │
│          "duration": 15                                          │
│        }                                                         │
│      ]                                                           │
│    }                                                             │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. Execute Commands & eBPF Traces (Parallel)                     │
│    - Fork command executor goroutines                            │
│    - Start eBPF traces via bpftrace                              │
│    - Collect all outputs                                         │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 7. Send Results Back to AI                                       │
│    {                                                             │
│      "role": "user",                                             │
│      "content": {                                                │
│        "commands": [...results...],                              │
│        "ebpf_traces": [...events...]                             │
│      }                                                           │
│    }                                                             │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 8. AI Response (Resolution Phase)                                 │
│    {                                                              │
│      "response_type": "resolution",                               │
│      "root_cause": "Slow disk I/O due to heavy checkpoint writes",│
│      "resolution_plan": "1. Increase checkpoint intervals...",    │
│      "confidence": "High"                                         │
│    }                                                              │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 9. Display Resolution to User                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 5. eBPF Trace Manager

Manages kernel-level tracing using **bpftrace exclusively** for deep system monitoring. bpftrace is a generic BPF scripting language that provides flexible kernel instrumentation capabilities.

**Note:** Only bpftrace is currently supported. Other eBPF tools (BCC, eBPF Go libraries) may be added in future releases.

**Supported Trace Types:**

| Probe Type | Target Example | Use Case |
|------------|---------------|----------|
| `tracepoint` | `syscalls:sys_enter_connect` | System call monitoring |
| `tracepoint` | `block:block_rq_complete` | Disk I/O tracking |
| `kprobe` | `tcp_connect` | TCP connection monitoring |
| `kprobe` | `vfs_read` | File read operations |
| `kretprobe` | `tcp_sendmsg` | TCP send with return values |

**Trace Execution Flow:**
```bash
# Example bpftrace script generated:
#!/usr/bin/env bpftrace

BEGIN {
    printf("Starting trace: tcp_connect_monitor\n");
}

kprobe:tcp_connect {
    printf("TCP connect from PID %d (%s) to port %d\n",
           pid, comm, arg1);
}

END {
    printf("Trace completed\n");
}
```

**Event Structure:**
```json
{
  "timestamp": 1703001234567890000,
  "event_type": "kprobe_enter",
  "process_id": 1234,
  "process_name": "postgres",
  "user_id": 999,
  "cpu": 2,
  "data": {
    "function": "tcp_connect",
    "port": 5432,
    "ip": "192.168.1.100"
  }
}
```

### 6. Command Executor

Safely executes diagnostic commands with timeouts and security validation.

**Safety Features:**
- Command timeout (default: 10 seconds)
- Output size limits
- Error handling and logging
- Safe command construction
- No shell injection vulnerabilities

### 7. Investigations Client

Handles all investigation-related API operations.

**API Endpoints:**

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/investigations` | Create investigation or send diagnostic message |
| `GET` | `/api/investigations/{id}` | Retrieve investigation details |

**Request Format (TensorZero Proxy):**
```json
{
  "model": "tensorzero::function_name::diagnose_and_heal",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ],
  "investigation_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

The `investigation_id` field is critical - it tells NannyAPI which investigation this diagnostic session belongs to, enabling proper tracking and routing.

### 8. Realtime Client

Maintains persistent SSE (Server-Sent Events) connection for real-time communication.

**Connection Flow:**
```flowchart
┌──────────┐                              ┌──────────┐
│  Agent   │                              │ NannyAPI │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ 1. GET /api/realtime                    │
     ├────────────────────────────────────────>│
     │ 2. event: connect                       │
     │    data: {"clientId": "abc123"}         │
     │<────────────────────────────────────────┤
     │                                         │
     │ 3. POST /api/realtime                   │
     │    Authorization: Bearer <token>        │
     │    {                                    │
     │      "clientId": "abc123",              │
     │      "subscriptions": [                 │
     │        "investigations"                 │
     │      ]                                  │
     │    }                                    │
     ├────────────────────────────────────────>│
     │ 4. 204 No Content                       │
     │<────────────────────────────────────────┤
     │                                         │
     │ === Listening for events ===            │
     │                                         │
     │ 5. event: record                        │
     │    data: {                              │
     │      "action": "create",                │
     │      "record": {                        │
     │        "id": "inv-123",                 │
     │        "user_prompt": "Fix nginx"       │
     │      }                                  │
     │    }                                    │
     │<────────────────────────────────────────┤
     │                                         │
     │ 6. Process investigation                │
     │                                         │
```

**Event Types:**

1. **Investigation Events:**
```json
{
  "action": "create",
  "record": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user_prompt": "PostgreSQL is slow",
    "agent_id": "agent-123",
    "status": "pending"
  }
}
```

### 9. Metrics Collector

Collects comprehensive system metrics using gopsutil library.

**Collected Metrics:**

| Category | Metrics | Library |
|----------|---------|---------|
| **System** | Hostname, Platform, Kernel Version, Architecture | `gopsutil/host` |
| **CPU** | Usage %, Core Count, Model Name | `gopsutil/cpu` |
| **Memory** | Total, Used, Free, Available, Swap | `gopsutil/mem` |
| **Disk** | Usage %, Total, Used, Free, Filesystem Info | `gopsutil/disk` |
| **Network** | Total RX/TX (GB), IP Addresses | `gopsutil/net` |
| **Load** | 1min, 5min, 15min averages | System call |
| **Block Devices** | Name, Size, Type, Model, Serial | `gopsutil/disk` |

**Ingestion Endpoint:**
```
POST /api/agent
Authorization: Bearer <access_token>

{
  "agent_id": "agent-123",
  "timestamp": "2025-12-30T10:30:00Z",
  "hostname": "prod-web-01",
  "cpu_usage": 45.2,
  "memory_usage": 12345.67,
  "disk_usage": 67.8,
  "network_in_gb": 123.45,
  "network_out_gb": 67.89,
  "load_avg_1": 2.15,
  "load_avg_5": 1.98,
  "load_avg_15": 1.76,
  ...
}
```

**Collection Schedule:** Every 30 seconds (configurable via `METRICS_INTERVAL`)

## Data Flow

### Metrics Ingestion Flow

```flowchart
Every 30 seconds (configurable via metrics_interval):

┌─────────────────────────────────────────────────────────────────────────┐
│                          METRICS COLLECTION FLOW                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌────────────────┐                                                     │
│  │ Metrics Timer  │                                                     │
│  │  (30s interval)│                                                     │
│  └────────┬───────┘                                                     │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────────────────────┐                                │
│  │  Collect System Metrics (gopsutil)  │                                │
│  │  • CPU usage, cores, model          │                                │
│  │  • Memory total/used/available      │                                │
│  │  • Disk usage, filesystems          │                                │
│  │  • Network RX/TX, IP addresses      │                                │
│  │  • Load averages (1/5/15 min)       │                                │
│  │  • Block devices & partitions       │                                │
│  └────────┬────────────────────────────┘                                │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────────────────────┐                                │
│  │   Build SystemMetrics JSON Struct   │                                │
│  │   {                                 │                                │
│  │     "timestamp": "2025-12-30...",   │                                │
│  │     "hostname": "prod-web-01",      │                                │
│  │     "cpu_usage": 45.2,              │                                │
│  │     "memory_total": 68719476736,    │                                │
│  │     "disk_usage": 67.8,             │                                │
│  │     "network_in_gb": 123.45,        │                                │
│  │     "load_avg_1": 2.15,             │                                │
│  │     ...                             │                                │
│  │   }                                 │                                │
│  └────────┬────────────────────────────┘                                │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────────────────────┐                                │
│  │    POST /api/agent                  │                                │
│  │    Authorization: Bearer <token>    │                                │
│  │    Content-Type: application/json   │                                │
│  │                                     │                                │
│  │    Body: SystemMetrics JSON         │                                │
│  └────────┬────────────────────────────┘                                │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────────────────────┐                                │
│  │       NannyAPI Backend              │                                │
│  │  ✓ Validates authentication token   │                                │
│  │  ✓ Stores metrics in database       │                                │
│  │  ✓ Triggers alerts if thresholds    │                                │
│  │  ✓ Returns 200 OK                   │                                │
│  └─────────────────────────────────────┘                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Metrics Collected:**

**System Information:**
- `hostname`: System hostname
- `platform`: OS platform (ubuntu, debian, centos, etc.)
- `platform_family`: Platform family (debian, rhel, etc.)
- `platform_version`: OS version (22.04, 8, etc.)
- `kernel_version`: Linux kernel version (5.15.0-56-generic)
- `kernel_arch`: Architecture (x86_64, aarch64)
- `os_type`: Operating system type (linux)

**CPU Metrics:**
- `cpu_usage`: CPU usage percentage (0-100)
- `cpu_cores`: Number of CPU cores
- `cpu_model`: CPU model name

**Memory Metrics:**
- `memory_usage`: Memory usage in MB
- `memory_total`: Total memory in bytes
- `memory_used`: Used memory in bytes
- `memory_free`: Free memory in bytes
- `memory_available`: Available memory in bytes
- `swap_total`: Total swap in bytes
- `swap_used`: Used swap in bytes
- `swap_free`: Free swap in bytes

**Disk Metrics:**
- `disk_usage`: Root disk usage percentage
- `disk_total`: Total disk space in bytes
- `disk_used`: Used disk space in bytes
- `disk_free`: Free disk space in bytes
- `filesystem_info`: Array of filesystem details (mountpoint, fstype, usage)

**Network Metrics:**
- `network_in_gb`: Total received data in GB (cumulative since boot)
- `network_out_gb`: Total sent data in GB (cumulative since boot)
- `ip_address`: Primary IP address
- `all_ips`: Array of all IP addresses
- `location`: Geographic location (placeholder)

**Load Metrics:**
- `load_avg_1`: 1-minute load average
- `load_avg_5`: 5-minute load average
- `load_avg_15`: 15-minute load average
- `process_count`: Number of running processes

**Block Devices:**
- `block_devices`: Array of physical/virtual disk devices
  - `name`: Device name (sda, nvme0n1, etc.)
  - `size`: Device size in bytes
  - `type`: Device type (disk, partition)
  - `model`: Device model
  - `serial_number`: Device serial number

**API Endpoint:**
```
POST /api/agent
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body Example:**
```json
{
  "agent_id": "agent-550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-12-30T10:30:00Z",
  "hostname": "prod-web-01",
  "platform": "ubuntu",
  "platform_family": "debian",
  "platform_version": "22.04",
  "kernel_version": "5.15.0-56-generic",
  "kernel_arch": "x86_64",
  "os_type": "linux",
  "cpu_usage": 45.2,
  "cpu_cores": 16,
  "cpu_model": "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
  "memory_usage": 51200.0,
  "memory_total": 68719476736,
  "memory_used": 53687091200,
  "memory_free": 15032385536,
  "memory_available": 20468695040,
  "swap_total": 2147483648,
  "swap_used": 0,
  "swap_free": 2147483648,
  "disk_usage": 67.8,
  "disk_total": 536870912000,
  "disk_used": 363869478912,
  "disk_free": 173001433088,
  "network_in_gb": 123.45,
  "network_out_gb": 67.89,
  "ip_address": "10.0.1.5",
  "all_ips": ["10.0.1.5", "172.17.0.1"],
  "location": "unknown",
  "load_avg_1": 2.15,
  "load_avg_5": 1.98,
  "load_avg_15": 1.76,
  "process_count": 342,
  "filesystem_info": [
    {
      "mountpoint": "/",
      "fstype": "ext4",
      "total": 536870912000,
      "used": 363869478912,
      "free": 173001433088,
      "usage_percent": 67.8
    },
    {
      "mountpoint": "/var",
      "fstype": "ext4",
      "total": 107374182400,
      "used": 85899345920,
      "free": 21474836480,
      "usage_percent": 80.0
    }
  ],
  "block_devices": [
    {
      "name": "sda",
      "size": 536870912000,
      "type": "disk",
      "model": "Samsung SSD 860",
      "serial_number": "S3Z9NB0K123456"
    },
    {
      "name": "nvme0n1",
      "size": 1073741824000,
      "type": "disk",
      "model": "Samsung 970 EVO",
      "serial_number": "S5H9NS0N234567"
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Metrics ingested successfully"
}
```

**Collection Frequency:**
- Default: Every 30 seconds
- Configurable via `metrics_interval` in config.yaml
- Example: `metrics_interval: 60` (every minute)

**Error Handling:**
- Failed metrics collection: Agent logs error but continues
- Failed API submission: Retry with exponential backoff
- Token expired: Automatic token refresh and retry

## Component Interactions

### Investigation Lifecycle

```flowchart
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              INVESTIGATION DIAGNOSTIC WORKFLOW                                  │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                 │
│  Portal/CLI              Agent                      NannyAPI                 TensorZero AI      │
│      │                     │                            │                          │            │
│      │ 1. Create           │                            │                          │            │
│      │    Investigation    │                            │                          │            │
│      ├────────────────────>│                            │                          │            │
│      │                     │                            │                          │            │
│      │                     │ 2. POST /api/              │                          │            │
│      │                     │    investigations          │                          │            │
│      │                     │    (create record)         │                          │            │
│      │                     ├───────────────────────────>│                          │            │
│      │                     │ 3. investigation_id        │                          │            │
│      │                     │<───────────────────────────┤                          │            │
│      │                     │                            │                          │            │
│      │                     │ 4. POST /api/              │                          │            │
│      │                     │    investigations          │                          │            │
│      │                     │    (TensorZero req)        │                          │            │
│      │                     ├───────────────────────────>│ 5. Forward request       │            │
│      │                     │                            ├─────────────────────────>│            │
│      │                     │                            │ 6. AI diagnostic         │            │
│      │                     │                            │    response              │            │
│      │                     │ 7. Diagnostic commands     │<─────────────────────────┤            │
│      │                     │<───────────────────────────┤                          │            │
│      │                     │                            │                          │            │
│      │                     │ 8. Execute:                │                          │            │
│      │                     │    • Diagnostic cmds       │                          │            │
│      │                     │    • eBPF traces           │                          │            │
│      │                     │                            │                          │            │
│      │                     │ 9. POST /api/              │                          │            │
│      │                     │    investigations          │                          │            │
│      │                     │    (with results)          │                          │            │
│      │                     ├───────────────────────────>│ 10. Forward results      │            │
│      │                     │                            ├─────────────────────────>│            │
│      │                     │                            │ 11. AI resolution        │            │
│      │                     │                            │     (root cause +        │            │
│      │                     │                            │      fix plan)           │            │
│      │                     │ 12. Final resolution       │<─────────────────────────┤            │
│      │                     │<───────────────────────────┤                          │            │
│      │ 13. Display         │                            │                          │            │
│      │     resolution      │                            │                          │            │
│      │<────────────────────┤                            │                          │            │
│      │                     │                            │                          │            │
│                                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Realtime Event Processing

```flowchart
┌───────────────────────────────────────────────────────────────────────────────────┐
│                       SERVER-SENT EVENTS (SSE) FLOW                               │
├───────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  Agent                         NannyAPI (SSE)                     Portal          │
│    │                                    │                              │          │
│    │ 1. GET /api/realtime               │                              │          │
│    │    (establish SSE connection)      │                              │          │
│    ├───────────────────────────────────>│                              │          │
│    │                                    │                              │          │
│    │ 2. event: connect                  │                              │          │
│    │    data: {"clientId": "abc123"}    │                              │          │
│    │<───────────────────────────────────┤                              │          │
│    │                                    │                              │          │
│    │ 3. POST /api/realtime              │                              │          │
│    │    {                               │                              │          │
│    │      "clientId": "abc123",         │                              │          │
│    │      "subscriptions": [            │                              │          │
│    │        "investigations"            │                              │          │
│    │      ]                             │                              │          │
│    │    }                               │                              │          │
│    ├───────────────────────────────────>│                              │          │
│    │                                    │                              │          │
│    │ 4. 204 No Content                  │                              │          │
│    │<───────────────────────────────────┤                              │          │
│    │                                    │                              │          │
│    │ ═══ SSE Connection Active ═══      │                              │          │
│    │                                    │                              │          │
│    │                                    │ 5. User creates investigation│          │
│    │                                    │<─────────────────────────────┤          │
│    │                                    │                              │          │
│    │ 6. event: record                   │                              │          │
│    │    data: {                         │                              │          │
│    │      "action": "create",           │                              │          │
│    │      "record": {                   │                              │          │
│    │        "id": "inv-123",            │                              │          │
│    │        "user_prompt": "Fix nginx"  │                              │          │
│    │      }                             │                              │          │
│    │    }                               │                              │          │
│    │<───────────────────────────────────┤                              │          │
│    │                                    │                              │          │
│    │ 7. Process event                   │                              │          │
│    │    (spawn goroutine)               │                              │          │
│    │                                    │                              │          │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## Design Patterns

### 1. Interface-Based Design

The agent uses interfaces extensively for testability and flexibility:

```go
// Authenticator interface for auth manager
type Authenticator interface {
    AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error)
}

// CommandExecutor interface for test mocking
type CommandExecutor interface {
    Execute(command string, args ...string) ([]byte, error)
}
```

### 2. Concurrent Execution

Commands and eBPF traces execute in parallel using goroutines:

```go
// Execute commands concurrently
var wg sync.WaitGroup
results := make([]CommandResult, len(commands))

for i, cmd := range commands {
    wg.Add(1)
    go func(idx int, command Command) {
        defer wg.Done()
        results[idx] = executor.Execute(command)
    }(i, cmd)
}

wg.Wait()
```

### 3. Graceful Error Handling

All components implement error handling with retry logic:

```go
// Token refresh with exponential backoff
func (am *AuthManager) EnsureAuthenticated() (*types.AuthToken, error) {
    token, err := am.LoadToken()
    if err != nil {
        return nil, err
    }
    
    if token.IsExpired() {
        return am.RefreshTokenWithRetry()
    }
    
    return token, nil
}
```

### 4. Configuration Hierarchy

Environment variables override file configuration:

```go
// Load from file
config := loadYAMLConfig("/etc/nannyagent/config.yaml")

// Override with environment variables
if url := os.Getenv("NANNYAPI_URL"); url != "" {
    config.APIBaseURL = url
}
```

### 5. Lifecycle Management

Components support clean shutdown:

```go
// Manager with stop channel
type Manager struct {
    stopChan chan struct{}
    stopOnce sync.Once
}

func (m *Manager) Stop() {
    m.stopOnce.Do(func() {
        close(m.stopChan)
    })
}
```

### 6. Resilient Connectivity

The agent implements a robust **Self-Healing Connectivity** pattern to handle network disruptions and server restarts seamlessly.

**Key Features:**
- **Automatic Token Refresh**: 401 Unauthorized responses trigger an immediate token refresh and request retry.
- **Connection Pool Management**: Transport-level errors (like `http2: response body closed`) trigger a reset of the HTTP connection pool (`CloseIdleConnections`), preventing subsequent requests from failing on dead connections.
- **Atomic Request/Read**: The `AuthenticatedRequest` pattern ensures that both the request execution and response body reading are protected by the retry loop, handling cases where the server sends headers but drops the connection during body transmission.
- **Fixed Retry Delays**: Retries use fixed wait intervals (for example, 5 seconds in `AuthenticatedRequest` and 60 seconds in `AuthenticatedDo`) between attempts to reduce load on the server.

---

## Security Considerations

1. **Root Privileges**: Required for eBPF but validated at startup
2. **Token Storage**: Tokens stored in `/var/lib/nannyagent/` with 0600 permissions
3. **Timeout Protection**: All commands and traces have timeouts
4. **No Shell Injection**: Commands constructed safely without shell expansion
5. **TLS/HTTPS**: All API communication over HTTPS
6. **OAuth Device Flow**: Industry-standard authentication

---

<div align="center">
  <p><strong>Next:</strong> <a href="./API_INTEGRATION.md">API Integration Guide</a></p>
  <p><em>NannyAgent - AI-Powered Linux Diagnostics</em></p>
</div>
