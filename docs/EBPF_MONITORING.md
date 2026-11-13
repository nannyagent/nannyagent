# eBPF Monitoring Guide

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Deep Kernel-Level Monitoring with eBPF</h1>
</div>

## Table of Contents

- [Overview](#overview)
- [eBPF Architecture](#ebpf-architecture)
- [Trace Types](#trace-types)
- [Trace Specifications](#trace-specifications)
- [Event Processing](#event-processing)
- [Use Cases](#use-cases)
- [Performance Considerations](#performance-considerations)
- [Security](#security)

## Overview

NannyAgent uses **bpftrace** exclusively for deep, kernel-level eBPF monitoring of Linux systems. `bpftrace` is a high-level scripting language that provides a powerful and flexible way to trace kernel and application behavior with minimal overhead.

**Important:** Currently, NannyAgent **only supports bpftrace** for eBPF tracing. Support for other eBPF tools (BCC, eBPF Go libraries) may be added in future releases.

### What is eBPF?

eBPF (Extended Berkeley Packet Filter) is a revolutionary technology that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.

**Benefits:**
- **Low Overhead**: Minimal impact on system performance
- **Safe**: Programs are verified before execution
- **Real-time**: Capture events as they happen
- **Comprehensive**: Access to kernel internals not available through traditional tools
- **No Instrumentation**: No need to modify applications

### Why bpftrace?

NannyAgent uses **bpftrace** as the generic BPF scripting tool to extract deep insights from the kernel:

```bash
# Check bpftrace availability
$ which bpftrace
/usr/bin/bpftrace

# Check kernel version (5.x+ required)
$ uname -r
5.15.0-56-generic
```

## eBPF Architecture

```flowchart
┌─────────────────────────────────────────────────────────────────┐
│                     NannyAgent Process                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │         eBPF Trace Manager (Go)                            │ │
│  │  - Trace specification parsing                             │ │
│  │  - bpftrace script generation                              │ │
│  │  - Process management                                      │ │
│  │  - Event parsing & aggregation                             │ │
│  └────────────────────────┬───────────────────────────────────┘ │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            │ spawn & monitor
                            ▼
        ┌───────────────────────────────────────┐
        │     bpftrace Process                  │
        │  ┌─────────────────────────────────┐  │
        │  │  Compiled eBPF Script           │  │
        │  │  (Generated from TraceSpec)     │  │
        │  └───────────────┬─────────────────┘  │
        └──────────────────┼────────────────────┘
                           │
                           │ eBPF syscall
                           ▼
        ┌──────────────────────────────────────────┐
        │         Linux Kernel                     │
        │  ┌────────────────────────────────────┐  │
        │  │    eBPF Virtual Machine            │  │
        │  │  - Program verification            │  │
        │  │  - JIT compilation                 │  │
        │  │  - Safe execution                  │  │
        │  └───────────────┬────────────────────┘  │
        │                  │                       │
        │  ┌───────────────┴────────────────────┐  │
        │  │   Kernel Instrumentation Points    │  │
        │  │  - Tracepoints                     │  │
        │  │  - Kprobes                         │  │
        │  │  - Kretprobes                      │  │
        │  │  - USDT probes                     │  │
        │  └────────────────────────────────────┘  │
        └──────────────────────────────────────────┘
                           │
                           │ events
                           ▼
        ┌──────────────────────────────────────────┐
        │    System Calls & Kernel Functions       │
        │  - tcp_connect(), vfs_read()             │
        │  - do_fork(), schedule()                 │
        │  - syscall entries/exits                 │
        └──────────────────────────────────────────┘
```

## Trace Types

### 1. Tracepoints

Stable kernel tracing points that won't change between kernel versions.

**Format:** `tracepoint:subsystem:event`

**Common Tracepoints:**

| Tracepoint | Monitors | Use Case |
|------------|----------|----------|
| `syscalls:sys_enter_connect` | Network connections | Track connection attempts |
| `syscalls:sys_enter_openat` | File opens | Monitor file access |
| `syscalls:sys_enter_execve` | Process execution | Track new processes |
| `block:block_rq_complete` | Disk I/O | Measure I/O latency |
| `sched:sched_process_exit` | Process termination | Track process lifecycle |
| `sched:sched_wakeup` | Process scheduling | Analyze scheduling behavior |

**Example bpftrace Script:**
```c
tracepoint:syscalls:sys_enter_openat {
    printf("%s (PID %d) opened file: %s\n",
           comm, pid, str(args->filename));
}
```

### 2. Kprobes (Kernel Probes)

Dynamic tracing of any kernel function.

**Format:** `kprobe:function_name`

**Common Kprobes:**

| Kprobe | Function | Use Case |
|--------|----------|----------|
| `kprobe:tcp_connect` | TCP connection | Network connectivity |
| `kprobe:tcp_sendmsg` | TCP send | Network throughput |
| `kprobe:vfs_read` | VFS read | File read operations |
| `kprobe:vfs_write` | VFS write | File write operations |
| `kprobe:do_fork` | Process fork | Process creation |
| `kprobe:__alloc_pages_nodemask` | Memory allocation | Memory usage patterns |

**Example bpftrace Script:**
```c
kprobe:tcp_connect {
    $sk = (struct sock *)arg0;
    $inet = (struct inet_sock *)$sk;
    printf("TCP connect to port %d from PID %d\n",
           $inet->inet_dport, pid);
}
```

### 3. Kretprobes (Kernel Return Probes)

Trace function return values.

**Format:** `kretprobe:function_name`

**Common Kretprobes:**

| Kretprobe | Monitors | Use Case |
|-----------|----------|----------|
| `kretprobe:tcp_sendmsg` | TCP send result | Track send errors |
| `kretprobe:vfs_read` | Read return value | Bytes read analysis |
| `kretprobe:do_sys_open` | Open result | Track open failures |

**Example bpftrace Script:**
```c
kretprobe:vfs_read {
    printf("Read returned %d bytes to PID %d (%s)\n",
           retval, pid, comm);
}
```

### 4. USDT Probes (User Statically-Defined Tracing)

Application-level tracing points.

**Format:** `usdt:/path/to/binary:provider:probe`

**Example:**
```c
usdt:/usr/bin/postgres:postgresql:transaction__start {
    printf("Transaction started by PID %d\n", pid);
}
```

## Trace Specifications

### TraceSpec Structure

```go
type TraceSpec struct {
    // Probe type: "p" (kprobe), "r" (kretprobe), "t" (tracepoint)
    ProbeType string `json:"probe_type"`

    // Target function/syscall/tracepoint
    Target string `json:"target"`

    // Format string for output
    Format string `json:"format"`

    // Arguments to extract
    Arguments []string `json:"arguments"`

    // Filter condition (optional)
    Filter string `json:"filter,omitempty"`

    // Duration in seconds
    Duration int `json:"duration"`

    // Process ID filter (optional)
    PID int `json:"pid,omitempty"`

    // Process name filter (optional)
    ProcessName string `json:"process_name,omitempty"`
}
```

### AI Request Format

When TensorZero AI wants to request eBPF monitoring:

```json
{
  "response_type": "diagnostic",
  "reasoning": "Need to monitor TCP connections for database connectivity issues",
  "commands": [...],
  "ebpf_programs": [
    {
      "name": "tcp_connect_monitor",
      "type": "kprobe",
      "target": "tcp_connect",
      "duration": 15,
      "description": "Monitor TCP connection attempts"
    },
    {
      "name": "disk_io_trace",
      "type": "tracepoint",
      "target": "block:block_rq_complete",
      "duration": 20,
      "description": "Track disk I/O completion latency"
    }
  ]
}
```

### Script Generation

The agent converts AI requests into bpftrace scripts:

**Input (from AI):**
```json
{
  "name": "tcp_connect_monitor",
  "type": "kprobe",
  "target": "tcp_connect",
  "duration": 15
}
```

**Generated bpftrace Script:**
```bash
#!/usr/bin/env bpftrace

BEGIN {
    printf("=== TCP Connect Monitor ===\n");
    printf("Tracing TCP connections for 15 seconds...\n");
    printf("%-8s %-16s %-6s %-16s %-6s\n",
           "TIME", "COMM", "PID", "DADDR", "DPORT");
}

kprobe:tcp_connect {
    $sk = (struct sock *)arg0;
    $inet = (struct inet_sock *)$sk;
    $daddr = ntop($inet->inet_daddr);
    $dport = $inet->inet_dport;
    $dport = ($dport >> 8) | (($dport << 8) & 0xFF00);
    
    printf("%-8s %-16s %-6d %-16s %-6d\n",
           strftime("%H:%M:%S", nsecs),
           comm,
           pid,
           $daddr,
           $dport);
}

END {
    printf("\n=== Trace Complete ===\n");
}
```

**Execution:**
```bash
# Run with timeout
timeout 15 bpftrace /tmp/tcp_connect_monitor.bt
```

## Event Processing

### Event Structure

```go
type TraceEvent struct {
    Timestamp   int64             `json:"timestamp"`
    PID         int               `json:"pid"`
    TID         int               `json:"tid"`
    UID         int               `json:"uid"`
    ProcessName string            `json:"process_name"`
    Function    string            `json:"function"`
    Message     string            `json:"message"`
    RawArgs     map[string]string `json:"raw_args"`
    CPU         int               `json:"cpu,omitempty"`
}
```

### Event Parsing

**Raw bpftrace Output:**
```text
12:34:56 postgres        1234   10.0.1.100      5432
12:34:57 nginx           5678   172.16.0.50     443
```

**Parsed Events:**
```json
[
  {
    "timestamp": 1703001296000000000,
    "pid": 1234,
    "process_name": "postgres",
    "function": "tcp_connect",
    "message": "Connected to 10.0.1.100:5432",
    "raw_args": {
      "daddr": "10.0.1.100",
      "dport": "5432"
    }
  },
  {
    "timestamp": 1703001297000000000,
    "pid": 5678,
    "process_name": "nginx",
    "function": "tcp_connect",
    "message": "Connected to 172.16.0.50:443",
    "raw_args": {
      "daddr": "172.16.0.50",
      "dport": "443"
    }
  }
]
```

### Trace Statistics

```go
type TraceStats struct {
    TotalEvents     int            `json:"total_events"`
    EventsByProcess map[string]int `json:"events_by_process"`
    EventsByUID     map[int]int    `json:"events_by_uid"`
    EventsPerSecond float64        `json:"events_per_second"`
    TopProcesses    []ProcessStat  `json:"top_processes"`
}
```

**Example Statistics:**
```json
{
  "total_events": 1247,
  "events_by_process": {
    "postgres": 856,
    "nginx": 245,
    "redis": 146
  },
  "events_by_uid": {
    "999": 856,
    "33": 245,
    "100": 146
  },
  "events_per_second": 83.13,
  "top_processes": [
    {
      "process_name": "postgres",
      "pid": 1234,
      "event_count": 856,
      "percentage": 68.6
    },
    {
      "process_name": "nginx",
      "pid": 5678,
      "event_count": 245,
      "percentage": 19.6
    }
  ]
}
```

## Use Cases

### 1. Network Connectivity Debugging

**Problem:** Application cannot connect to database

**eBPF Trace:**
```json
{
  "name": "tcp_connect_trace",
  "type": "kprobe",
  "target": "tcp_connect",
  "duration": 30
}
```

**Script:**
```c
kprobe:tcp_connect {
    $sk = (struct sock *)arg0;
    $inet = (struct inet_sock *)$sk;
    printf("PID %d (%s) connecting to %s:%d\n",
           pid, comm,
           ntop($inet->inet_daddr),
           $inet->inet_dport);
}
```

**Insight:** Shows which processes are attempting connections and to which addresses/ports.

### 2. Disk I/O Performance

**Problem:** Slow disk operations

**eBPF Trace:**
```json
{
  "name": "block_io_latency",
  "type": "tracepoint",
  "target": "block:block_rq_complete",
  "duration": 20
}
```

**Script:**
```c
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
}

tracepoint:block:block_rq_complete /@start[args->dev, args->sector]/ {
    $latency = (nsecs - @start[args->dev, args->sector]) / 1000;
    @io_latency_us = hist($latency);
    delete(@start[args->dev, args->sector]);
}

END {
    printf("\nI/O Latency Distribution (microseconds):\n");
    print(@io_latency_us);
}
```

**Output:**
```text
I/O Latency Distribution (microseconds):
[2, 4)      245 |@@@@@@@@@@@@                      |
[4, 8)      456 |@@@@@@@@@@@@@@@@@@@@@             |
[8, 16)     678 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   |
[16, 32)    345 |@@@@@@@@@@@@@@@@                  |
[32, 64)    123 |@@@@@@                            |
[64, 128)    45 |@@                                |
```

### 3. File Access Monitoring

**Problem:** Unknown process modifying configuration files

**eBPF Trace:**
```json
{
  "name": "file_write_monitor",
  "type": "kprobe",
  "target": "vfs_write",
  "duration": 60
}
```

**Script:**
```c
kprobe:vfs_write {
    $file = (struct file *)arg0;
    $dentry = $file->f_path.dentry;
    $name = str($dentry->d_name.name);
    
    if (strcontains($name, ".conf") || strcontains($name, ".cfg")) {
        printf("%s (PID %d, UID %d) writing to %s\n",
               comm, pid, uid, $name);
    }
}
```

### 4. Process Creation Tracking

**Problem:** Suspicious process spawning

**eBPF Trace:**
```json
{
  "name": "process_exec_trace",
  "type": "tracepoint",
  "target": "syscalls:sys_enter_execve",
  "duration": 30
}
```

**Script:**
```c
tracepoint:syscalls:sys_enter_execve {
    printf("EXEC: %s (PID %d) -> %s\n",
           comm, pid, str(args->filename));
}

tracepoint:sched:sched_process_exit {
    printf("EXIT: %s (PID %d) exit code %d\n",
           comm, pid, args->exit_code);
}
```

### 5. Memory Allocation Patterns

**Problem:** Memory leak investigation

**eBPF Trace:**
```json
{
  "name": "memory_alloc_trace",
  "type": "kprobe",
  "target": "__alloc_pages_nodemask",
  "duration": 15
}
```

**Script:**
```c
kprobe:__alloc_pages_nodemask {
    @alloc_by_process[comm] = count();
    @alloc_bytes[comm] = sum(arg1 * 4096); // arg1 = order, 4KB pages
}

END {
    printf("\n=== Memory Allocations ===\n");
    print(@alloc_by_process);
    printf("\n=== Memory Allocated (bytes) ===\n");
    print(@alloc_bytes);
}
```

### 6. TCP Retransmission Analysis

**Problem:** Network quality issues

**eBPF Trace:**
```json
{
  "name": "tcp_retransmit_trace",
  "type": "kprobe",
  "target": "tcp_retransmit_skb",
  "duration": 30
}
```

**Script:**
```c
kprobe:tcp_retransmit_skb {
    $sk = (struct sock *)arg0;
    $inet = (struct inet_sock *)$sk;
    printf("TCP retransmit: %s:%d -> %s:%d (PID %d)\n",
           ntop($inet->inet_saddr),
           $inet->inet_sport,
           ntop($inet->inet_daddr),
           $inet->inet_dport,
           pid);
    @retransmits = count();
}

END {
    printf("\nTotal retransmissions: ");
    print(@retransmits);
}
```

## Performance Considerations

### Overhead

eBPF is extremely efficient, but consider:

| Trace Type | Overhead | Notes |
|------------|----------|-------|
| Tracepoints | < 0.1% | Lowest overhead, use when available |
| Kprobes | 0.1-1% | Slightly higher, but still minimal |
| High-frequency events | 1-5% | (e.g., all syscalls, scheduler) |
| Complex filters | Variable | Keep filters simple |

### Best Practices

1. **Use Tracepoints First**: Stable and lowest overhead
2. **Limit Duration**: Default 10-30 seconds
3. **Filter Early**: Apply filters in eBPF, not userspace
4. **Aggregate in Kernel**: Use maps for aggregation
5. **Limit Output**: Don't print every event for high-frequency probes

**Good (Aggregated):**
```c
kprobe:tcp_connect {
    @connects[comm] = count();
}
```

**Bad (Per-event):**
```c
kprobe:tcp_connect {
    printf("Connect from %s\n", comm); // Generates too much output
}
```

### Resource Limits

```go
const (
    MaxTraceDuration = 60 * time.Second  // Maximum 60 seconds
    MaxConcurrentTraces = 3               // Max 3 simultaneous traces
    MaxEventBufferSize = 10000            // Max events to buffer
)
```

## Security

### Required Privileges

```bash
# Must run as root
$ sudo nannyagent

# Or with CAP_BPF capability (Linux 5.8+)
$ sudo setcap cap_bpf=ep /usr/sbin/nannyagent
```

### Safety Features

1. **Kernel Verification**: eBPF programs are verified before loading
2. **Sandboxed Execution**: Cannot crash kernel
3. **Resource Limits**: Memory and CPU limits enforced
4. **Timeout Protection**: All traces have maximum duration
5. **Read-Only**: eBPF programs cannot modify kernel state

### Isolation

```bash
# Each trace runs in isolated temp directory
/tmp/nanny-ebpf-XXXXXX/
    tcp_connect_monitor.bt
    output.log
```

Cleaned up automatically after completion.

### Audit Logging

All eBPF activity is logged:

```text
[INFO] Starting eBPF trace: tcp_connect_monitor (kprobe:tcp_connect, 15s)
[INFO] eBPF trace completed: 1247 events captured
[INFO] Trace statistics: postgres=856, nginx=245, redis=146
```

---

## Example: Complete Diagnostic Session

### Problem

User reports: "PostgreSQL queries are extremely slow"

### AI Analysis

```json
{
  "response_type": "diagnostic",
  "reasoning": "Need to monitor disk I/O, TCP connections, and process scheduling to identify bottleneck",
  "commands": [
    {
      "id": "pg_stats",
      "command": "psql -c 'SELECT * FROM pg_stat_activity'",
      "description": "Check active queries"
    },
    {
      "id": "io_stats",
      "command": "iostat -x 1 5",
      "description": "Monitor disk I/O"
    }
  ],
  "ebpf_programs": [
    {
      "name": "disk_io_latency",
      "type": "tracepoint",
      "target": "block:block_rq_complete",
      "duration": 15,
      "description": "Measure I/O latency distribution"
    },
    {
      "name": "postgres_reads",
      "type": "kprobe",
      "target": "vfs_read",
      "duration": 15,
      "description": "Track file reads by PostgreSQL"
    }
  ]
}
```

### Execution

**Disk I/O Trace:**
```text
=== Disk I/O Latency ===
[32, 64)     12 |@@                |
[64, 128)    45 |@@@@@@            |
[128, 256)   123|@@@@@@@@@@@@@@@@@ |
[256, 512)   345|@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[512, 1024)  234|@@@@@@@@@@@@@@@@@@@@@@@        |
```

**VFS Read Trace:**
```text
15:23:45 postgres  1234  /var/lib/postgresql/data/base/16384/12345
15:23:45 postgres  1234  /var/lib/postgresql/data/base/16384/12346
15:23:45 postgres  1234  /var/lib/postgresql/data/base/16384/12347
... (856 reads in 15 seconds)
```

### AI Resolution

```json
{
  "response_type": "resolution",
  "root_cause": "Slow disk I/O latency (avg 400μs) combined with high read volume (856 reads/15s = 57 reads/sec) indicates disk contention. eBPF trace shows PostgreSQL reading from multiple data files sequentially.",
  "resolution_plan": "1. Increase shared_buffers to reduce disk reads\n2. Enable huge pages for better memory performance\n3. Consider moving to faster storage (SSD)\n4. Optimize queries to reduce sequential scans",
  "confidence": "High",
  "ebpf_evidence": "disk_io_latency trace showed 512-1024μs latency for 67% of I/O operations. postgres_reads trace confirmed 856 sequential file reads in 15 seconds."
}
```

---

<div align="center">
  <p><em>NannyAgent - AI-Powered Linux Diagnostics</em></p>
</div>
