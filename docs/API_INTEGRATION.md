# API Integration Guide

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Backend API Integration</h1>
</div>

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [REST API Endpoints](#rest-api-endpoints)
- [Realtime (SSE) API](#realtime-sse-api)
- [Investigations API](#investigations-api)
- [Metrics API](#metrics-api)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

## Overview

NannyAgent communicates with the NannyAPI backend using multiple protocols:

1. **REST API** - Standard HTTP requests for CRUD operations
2. **Server-Sent Events (SSE)** - Real-time push notifications from server

**Base URL Configuration:**
```bash
NANNYAPI_URL=https://api.nannyai.dev  # Production
# or
NANNYAPI_URL=http://localhost:8090    # Development
```

## Authentication

### Device Flow OAuth 2.0

NannyAgent implements the OAuth 2.0 Device Authorization Grant flow for secure, user-authorized registration.

#### Flow Diagram

```text
┌──────────┐                  ┌──────────┐                 ┌──────────┐
│  Agent   │                  │ NannyAPI │                 │  Portal  │
└────┬─────┘                  └────┬─────┘                 └────┬─────┘
     │                             │                            │
     │                             │                            │
     │ Step 1: Request Device Code │                            │
     │ POST /api/auth              │                            │
     │ {                           │                            │
     │   "action": "device-auth-start"                          │
     │ }                           │                            │
     ├────────────────────────────>│                            │
     │                             │                            │
     │ Response:                   │                            │
     │ {                           │                            │
     │   "device_code": "uuid",    │                            │
     │   "user_code": "ABCD1234",  │                            │
     │   "verification_uri": "https://nannyai.dev/device",      │
     │   "expires_in": 600         │                            │
     │ }                           │                            │
     │<────────────────────────────┤                            │
     │                             │                            │
     │ Step 2: Display to User     │                            │
     │ "Visit https://nannyai.dev/device"                       │
     │ "Enter code: ABCD1234"      │                            │
     │                             │                            │
     │                             │ Step 3: User Authorization │
     │                             │<───────────────────────────┤
     │                             │                            │
     │                             │ POST /api/auth             │
     │                             │ {                          │
     │                             │   "action": "authorize",   │
     │                             │   "user_code": "ABCD1234"  │
     │                             │ }                          │
     │                             │                            │
     │                             │ Response:                  │
     │                             │ {                          │
     │                             │   "success": true,         │
     │                             │   "message": "Authorized"  │
     │                             │ }                          │
     │                             │───────────────────────────>│
     │                             │                            │
     │ Step 4: Register Agent      │                            │
     │ POST /api/auth              │                            │
     │ {                           │                            │
     │   "action": "register",     │                            │
     │   "device_code": "uuid",    │                            │
     │   "hostname": "prod-01",    │                            │
     │   "platform": "ubuntu",     │                            │
     │   "version": "1.0.0",       │                            │
     │   "primary_ip": "10.0.1.5", │                            │
     │   "kernel_version": "5.15", │                            │
     │   "all_ips": [...]          │                            │
     │ }                           │                            │
     ├────────────────────────────>│                            │
     │                             │                            │
     │ Response:                   │                            │
     │ {                           │                            │
     │   "access_token": "eyJ...", │                            │
     │   "refresh_token": "eyJ...",│                            │
     │   "token_type": "Bearer",   │                            │
     │   "expires_in": 3600,       │                            │
     │   "agent_id": "agent-123"   │                            │
     │ }                           │                            │
     │<────────────────────────────┤                            │
     │                             │                            │
     │ Step 5: Store Token         │                            │
     │ /var/lib/nannyagent/token.json                           │
     │                             │                            │
```

#### Implementation

**1. Device Auth Start**

```bash
curl -X POST https://api.nannyai.dev/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "action": "device-auth-start"
  }'
```

**Response:**
```json
{
  "device_code": "550e8400-e29b-41d4-a716-446655440000",
  "user_code": "ABCD1234",
  "verification_uri": "https://nannyai.dev/device",
  "expires_in": 600
}
```

**2. User Authorization**

User visits `https://nannyai.dev/device` and enters `ABCD1234`.

Portal sends:
```bash
curl -X POST https://api.nannyai.dev/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "action": "authorize",
    "user_code": "ABCD1234"
  }'
```

**3. Agent Registration**

```bash
curl -X POST https://api.nannyai.dev/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "action": "register",
    "device_code": "550e8400-e29b-41d4-a716-446655440000",
    "hostname": "prod-web-01",
    "platform": "ubuntu",
    "platform_family": "debian",
    "version": "1.0.0",
    "primary_ip": "10.0.1.5",
    "kernel_version": "5.15.0-56-generic",
    "all_ips": ["10.0.1.5", "172.17.0.1"],
    "os_type": "linux"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "agent_id": "agent-550e8400-e29b-41d4-a716-446655440000"
}
```

**4. Token Refresh**

```bash
curl -X POST https://api.nannyai.dev/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "action": "refresh",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "agent_id": "agent-550e8400-e29b-41d4-a716-446655440000"
}
```

### Token Storage

Tokens are stored in `/var/lib/nannyagent/token.json` with 0600 permissions:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_at": "2025-12-30T12:00:00Z",
  "agent_id": "agent-550e8400-e29b-41d4-a716-446655440000"
}
```

### Authentication Headers

All authenticated requests include:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

### Static Token Authentication (alternative)

Static tokens (`nsk_*`) bypass the device auth flow entirely. The agent sends a
single registration request and subsequently authenticates all API calls with the
static token.

**Registration (no device auth):**

```bash
curl -X POST https://api.nannyai.dev/api/agent \
  -H "Authorization: Bearer nsk_your_static_token" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "register-with-token",
    "hostname": "prod-web-01",
    "os_type": "linux",
    "platform_family": "debian",
    "version": "0.0.15",
    "primary_ip": "10.0.1.5",
    "kernel_version": "5.15.0-56-generic",
    "all_ips": ["10.0.1.5", "172.17.0.1"]
  }'
```

**Response:**
```json
{
  "agent_id": "aqvdtvpuoyvji6t"
}
```

**Subsequent authenticated requests:**

```http
Authorization: Bearer nsk_your_static_token
X-Agent-ID: aqvdtvpuoyvji6t
Content-Type: application/json
```

## REST API Endpoints

### Health Check

```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-30T10:30:00Z"
}
```

### Agent Status

```bash
GET /api/agent/{agent_id}
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "agent_id": "agent-123",
  "hostname": "prod-web-01",
  "status": "active",
  "last_seen": "2025-12-30T10:29:45Z",
  "version": "1.0.0",
  "platform": "ubuntu",
  "kernel_version": "5.15.0-56-generic",
  "health_status": "healthy"
}
```

## Realtime (SSE) API

Server-Sent Events provide real-time push notifications from the backend to agents.

### Connection Establishment

**1. Open SSE Connection**

```bash
GET /api/realtime
```

**Response (SSE Stream):**
```http
event: connect
data: {"clientId": "client-abc123xyz"}

```

**2. Subscribe to Channels**

```bash
POST /api/realtime
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "clientId": "client-abc123xyz",
  "subscriptions": ["investigations"]
}
```

**Response:**
```
HTTP/1.1 204 No Content
```

### Event Types

#### Investigation Events

```http
event: record
data: {"action":"create","record":{"id":"inv-123","agent_id":"agent-123","user_prompt":"PostgreSQL is slow","status":"pending","priority":"high","created_at":"2025-12-30T10:30:00Z"}}

```

**Parsed Event:**
```json
{
  "action": "create",
  "record": {
    "id": "inv-123",
    "agent_id": "agent-123",
    "user_prompt": "PostgreSQL is slow",
    "status": "pending",
    "priority": "high",
    "created_at": "2025-12-30T10:30:00Z"
  }
}
```

### Connection Management

**Features:**
- Automatic reconnection with exponential backoff on disconnect
- Client ID tracking for subscription management
- Graceful error handling
- Unlimited retries - agent never gives up on reconnection

**Exponential Backoff (SSE Reconnection):**

When the SSE connection drops, the agent uses exponential backoff to prevent overwhelming the server:

```text
Attempt 0: Wait 30 seconds
Attempt 1: Wait 60 seconds  (30 × 2^1)
Attempt 2: Wait 120 seconds (30 × 2^2)
Attempt 3: Wait 240 seconds (30 × 2^3)
Attempt 4: Wait 480 seconds (30 × 2^4)
Attempt 5+: Wait 1800 seconds (max: 30 minutes)
```

**Backoff Parameters:**
| Parameter | Value | Description |
|-----------|-------|-------------|
| Initial Backoff | 30 seconds | First retry delay |
| Maximum Backoff | 30 minutes | Cap on retry delay |
| Backoff Factor | 2.0 | Multiplier per attempt |
| Retry Limit | Unlimited | Agent always retries |

**Backoff Formula:**
```
backoff = min(MaxBackoff, InitialBackoff × 2^attempt)
```

The backoff counter resets to zero upon successful reconnection.

**Code Example:**
```go
// Start SSE client with handlers
client := realtime.NewClient(
    baseURL,
    accessToken,
    investigationHandler,
)

go client.Start() // Blocks until connection closed, auto-reconnects with backoff
```

## Investigations API

The investigations API handles diagnostic sessions and AI communication.

### Create Investigation

```bash
POST /api/investigations
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "agent_id": "agent-123",
  "issue": "PostgreSQL performance degradation",
  "priority": "high"
}
```

**Response:**
```json
{
  "id": "inv-550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "agent-123",
  "issue": "PostgreSQL performance degradation",
  "status": "pending",
  "priority": "high",
  "created_at": "2025-12-30T10:30:00Z"
}
```

### Send Diagnostic Message (TensorZero Proxy)

This endpoint proxies requests to TensorZero AI based on the investigation ID.

```bash
POST /api/investigations
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "model": "tensorzero::function_name::diagnose_and_heal",
  "messages": [
    {
      "role": "user",
      "content": "System: Ubuntu 22.04, Kernel: 5.15.0-56\nCPU: 16 cores, Usage: 45%\nMemory: 64GB, Usage: 78%\n\nIssue: PostgreSQL is slow"
    }
  ],
  "investigation_id": "inv-550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (TensorZero Format):**
```json
{
  "id": "chatcmpl-123",
  "object": "chat.completion",
  "created": 1703001234,
  "model": "tensorzero::function_name::diagnose_and_heal",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "{\"response_type\":\"diagnostic\",\"reasoning\":\"Need to check PostgreSQL query performance and disk I/O\",\"commands\":[{\"id\":\"pg_stats\",\"command\":\"psql -c 'SELECT * FROM pg_stat_database'\",\"description\":\"Check database stats\"},{\"id\":\"disk_io\",\"command\":\"iostat -x 1 10\",\"description\":\"Monitor disk I/O\"}],\"ebpf_programs\":[{\"name\":\"disk_trace\",\"type\":\"tracepoint\",\"target\":\"block:block_rq_complete\",\"duration\":15,\"description\":\"Trace disk I/O operations\"}]}"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 200,
    "total_tokens": 350
  }
}
```

**Parsed Response Content:**
```json
{
  "response_type": "diagnostic",
  "reasoning": "Need to check PostgreSQL query performance and disk I/O",
  "commands": [
    {
      "id": "pg_stats",
      "command": "psql -c 'SELECT * FROM pg_stat_database'",
      "description": "Check database stats"
    },
    {
      "id": "disk_io",
      "command": "iostat -x 1 10",
      "description": "Monitor disk I/O"
    }
  ],
  "ebpf_programs": [
    {
      "name": "disk_trace",
      "type": "tracepoint",
      "target": "block:block_rq_complete",
      "duration": 15,
      "description": "Trace disk I/O operations"
    }
  ]
}
```

### Get Investigation

```bash
GET /api/investigations/{investigation_id}
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "id": "inv-550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "agent-123",
  "issue": "PostgreSQL performance degradation",
  "status": "in_progress",
  "priority": "high",
  "created_at": "2025-12-30T10:30:00Z",
  "updated_at": "2025-12-30T10:31:30Z",
  "resolution": null
}
```

## Metrics API

### Ingest System Metrics

```bash
POST /api/agent
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "agent_id": "agent-123",
  "timestamp": "2025-12-30T10:30:00Z",
  "hostname": "prod-web-01",
  "platform": "ubuntu",
  "platform_family": "debian",
  "platform_version": "22.04",
  "kernel_version": "5.15.0-56-generic",
  "kernel_arch": "x86_64",
  "os": "linux",
  "cpu_usage": 45.2,
  "cpu_cores": 16,
  "cpu_model": "Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz",
  "memory_usage": 50176.0,
  "memory_total": 67108864000,
  "memory_used": 52428800000,
  "memory_free": 8388608000,
  "memory_available": 14680064000,
  "swap_total": 8589934592,
  "swap_used": 0,
  "swap_free": 8589934592,
  "disk_usage": 67.8,
  "disk_total": 536870912000,
  "disk_used": 364088066048,
  "disk_free": 145680179200,
  "network_in_gb": 123.45,
  "network_out_gb": 67.89,
  "load_avg_1": 2.15,
  "load_avg_5": 1.98,
  "load_avg_15": 1.76,
  "process_count": 0,
  "ip_address": "10.0.1.5",
  "all_ips": ["10.0.1.5", "172.17.0.1"],
  "location": "unknown",
  "filesystem_info": [
    {
      "device": "/dev/sda1",
      "mountpoint": "/",
      "type": "ext4",
      "fstype": "ext4",
      "total": 536870912000,
      "used": 364088066048,
      "free": 145680179200,
      "usage": 67.8,
      "usage_percent": 67.8
    }
  ],
  "block_devices": [
    {
      "name": "sda",
      "size": 536870912000,
      "type": "disk",
      "model": "Samsung SSD 860",
      "serial_number": "S3Z9NB0K123456"
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

**Collection Frequency:** Every 30 seconds (default)

## Error Handling

### HTTP Status Codes

| Status Code | Meaning | Action |
|-------------|---------|--------|
| 200 | Success | Continue |
| 204 | No Content | Success (no response body) |
| 400 | Bad Request | Fix request format |
| 401 | Unauthorized | Refresh token |
| 403 | Forbidden | Check permissions |
| 404 | Not Found | Check endpoint URL |
| 429 | Too Many Requests | Implement exponential backoff |
| 500 | Internal Server Error | Retry with backoff |
| 503 | Service Unavailable | Retry with backoff |

### Error Response Format

```json
{
  "error": "unauthorized",
  "error_description": "Access token has expired",
  "timestamp": "2025-12-30T10:30:00Z"
}
```

### Retry Strategy

**SSE Connection Backoff:**

The SSE realtime connection uses exponential backoff with the following parameters:

```text
Initial Backoff: 30 seconds
Maximum Backoff: 30 minutes
Backoff Factor: 2.0
Retry Limit: Unlimited (agent always retries)

Attempt 0: 30 seconds
Attempt 1: 60 seconds
Attempt 2: 120 seconds (2 minutes)
Attempt 3: 240 seconds (4 minutes)
Attempt 4: 480 seconds (8 minutes)
Attempt 5: 960 seconds (16 minutes)
Attempt 6+: 1800 seconds (30 minutes max)
```

**Implementation:**
```go
const (
    InitialBackoff = 30 * time.Second
    MaxBackoff     = 30 * time.Minute
    BackoffFactor  = 2.0
)

func CalculateBackoff(attempt int) time.Duration {
    if attempt < 0 {
        attempt = 0
    }
    backoff := float64(InitialBackoff) * math.Pow(BackoffFactor, float64(attempt))
    if backoff > float64(MaxBackoff) {
        backoff = float64(MaxBackoff)
    }
    return time.Duration(backoff)
}
```

**HTTP Request Retry (Generic):**
```go
func retryWithBackoff(fn func() error, maxRetries int) error {
    for i := 0; i < maxRetries; i++ {
        err := fn()
        if err == nil {
            return nil
        }
        
        if i < maxRetries-1 {
            backoff := time.Duration(1<<uint(i)) * time.Second
            if backoff > 32*time.Second {
                backoff = 32 * time.Second
            }
            time.Sleep(backoff)
        }
    }
    return fmt.Errorf("max retries exceeded")
}
```

## Rate Limiting

**Current Limits:**
- Metrics ingestion: 2 requests per minute (1 every 30 seconds)
- Investigations: No limit (authenticated)
- Realtime SSE: 1 connection per agent

**Rate Limit Headers:**
```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1703001234
```

---

## Code Examples

### Complete Investigation Flow

```go
// 1. Create investigation
investigationResp, err := client.CreateInvestigation(
    accessToken,
    agentID,
    "PostgreSQL is slow",
    "high",
)

// 2. Send diagnostic request
messages := []types.ChatMessage{
    {
        Role: "user",
        Content: systemInfo + "\n" + issue,
    },
}

response, err := client.SendDiagnosticMessage(
    accessToken,
    "tensorzero::function_name::diagnose_and_heal",
    messages,
    investigationResp.ID,
)

// 3. Parse AI response
var diagnosticResp DiagnosticResponse
json.Unmarshal([]byte(response), &diagnosticResp)

// 4. Execute commands
for _, cmd := range diagnosticResp.Commands {
    result := executor.Execute(cmd.Command)
    results = append(results, result)
}

// 5. Start eBPF traces
for _, trace := range diagnosticResp.EBPFPrograms {
    go ebpfManager.StartTrace(trace)
}

// 6. Send results back
resultsMsg := types.ChatMessage{
    Role: "user",
    Content: formatResults(results, traces),
}
messages = append(messages, resultsMsg)

resolution, err := client.SendDiagnosticMessage(
    accessToken,
    "tensorzero::function_name::diagnose_and_heal",
    messages,
    investigationResp.ID,
)

// 7. Display resolution
fmt.Println(resolution)
```

### SSE Event Handling

```go
// Create handlers
investigationHandler := func(investigationID, prompt string) {
    agent.SetInvestigationID(investigationID)
    go agent.DiagnoseIssueWithInvestigation(prompt)
}

// Start SSE client with all handlers
client := realtime.NewClient(
    baseURL,
    accessToken,
    investigationHandler,
)

go client.Start() // Auto-reconnects with exponential backoff (30s initial, 30m max)
```

---

<div align="center">
  <p><strong>Next:</strong> <a href="./EBPF_MONITORING.md">eBPF Monitoring Guide</a></p>
  <p><em>NannyAgent - AI-Powered Linux Diagnostics</em></p>
</div>
