# Agent SBOM Vulnerability Scanning Guide

This guide explains how to configure NannyAgent to perform SBOM (Software Bill of Materials) vulnerability scanning and report findings to NannyAPI.

> **Note**: NannyAgent only supports **Linux** systems. The SBOM scanning functionality requires `syft` to be installed on the agent machine.

## API Quick Reference

### Base URL
All SBOM endpoints are prefixed with `/api/sbom`

### Authentication
All endpoints (except `/api/sbom/status`) require authentication via Bearer token:
```
Authorization: Bearer <AGENT_TOKEN or USER_TOKEN>
```

### Endpoints Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/sbom/status` | None | Check if vulnerability scanning is enabled |
| POST | `/api/sbom/request` | User only | Request a new scan (creates pending scan record) |
| GET | `/api/sbom/pending` | Agent only | Get pending scans for the agent |
| POST | `/api/sbom/scans/{id}/acknowledge` | Agent | Acknowledge a pending scan (status → scanning) |
| POST | `/api/sbom/upload` | Agent/User | Upload SBOM results (agent MUST include `scan_id`) |
| PATCH | `/api/sbom/scans/{id}/status` | Agent/User | Update scan status (completed/failed) |
| GET | `/api/sbom/scans` | Agent/User | List scans |
| GET | `/api/sbom/scans/{id}` | Agent/User | Get scan details |
| GET | `/api/sbom/scans/{id}/vulnerabilities` | Agent/User | Get vulnerabilities for a scan |
| GET | `/api/sbom/agents/{agentId}/summary` | User | Get agent vulnerability summary |
| GET | `/api/sbom/agents/{agentId}/vulnerabilities` | User | Get agent vulnerabilities |
| GET | `/api/sbom/config/syft` | Agent | Get agent's syft config |
| GET | `/api/sbom/agents/{agentId}/syft-config` | User | Get specific agent's syft config |
| PUT | `/api/sbom/agents/{agentId}/syft-config` | User | Update agent's syft config |
| POST | `/api/sbom/db/update` | Admin | Trigger Grype DB update |

---

## User-Initiated Scan Workflow (Required)

**Important:** Only users can initiate scans. Agents must follow this workflow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SBOM SCAN WORKFLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. USER: POST /api/sbom/request                                            │
│     └─> Creates scan record with status="pending"                           │
│     └─> Returns { scan_id: "abc123", status: "pending" }                    │
│                                                                              │
│  2. AGENT: GET /api/sbom/pending                                            │
│     └─> Polls for pending scans                                             │
│     └─> Returns list of scans with scan_id                                  │
│                                                                              │
│  3. AGENT: POST /api/sbom/scans/{scan_id}/acknowledge                       │
│     └─> Updates status to "scanning"                                        │
│                                                                              │
│  4. AGENT: Runs syft to generate SBOM                                       │
│                                                                              │
│  5. AGENT: POST /api/sbom/upload (with scan_id!)                           │
│     └─> Uploads SBOM with scan_id form field                                │
│     └─> API processes and updates existing record                           │
│                                                                              │
│  6. (On failure) AGENT: PATCH /api/sbom/scans/{scan_id}/status             │
│     └─> Updates status to "failed" with error message                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: User Requests Scan

```bash
# User requests a scan for their agent
curl -X POST "${NANNYAPI_URL}/api/sbom/request" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "ns3tcef0wgl509h",
    "scan_type": "host",
    "source_name": "my-server"
  }'
```

**Response:**
```json
{
  "scan_id": "ko9u8v0fy1be2qz",
  "agent_id": "ns3tcef0wgl509h",
  "scan_type": "host",
  "status": "pending",
  "source_name": "my-server"
}
```

### Step 2: Agent Polls for Pending Scans

```bash
# Agent checks for pending scans
curl -s "${NANNYAPI_URL}/api/sbom/pending" \
  -H "Authorization: Bearer ${AGENT_TOKEN}"
```

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "ko9u8v0fy1be2qz",
      "scan_type": "host",
      "source_name": "my-server",
      "source_type": "",
      "status": "pending"
    }
  ],
  "total": 1
}
```

### Step 3: Agent Acknowledges Scan

```bash
# Agent acknowledges the scan (status changes to "scanning")
curl -X POST "${NANNYAPI_URL}/api/sbom/scans/ko9u8v0fy1be2qz/acknowledge" \
  -H "Authorization: Bearer ${AGENT_TOKEN}"
```

**Response:**
```json
{
  "success": true,
  "scan_id": "ko9u8v0fy1be2qz",
  "status": "scanning"
}
```

### Step 4: Agent Generates SBOM

```bash
# Generate SBOM using syft
syft scan dir:/ \
  --exclude '/proc/**' \
  --exclude '/sys/**' \
  --exclude '/dev/**' \
  --exclude '/run/**' \
  --exclude '/tmp/**' \
  -o json > /tmp/host-sbom.json

# Compress for upload
gzip -c /tmp/host-sbom.json > /tmp/host-sbom.json.gz
```

### Step 5: Agent Uploads SBOM with scan_id (CRITICAL!)

```bash
# Upload with scan_id - THIS IS REQUIRED FOR AGENTS
curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F "scan_id=ko9u8v0fy1be2qz" \
  -F "sbom_archive=@/tmp/host-sbom.json.gz" \
  -F "scan_type=host" \
  -F "source_name=$(hostname)"
```

**Response:**
```json
{
  "scan_id": "ko9u8v0fy1be2qz",
  "status": "completed",
  "message": "SBOM scanned successfully",
  "vuln_counts": {
    "critical": 0,
    "high": 1050,
    "medium": 16504,
    "low": 6379,
    "total": 24145
  }
}
```

> **⚠️ Important:** Agents MUST include the `scan_id` form field. Without it, the API returns:
> ```json
> {"error": "scan_id is required. Only users can initiate new scans."}
> ```

### Step 6: Update Status on Failure (if needed)

If the scan fails (e.g., syft error), update the status:

```bash
curl -X PATCH "${NANNYAPI_URL}/api/sbom/scans/ko9u8v0fy1be2qz/status" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "failed",
    "error_message": "syft scan failed: command not found"
  }'
```

**Response:**
```json
{
  "success": true,
  "scan_id": "ko9u8v0fy1be2qz",
  "status": "failed"
}
```

---

## Prerequisites

1. **NannyAPI** with vulnerability scanning enabled (`--enable-vuln-scan`)
2. **Syft** installed on the agent machine (Linux only)
3. Agent registered with NannyAPI and has a valid authentication token

## Installing Syft

Syft is used to generate SBOMs from the host filesystem or containers.

### Linux (via install script)

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

### Verify Installation

```bash
syft version
```

## Recommended Compression Format

When uploading SBOMs to NannyAPI, **gzip (`.gz`) is the recommended compression format** for the following reasons:

- **Best compression ratio** for JSON data (typically 85-95% size reduction)
- **Native support** on all Linux distributions without additional tools
- **Fastest decompression** compared to other formats
- **Widely supported** in CI/CD pipelines and automation scripts

Supported formats:
- `.gz` - **Recommended** - Best balance of compression and speed
- `.tar.gz` / `.tgz` - Good for multiple SBOMs bundled together
- `.bz2` - Higher compression but slower (use for archival only)
- Uncompressed JSON - Acceptable for small SBOMs (<1MB)

Example compression:
```bash
# Recommended: gzip compression
gzip -c sbom.json > sbom.json.gz

# Alternative: tar.gz for multiple files
tar -czf sboms.tar.gz host-sbom.json container-*.json
```

## SBOM Generation

### Full Host Scan

Generate an SBOM for the entire host filesystem:

```bash
syft scan dir:/ -o json > /tmp/host-sbom.json
```

### Optimized Host Scan

Exclude unnecessary directories for faster scans:

```bash
syft scan dir:/ \
  --exclude '/proc/**' \
  --exclude '/sys/**' \
  --exclude '/dev/**' \
  --exclude '/run/**' \
  --exclude '/tmp/**' \
  --exclude '/var/cache/**' \
  --exclude '/var/log/**' \
  --exclude '/home/*/.cache/**' \
  -o json > /tmp/host-sbom.json
```

### Container Scan (Podman)

```bash
# Running container
syft scan podman:container-name -o json > /tmp/container-sbom.json

# Image
syft scan podman:localhost/my-image:latest -o json > /tmp/image-sbom.json
```

### Container Scan (Docker)

```bash
# Running container
syft scan docker:container-name -o json > /tmp/container-sbom.json

# Image
syft scan docker:my-image:latest -o json > /tmp/image-sbom.json
```

## Superuser Configuration (Portal Settings)

Superusers can configure SBOM scanning settings directly from the portal without needing CLI access. The following settings are available in the `sbom_settings` collection:

| Setting Key | Description | Default | Type |
|-------------|-------------|---------|------|
| `grype_db_update_cron` | Cron expression for automatic Grype DB updates | `0 3 * * *` (daily at 3 AM) | cron |
| `grype_db_auto_update` | Enable/disable automatic Grype DB updates | `true` | bool |
| `default_min_severity` | Default minimum severity filter for API responses | `low` | string |
| `default_min_cvss` | Default minimum CVSS score filter (0.0-10.0) | `0` | number |
| `scans_per_agent` | Maximum SBOM scans to retain per agent | `10` | number |
| `retention_days` | How long to keep vulnerability scan data | `90` | number |
| `default_syft_exclude_patterns` | Default syft exclusion patterns (JSON array) | See below | json |

**Default Syft Exclude Patterns:**
```json
["**/proc/**", "**/sys/**", "**/dev/**", "**/run/**", "**/tmp/**", "**/var/cache/**", "**/var/log/**", "**/home/*/.cache/**"]
```

**Managing settings via API:**

```bash
# List all SBOM settings (superuser only)
curl -s "${NANNYAPI_URL}/api/collections/sbom_settings/records" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Update a setting (superuser only)
curl -X PATCH "${NANNYAPI_URL}/api/collections/sbom_settings/records/${SETTING_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "0 4 * * *"}'
```

## Per-Agent Syft Configuration

Users can configure per-agent syft exclusion patterns. This allows fine-grained control over what directories/files the agent scans when generating SBOMs.

### Get Agent's Syft Config

**As an agent** (gets its own config):
```bash
curl -s "${NANNYAPI_URL}/api/sbom/config/syft" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq
```

**As a user** (gets config for a specific agent):
```bash
curl -s "${NANNYAPI_URL}/api/sbom/agents/${AGENT_ID}/syft-config" \
  -H "Authorization: Bearer ${USER_TOKEN}" | jq
```

**Response:**
```json
{
  "exclude_patterns": [
    "**/proc/**",
    "**/sys/**",
    "**/dev/**",
    "**/run/**",
    "**/tmp/**"
  ]
}
```

### Update Agent's Syft Config

Users can set custom exclusion patterns for their agents:

```bash
curl -X PUT "${NANNYAPI_URL}/api/sbom/agents/${AGENT_ID}/syft-config" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "exclude_patterns": [
      "**/proc/**",
      "**/sys/**",
      "**/dev/**",
      "**/run/**",
      "**/tmp/**",
      "**/var/cache/**",
      "**/var/log/**",
      "**/home/*/.cache/**",
      "**/opt/backups/**"
    ]
  }'
```

The agent should fetch its config before running syft and apply the exclusion patterns:

```bash
# Fetch exclusion patterns from API
EXCLUDE_PATTERNS=$(curl -s "${NANNYAPI_URL}/api/sbom/config/syft" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq -r '.exclude_patterns[]')

# Build syft exclude arguments
EXCLUDE_ARGS=""
for pattern in $EXCLUDE_PATTERNS; do
    EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude '$pattern'"
done

# Run syft with configured exclusions
eval "syft scan dir:/ $EXCLUDE_ARGS -o json > /tmp/host-sbom.json"
```

## Storage Architecture

**Important:** Vulnerability data is now stored efficiently to prevent database bloat:

1. **Grype output archives** are stored as `.tar.gz` files in `pb_data/storage/sbom_archives/{agent_id}/`
2. **Only metadata and counts** are stored in the database (`sbom_scans` collection)
3. **Vulnerabilities are loaded on-demand** from archives when requested
4. **Automatic retention** enforces the `scans_per_agent` limit (default: 10 scans per agent)

This architecture prevents the database from growing unbounded while still allowing full access to vulnerability details.

## Uploading SBOMs to NannyAPI

### Agent Upload (with scan_id - REQUIRED)

Agents must always include the `scan_id` from a user-initiated scan request:

```bash
# Compress the SBOM
gzip -c /tmp/host-sbom.json > /tmp/host-sbom.json.gz

# Upload with scan_id (REQUIRED for agents)
curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F "scan_id=${SCAN_ID}" \
  -F "sbom_archive=@/tmp/host-sbom.json.gz" \
  -F "scan_type=host" \
  -F "source_name=$(hostname)"
```

### User Upload (can create new scan)

Users can upload directly without a pre-existing scan_id:

```bash
curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "X-Agent-ID: ${AGENT_ID}" \
  -F "sbom_archive=@/tmp/sbom.json.gz" \
  -F "scan_type=host" \
  -F "source_name=$(hostname)"
```

### Upload Form Fields

| Field | Required | Description |
|-------|----------|-------------|
| `sbom_archive` | Yes | The gzipped SBOM JSON file |
| `scan_id` | **Yes for agents** | The scan ID from `/api/sbom/pending` |
| `scan_type` | No | `host`, `container`, or `image` (default: `image`) |
| `source_name` | No | Name of the scanned source (defaults to filename) |
| `source_type` | No | Type hint (e.g., `podman`, `docker`, `registry`) |

### Response

```json
{
  "scan_id": "abc123def456",
  "status": "completed",
  "message": "SBOM scanned successfully",
  "vuln_counts": {
    "critical": 2,
    "high": 15,
    "medium": 42,
    "low": 89,
    "total": 148
  }
}
```

## Complete Agent Implementation

Here's a complete implementation showing how the agent should handle user-initiated SBOM scans:

```bash
#!/bin/bash
#
# NannyAgent SBOM Scanner
# Handles user-initiated SBOM scan requests
#

set -euo pipefail

# Configuration
NANNYAPI_URL="${NANNYAPI_URL:-http://localhost:8090}"
AGENT_TOKEN="${NANNYAPI_AGENT_TOKEN:-}"
LOG_FILE="${LOG_FILE:-/var/log/nannyagent-sbom.log}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE" >&2
}

# Validate requirements
check_requirements() {
    if ! command -v syft &> /dev/null; then
        log_error "syft is not installed"
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        log_error "curl is not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq is not installed"
        exit 1
    fi
    
    if [[ -z "$AGENT_TOKEN" ]]; then
        log_error "NANNYAPI_AGENT_TOKEN is not set"
        exit 1
    fi
}

# Check if vulnerability scanning is enabled on API
check_api_status() {
    local status
    status=$(curl -s "${NANNYAPI_URL}/api/sbom/status")
    
    if echo "$status" | jq -e '.enabled == false' > /dev/null 2>&1; then
        log_error "Vulnerability scanning is not enabled on the API"
        return 1
    fi
    
    return 0
}

# Get pending scans for this agent
get_pending_scans() {
    curl -s "${NANNYAPI_URL}/api/sbom/pending" \
        -H "Authorization: Bearer ${AGENT_TOKEN}"
}

# Acknowledge a scan (status: pending -> scanning)
acknowledge_scan() {
    local scan_id="$1"
    curl -s -X POST "${NANNYAPI_URL}/api/sbom/scans/${scan_id}/acknowledge" \
        -H "Authorization: Bearer ${AGENT_TOKEN}"
}

# Update scan status on failure
update_scan_status() {
    local scan_id="$1"
    local status="$2"
    local error_message="${3:-}"
    
    local payload="{\"status\": \"${status}\""
    if [[ -n "$error_message" ]]; then
        payload="${payload}, \"error_message\": \"${error_message}\""
    fi
    payload="${payload}}"
    
    curl -s -X PATCH "${NANNYAPI_URL}/api/sbom/scans/${scan_id}/status" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload"
}

# Get syft exclusion patterns from API
get_syft_config() {
    local config
    config=$(curl -s "${NANNYAPI_URL}/api/sbom/config/syft" \
        -H "Authorization: Bearer ${AGENT_TOKEN}")
    
    echo "$config" | jq -r '.exclude_patterns // [] | .[]' 2>/dev/null || true
}

# Generate SBOM
generate_sbom() {
    local sbom_file="$1"
    local scan_type="$2"
    local source_name="$3"
    
    log "Generating SBOM for ${scan_type}: ${source_name}"
    
    # Get exclusion patterns from API
    local exclude_args=""
    while IFS= read -r pattern; do
        if [[ -n "$pattern" ]]; then
            exclude_args="$exclude_args --exclude '$pattern'"
        fi
    done < <(get_syft_config)
    
    case "$scan_type" in
        host)
            if [[ -n "$exclude_args" ]]; then
                eval "syft scan dir:/ $exclude_args -o json > '$sbom_file' 2>/dev/null"
            else
                syft scan dir:/ -o json > "$sbom_file" 2>/dev/null
            fi
            ;;
        container)
            syft scan "podman:${source_name}" -o json > "$sbom_file" 2>/dev/null || \
            syft scan "docker:${source_name}" -o json > "$sbom_file" 2>/dev/null
            ;;
        image)
            syft scan "$source_name" -o json > "$sbom_file" 2>/dev/null
            ;;
        *)
            log_error "Unknown scan type: $scan_type"
            return 1
            ;;
    esac
    
    if [[ ! -s "$sbom_file" ]]; then
        log_error "Failed to generate SBOM"
        return 1
    fi
    
    log "SBOM generated: $(du -h "$sbom_file" | cut -f1)"
    return 0
}

# Upload SBOM to API with scan_id
upload_sbom() {
    local scan_id="$1"
    local sbom_file="$2"
    local scan_type="$3"
    local source_name="$4"
    
    local compressed_file="${sbom_file}.gz"
    
    log "Compressing SBOM..."
    gzip -c "$sbom_file" > "$compressed_file"
    log "Compressed: $(du -h "$compressed_file" | cut -f1)"
    
    log "Uploading to ${NANNYAPI_URL} (scan_id: ${scan_id})..."
    
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "${NANNYAPI_URL}/api/sbom/upload" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -F "scan_id=${scan_id}" \
        -F "sbom_archive=@${compressed_file}" \
        -F "scan_type=${scan_type}" \
        -F "source_name=${source_name}")
    
    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')
    
    rm -f "$compressed_file"
    
    if [[ "$http_code" != "200" ]]; then
        log_error "Upload failed with HTTP $http_code: $body"
        return 1
    fi
    
    # Parse vulnerability counts
    local total
    total=$(echo "$body" | jq -r '.vuln_counts.total // 0')
    local critical
    critical=$(echo "$body" | jq -r '.vuln_counts.critical // 0')
    local high
    high=$(echo "$body" | jq -r '.vuln_counts.high // 0')
    
    log "Scan ${scan_id} complete: ${total} vulnerabilities (Critical: ${critical}, High: ${high})"
    return 0
}

# Process a single scan request
process_scan() {
    local scan_id="$1"
    local scan_type="$2"
    local source_name="$3"
    
    log "Processing scan: ${scan_id} (type: ${scan_type})"
    
    # Acknowledge the scan first
    local ack_response
    ack_response=$(acknowledge_scan "$scan_id")
    if ! echo "$ack_response" | jq -e '.success == true' > /dev/null 2>&1; then
        log_error "Failed to acknowledge scan ${scan_id}: $ack_response"
        return 1
    fi
    log "Scan ${scan_id} acknowledged"
    
    # Create temp file for SBOM
    local temp_sbom
    temp_sbom=$(mktemp /tmp/nannyagent-sbom.XXXXXX.json)
    trap "rm -f '$temp_sbom' '${temp_sbom}.gz'" RETURN
    
    # Determine source name if not provided
    if [[ -z "$source_name" ]]; then
        case "$scan_type" in
            host)
                source_name=$(hostname -f 2>/dev/null || hostname)
                ;;
            *)
                source_name="unknown"
                ;;
        esac
    fi
    
    # Generate SBOM
    if ! generate_sbom "$temp_sbom" "$scan_type" "$source_name"; then
        log_error "SBOM generation failed for scan ${scan_id}"
        update_scan_status "$scan_id" "failed" "SBOM generation failed"
        return 1
    fi
    
    # Upload SBOM with scan_id
    if ! upload_sbom "$scan_id" "$temp_sbom" "$scan_type" "$source_name"; then
        log_error "SBOM upload failed for scan ${scan_id}"
        update_scan_status "$scan_id" "failed" "SBOM upload failed"
        return 1
    fi
    
    log "Scan ${scan_id} completed successfully"
    return 0
}

# Main loop - poll for pending scans
main_loop() {
    log "Starting SBOM scan handler (poll interval: ${POLL_INTERVAL}s)"
    
    while true; do
        if ! check_api_status; then
            log "API not available, retrying in ${POLL_INTERVAL}s..."
            sleep "$POLL_INTERVAL"
            continue
        fi
        
        # Get pending scans
        local pending
        pending=$(get_pending_scans)
        
        local scan_count
        scan_count=$(echo "$pending" | jq -r '.total // 0')
        
        if [[ "$scan_count" -gt 0 ]]; then
            log "Found ${scan_count} pending scan(s)"
            
            # Process each pending scan
            echo "$pending" | jq -c '.scans[]' | while read -r scan; do
                local scan_id scan_type source_name
                scan_id=$(echo "$scan" | jq -r '.scan_id')
                scan_type=$(echo "$scan" | jq -r '.scan_type // "host"')
                source_name=$(echo "$scan" | jq -r '.source_name // ""')
                
                process_scan "$scan_id" "$scan_type" "$source_name" || true
            done
        fi
        
        sleep "$POLL_INTERVAL"
    done
}

# One-shot mode - process pending scans once
main_oneshot() {
    check_requirements
    
    if ! check_api_status; then
        log_error "API not available"
        exit 1
    fi
    
    local pending
    pending=$(get_pending_scans)
    
    local scan_count
    scan_count=$(echo "$pending" | jq -r '.total // 0')
    
    if [[ "$scan_count" -eq 0 ]]; then
        log "No pending scans"
        exit 0
    fi
    
    log "Processing ${scan_count} pending scan(s)"
    
    local exit_code=0
    echo "$pending" | jq -c '.scans[]' | while read -r scan; do
        local scan_id scan_type source_name
        scan_id=$(echo "$scan" | jq -r '.scan_id')
        scan_type=$(echo "$scan" | jq -r '.scan_type // "host"')
        source_name=$(echo "$scan" | jq -r '.source_name // ""')
        
        if ! process_scan "$scan_id" "$scan_type" "$source_name"; then
            exit_code=1
        fi
    done
    
    exit $exit_code
}

# Entry point
case "${1:-oneshot}" in
    daemon)
        check_requirements
        main_loop
        ;;
    oneshot|*)
        main_oneshot
        ;;
esac
```

Save this as `/usr/local/bin/nannyagent-sbom` and make it executable:

```bash
sudo chmod +x /usr/local/bin/nannyagent-sbom
```

### Usage

```bash
# One-shot mode (process pending scans and exit)
NANNYAPI_AGENT_TOKEN=xxx /usr/local/bin/nannyagent-sbom

# Daemon mode (continuous polling)
NANNYAPI_AGENT_TOKEN=xxx /usr/local/bin/nannyagent-sbom daemon
```

## Scheduling Scans

### Using Cron

Add to `/etc/cron.d/nannyagent-sbom`:

```cron
# Run host SBOM scan daily at 4 AM
0 4 * * * root NANNYAPI_URL=https://api.example.com NANNYAPI_AGENT_TOKEN=your-token /usr/local/bin/nannyagent-sbom >> /var/log/nannyagent-sbom.log 2>&1
```

### Using Systemd Timer

Create `/etc/systemd/system/nannyagent-sbom.service`:

```ini
[Unit]
Description=NannyAgent SBOM Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nannyagent-sbom
Environment=NANNYAPI_URL=https://api.example.com
Environment=NANNYAPI_AGENT_TOKEN=your-token
StandardOutput=append:/var/log/nannyagent-sbom.log
StandardError=append:/var/log/nannyagent-sbom.log
```

Create `/etc/systemd/system/nannyagent-sbom.timer`:

```ini
[Unit]
Description=Run NannyAgent SBOM Scanner daily

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nannyagent-sbom.timer
```

## Container Scanning

### Scan All Running Containers

```bash
#!/bin/bash
# Scan all running Podman containers

NANNYAPI_URL="${NANNYAPI_URL:-http://localhost:8090}"
AGENT_TOKEN="${NANNYAPI_AGENT_TOKEN}"

for container in $(podman ps -q); do
    name=$(podman inspect -f '{{.Name}}' "$container")
    echo "Scanning container: $name"
    
    # Note: For containers, user should first request scan via API
    # This example assumes scan_id is obtained from /api/sbom/pending
    
    sbom_file=$(mktemp)
    syft scan "podman:${container}" -o json > "$sbom_file"
    gzip -c "$sbom_file" > "${sbom_file}.gz"
    
    # Agent must include scan_id from pending scans
    curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -F "scan_id=${SCAN_ID}" \
        -F "sbom_archive=@${sbom_file}.gz" \
        -F "scan_type=container" \
        -F "source_name=${name}" \
        -F "source_type=podman"
    
    rm -f "$sbom_file" "${sbom_file}.gz"
done
```

### CI/CD Integration (User-Initiated)

For CI/CD, users can upload directly since they're authenticated as users:

```yaml
# GitLab CI example - User uploads directly (no scan_id needed)
sbom-scan:
  stage: security
  script:
    - syft scan ${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA} -o json > sbom.json
    - gzip -c sbom.json > sbom.json.gz
    - |
      curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
        -H "Authorization: Bearer ${USER_TOKEN}" \
        -H "X-Agent-ID: ${AGENT_ID}" \
        -F "sbom_archive=@sbom.json.gz" \
        -F "scan_type=image" \
        -F "source_name=${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}" \
        -F "source_type=registry"
```

## Viewing Results

### Via API

```bash
# Get vulnerability summary for your agent
curl -s "${NANNYAPI_URL}/api/sbom/agents/${AGENT_ID}/summary" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq

# List recent scans
curl -s "${NANNYAPI_URL}/api/sbom/scans" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq

# Get critical vulnerabilities
curl -s "${NANNYAPI_URL}/api/sbom/scans/${SCAN_ID}/vulnerabilities?severity=critical" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq
```

### Advanced Vulnerability Filtering

The API supports powerful filtering to reduce noise and focus on actionable vulnerabilities:

```bash
# Filter by multiple severities (critical and high only)
curl -s "${NANNYAPI_URL}/api/sbom/scans/${SCAN_ID}/vulnerabilities?severities=critical,high" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq

# Filter by minimum CVSS score (7.0 or higher)
curl -s "${NANNYAPI_URL}/api/sbom/scans/${SCAN_ID}/vulnerabilities?min_cvss=7.0" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq

# Filter by fix availability (only fixable vulnerabilities)
curl -s "${NANNYAPI_URL}/api/sbom/scans/${SCAN_ID}/vulnerabilities?fix_state=fixed" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq

# Combine filters: critical/high with CVSS >= 8.0 that have fixes available
curl -s "${NANNYAPI_URL}/api/sbom/scans/${SCAN_ID}/vulnerabilities?severities=critical,high&min_cvss=8.0&fix_state=fixed" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq

# Get agent-wide vulnerabilities with filtering
curl -s "${NANNYAPI_URL}/api/sbom/agents/${AGENT_ID}/vulnerabilities?severities=critical,high&min_cvss=7.0" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" | jq
```

**Available filter parameters:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `severity` | Single severity (backward compatibility) | `severity=critical` |
| `severities` | Multiple severities (comma-separated) | `severities=critical,high` |
| `min_cvss` | Minimum CVSS score (0.0-10.0) | `min_cvss=7.0` |
| `fix_state` | Fix availability: `fixed`, `not-fixed`, `wont-fix`, `unknown` | `fix_state=fixed` |
| `fixable` | **Deprecated** - Use `fix_state=fixed` instead | `fixable=true` |
| `limit` | Max results per page (default: 100, max: 500) | `limit=50` |
| `offset` | Pagination offset | `offset=100` |

### Via Frontend Dashboard

The NannyAI frontend provides a visual dashboard showing:

- Vulnerability trends over time
- Per-agent vulnerability counts
- Fixable vs unfixable vulnerabilities
- Detailed CVE information with links

## Troubleshooting

### Check API Status

```bash
curl -s "${NANNYAPI_URL}/api/sbom/status" | jq
```

If `enabled` is `false`, ask your administrator to enable vulnerability scanning.

### Syft Errors

```bash
# Check syft version
syft version

# Run with debug output
syft scan dir:/ -o json -v 2>&1 | head -100
```

### Upload Failures

```bash
# Test with verbose curl
curl -v -X POST "${NANNYAPI_URL}/api/sbom/upload" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F "sbom_archive=@sbom.json.gz"
```

### Large SBOM Issues

If your SBOM exceeds the 50MB limit:

1. Use gzip compression (reduces size by ~90%)
2. Exclude unnecessary directories
3. Scan specific paths instead of full filesystem

```bash
# Scan only installed packages
syft scan dir:/usr -o json > /tmp/sbom.json
```
