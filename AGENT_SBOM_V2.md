# Agent SBOM Vulnerability Scanning Guide

This guide explains how to configure NannyAgent to perform SBOM (Software Bill of Materials) vulnerability scanning and report findings to NannyAPI.

> **Note**: NannyAgent only supports **Linux** systems. The SBOM scanning functionality requires `syft` to be installed on the agent machine.

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

### Basic Upload

```bash
# Compress the SBOM
gzip -c /tmp/host-sbom.json > /tmp/host-sbom.json.gz

# Upload
curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F "sbom_archive=@/tmp/host-sbom.json.gz" \
  -F "scan_type=host" \
  -F "source_name=$(hostname)"
```

### Upload with Full Metadata

```bash
curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F "sbom_archive=@/tmp/sbom.json.gz" \
  -F "scan_type=container" \
  -F "source_name=web-frontend" \
  -F "source_type=podman"
```

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

## Complete Agent Script

Here's a complete script for automated SBOM scanning:

```bash
#!/bin/bash
#
# NannyAgent SBOM Scanner
# Generates and uploads host SBOM to NannyAPI
#

set -euo pipefail

# Configuration
NANNYAPI_URL="${NANNYAPI_URL:-http://localhost:8090}"
AGENT_TOKEN="${NANNYAPI_AGENT_TOKEN:-}"
SCAN_TYPE="${SCAN_TYPE:-host}"
LOG_FILE="${LOG_FILE:-/var/log/nannyagent-sbom.log}"

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
    
    if [[ -z "$AGENT_TOKEN" ]]; then
        log_error "NANNYAPI_AGENT_TOKEN is not set"
        exit 1
    fi
}

# Check if vulnerability scanning is enabled on API
check_api_status() {
    local status
    status=$(curl -s "${NANNYAPI_URL}/api/sbom/status")
    
    if echo "$status" | grep -q '"enabled":false'; then
        log_error "Vulnerability scanning is not enabled on the API"
        exit 1
    fi
    
    log "API vulnerability scanning is active"
}

# Generate SBOM
generate_sbom() {
    local sbom_file="$1"
    local scan_type="$2"
    local source="$3"
    
    log "Generating SBOM for ${scan_type}: ${source}"
    
    case "$scan_type" in
        host)
            syft scan dir:/ \
                --exclude '/proc/**' \
                --exclude '/sys/**' \
                --exclude '/dev/**' \
                --exclude '/run/**' \
                --exclude '/tmp/**' \
                --exclude '/var/cache/**' \
                --exclude '/var/log/**' \
                -o json > "$sbom_file" 2>/dev/null
            ;;
        container)
            syft scan "podman:${source}" -o json > "$sbom_file" 2>/dev/null || \
            syft scan "docker:${source}" -o json > "$sbom_file" 2>/dev/null
            ;;
        image)
            syft scan "$source" -o json > "$sbom_file" 2>/dev/null
            ;;
        *)
            log_error "Unknown scan type: $scan_type"
            exit 1
            ;;
    esac
    
    if [[ ! -s "$sbom_file" ]]; then
        log_error "Failed to generate SBOM"
        exit 1
    fi
    
    log "SBOM generated: $(du -h "$sbom_file" | cut -f1)"
}

# Upload SBOM to API
upload_sbom() {
    local sbom_file="$1"
    local scan_type="$2"
    local source_name="$3"
    
    local compressed_file="${sbom_file}.gz"
    
    log "Compressing SBOM..."
    gzip -c "$sbom_file" > "$compressed_file"
    log "Compressed: $(du -h "$compressed_file" | cut -f1)"
    
    log "Uploading to ${NANNYAPI_URL}..."
    
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "${NANNYAPI_URL}/api/sbom/upload" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -F "sbom_archive=@${compressed_file}" \
        -F "scan_type=${scan_type}" \
        -F "source_name=${source_name}")
    
    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" != "200" ]]; then
        log_error "Upload failed with HTTP $http_code: $body"
        rm -f "$compressed_file"
        exit 1
    fi
    
    # Parse vulnerability counts
    local critical high medium low total
    critical=$(echo "$body" | grep -o '"critical":[0-9]*' | cut -d: -f2 || echo "0")
    high=$(echo "$body" | grep -o '"high":[0-9]*' | cut -d: -f2 || echo "0")
    medium=$(echo "$body" | grep -o '"medium":[0-9]*' | cut -d: -f2 || echo "0")
    low=$(echo "$body" | grep -o '"low":[0-9]*' | cut -d: -f2 || echo "0")
    total=$(echo "$body" | grep -o '"total":[0-9]*' | cut -d: -f2 || echo "0")
    
    log "Scan complete: ${total} vulnerabilities (Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low})"
    
    rm -f "$compressed_file"
}

# Main
main() {
    local temp_sbom
    temp_sbom=$(mktemp /tmp/nannyagent-sbom.XXXXXX.json)
    trap "rm -f $temp_sbom ${temp_sbom}.gz" EXIT
    
    check_requirements
    check_api_status
    
    local source_name
    case "$SCAN_TYPE" in
        host)
            source_name=$(hostname -f 2>/dev/null || hostname)
            ;;
        container|image)
            source_name="${1:-unknown}"
            ;;
    esac
    
    generate_sbom "$temp_sbom" "$SCAN_TYPE" "$source_name"
    upload_sbom "$temp_sbom" "$SCAN_TYPE" "$source_name"
    
    log "SBOM scan completed successfully"
}

main "$@"
```

Save this as `/usr/local/bin/nannyagent-sbom` and make it executable:

```bash
sudo chmod +x /usr/local/bin/nannyagent-sbom
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
    
    sbom_file=$(mktemp)
    syft scan "podman:${container}" -o json > "$sbom_file"
    gzip -c "$sbom_file" > "${sbom_file}.gz"
    
    curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -F "sbom_archive=@${sbom_file}.gz" \
        -F "scan_type=container" \
        -F "source_name=${name}" \
        -F "source_type=podman"
    
    rm -f "$sbom_file" "${sbom_file}.gz"
done
```

### CI/CD Integration

Add to your pipeline after building images:

```yaml
# GitLab CI example
sbom-scan:
  stage: security
  script:
    - syft scan ${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA} -o json > sbom.json
    - gzip -c sbom.json > sbom.json.gz
    - |
      curl -X POST "${NANNYAPI_URL}/api/sbom/upload" \
        -H "Authorization: Bearer ${NANNYAPI_AGENT_TOKEN}" \
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
