# Configuration Guide

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Configuration Management</h1>
</div>

## Table of Contents

- [Overview](#overview)
- [Configuration Priority](#configuration-priority)
- [Authentication Modes](#authentication-modes)
- [Command-Line Arguments](#command-line-arguments)
- [Validation Rules](#validation-rules)
- [Configuration File](#configuration-file)
- [Environment Variables](#environment-variables)
- [Configuration Options](#configuration-options)
- [Usage Examples](#usage-examples)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

NannyAgent uses a simple, secure configuration system with three sources:

1. **YAML configuration file**: `/etc/nannyagent/config.yaml`
2. **Environment variables**: Override YAML settings
3. **Command-line arguments**: Highest priority, override both YAML and env vars

This design provides flexibility for different deployment scenarios while maintaining security.

## Configuration Priority

Configuration is loaded in the following order (later sources override earlier):

1. `/etc/nannyagent/config.yaml` (system-wide YAML config)
2. Environment variables (override YAML)
3. Command-line arguments (highest priority - override everything)

## Authentication Modes

NannyAgent supports two authentication modes:

### OAuth2 Device Flow (default)

The traditional interactive registration flow. Requires a user to approve the agent
in the NannyAI portal.

```bash
sudo nannyagent --register
# Follow the portal instructions to enter the user code
```

### Static Token (automated, no user interaction)

Static tokens bypass the entire OAuth2 flow. The agent auto-registers using the
static token as a user credential. Ideal for automation and fleet deployment.

**Setup:**

1. Create a static token in the NannyAI portal (or via API `create-static-token`)
2. Add it to `/etc/nannyagent/config.yaml`:
   ```yaml
   nannyapi_url: "https://api.nannyai.dev"
   static_token: "nsk_your_token_here"
   ```
3. Register the agent (fully automated, no portal interaction):
   ```bash
   sudo nannyagent --register
   ```
4. Start the service:
   ```bash
   sudo systemctl enable --now nannyagent
   ```

**How it works:**

- Registration sends a single `POST /api/agent` with `action: "register-with-token"`
  and system information (hostname, OS, IPs, kernel version)
- The static token (prefixed `nsk_`) is sent as `Authorization: Bearer nsk_...`
- No device authorization flow is triggered — no device codes, user codes, or polling
- An `X-Agent-ID` header identifies the specific agent after registration
- No access token refresh or renewal is needed — the static token is long-lived
- The `agent_id` is auto-saved to `/etc/nannyagent/config.yaml` after registration

**Environment variable alternative:**

```bash
export NANNYAI_STATIC_TOKEN=nsk_your_token_here
```

> **Security:** The `static_token` is intentionally NOT available as a CLI argument
> to prevent exposure in the process list. Use the config file or env var only.

## Command-Line Arguments

All YAML configuration options are available as CLI flags with the highest priority.

| Flag | YAML Key | Description |
|------|----------|-------------|
| `--api-url <url>` | `nannyapi_url` | NannyAPI endpoint URL |
| `--portal-url <url>` | `portal_url` | Portal URL for device auth |
| `--token-path <path>` | `token_path` | Token storage path |
| `--metrics-interval <secs>` | `metrics_interval` | Metrics collection interval |
| `--proxmox-interval <secs>` | `proxmox_interval` | Proxmox data collection interval |
| `--agent-id <id>` | `agent_id` | Agent ID (static token mode) |
| `--debug` | `debug` | Enable debug mode |

**Commands:**

| Flag | Description |
|------|-------------|
| `--register` | Register agent (interactive or automated with static token) |
| `--status` | Show agent status and connectivity |
| `--diagnose <issue>` | Run one-off diagnosis |
| `--daemon` | Run as daemon (systemd mode) |
| `--version` | Show version |
| `--help` | Show help |

**Examples:**

```bash
# Register with a specific API URL
sudo nannyagent --register --api-url http://localhost:8090

# Run in debug mode with custom metrics interval
sudo nannyagent --daemon --debug --metrics-interval 60

# One-off diagnosis with custom API URL
sudo nannyagent --diagnose "disk full on /var" --api-url http://my-api:8090
```

## Validation Rules

All configuration values are validated regardless of source (YAML, environment
variable, or CLI flag). Validation runs twice: once after loading config + env,
and again after CLI flags are merged. Invalid values cause an immediate, clear
error message and the agent will not start.

### URLs (`nannyapi_url`, `portal_url`)

| Rule | Detail |
|------|--------|
| Scheme | Must be `http` or `https` |
| Host | Must be present (e.g. `https://` alone is rejected) |
| Length | Max 2 048 characters |
| Format | Must be a parseable URL |

### Intervals (`metrics_interval`, `proxmox_interval`)

| Rule | Detail |
|------|--------|
| Minimum | 5 seconds |
| Maximum | 604 800 seconds (7 days) |
| Negative / zero | Rejected |

### Token Path (`token_path`)

| Rule | Detail |
|------|--------|
| Path type | Must be an absolute path (starts with `/`) |
| Length | Max 4 096 characters |

### Static Token (`static_token`)

| Rule | Detail |
|------|--------|
| Prefix | Must start with `nsk_` |
| Min length | 5 characters (`nsk_` + at least 1) |
| Max length | 512 characters |

### Agent ID (`agent_id`)

| Rule | Detail |
|------|--------|
| Whitespace | Must not be blank / whitespace-only |
| Max length | 256 characters |

### Token Renewal

| Setting | Min | Max |
|---------|-----|-----|
| `token_renewal_threshold_days` | 1 | 365 |
| `token_renewal_check_interval_secs` | 1 | 2 592 000 (30 days) |
| `token_renewal_retry_interval_secs` | 1 | 2 592 000 (30 days) |

### HTTP Transport

| Setting | Min | Max |
|---------|-----|-----|
| `max_idle_conns` | 0 | 1 000 |
| `max_idle_conns_per_host` | 0 | 1 000 (and ≤ `max_idle_conns`) |
| `idle_conn_timeout_sec` | 0 | 3 600 (1 hour) |
| `response_header_timeout_sec` | 0 | 300 (5 minutes) |
| `transport_reset_threshold` | 1 | 100 |
| `initial_retry_delay_sec` | 1 | 86 400 (1 day) |
| `max_retry_delay_sec` | 1 | 86 400 (and ≥ `initial_retry_delay_sec`) |

## Configuration File

### Location

**Only one location is supported:**

```text
/etc/nannyagent/config.yaml
```

### Format

```yaml
# Required: NannyAPI backend URL
nannyapi_url: https://api.nannyai.dev

# Optional: Portal URL for device authorization (default: https://nannyai.dev)
portal_url: https://nannyai.dev

# Optional: Token storage path (default: /var/lib/nannyagent/token.json)
token_path: /var/lib/nannyagent/token.json

# Optional: Static token for automated auth (bypasses OAuth2)
# static_token: "nsk_your_static_token_here"

# Optional: Agent ID (auto-populated after registration)
# agent_id: ""

# Optional: Metrics collection interval in seconds (default: 30)
metrics_interval: 30

# Optional: Proxmox data collection interval in seconds (default: 300)
proxmox_interval: 300

# Optional: Refresh token renewal threshold in days (default: 7)
token_renewal_threshold_days: 7

# Optional: How often (secs) to check if renewal is needed (default: 21600 = 6h)
token_renewal_check_interval_secs: 21600

# Optional: How often (secs) to retry a failed renewal (default: 3600 = 1h)
token_renewal_retry_interval_secs: 3600

# Optional: Enable debug logging (default: false)
debug: false
```

### Creating Configuration File

```bash
# Create directory
sudo mkdir -p /etc/nannyagent

# Create configuration file
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
token_path: /var/lib/nannyagent/token.json
metrics_interval: 30
proxmox_interval: 300
debug: false
EOF

# Secure permissions (root only)
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

### Permissions

**Security is critical:**

```bash
# Configuration file should NOT be world-readable
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml

# Verify
ls -la /etc/nannyagent/config.yaml
# Should show: -rw------- 1 root root
```

## Environment Variables

Environment variables override values from `/etc/nannyagent/config.yaml`, but are themselves overridden by command-line arguments (see [Command-Line Arguments](#command-line-arguments)).

### Supported Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NANNYAPI_URL` | string | **(required)** | NannyAPI backend URL |
| `NANNYAI_PORTAL_URL` | string | `https://nannyai.dev` | Portal URL for device auth |
| `TOKEN_PATH` | string | `/var/lib/nannyagent/token.json` | Token storage location |
| `NANNYAI_STATIC_TOKEN` | string | *(empty)* | Static API token (nsk_...) |
| `NANNYAI_AGENT_ID` | string | *(empty)* | Agent ID for static token mode |
| `DEBUG` | bool | `false` | Enable debug logging (`true` or `1`) |

### Using Environment Variables

```bash
# Override API URL for testing
export NANNYAPI_URL=http://localhost:8090
sudo nannyagent --status

# Enable debug mode temporarily
export DEBUG=true
sudo nannyagent --diagnose "check logs"

# Use custom token path
export TOKEN_PATH=/tmp/test-token.json
sudo nannyagent --register
```

### Systemd Service with Environment Variables

If using systemd, you can add environment variables to the service:

```bash
# Edit service file
sudo systemctl edit nannyagent

# Add override:
[Service]
Environment="NANNYAPI_URL=https://api.nannyai.dev"
Environment="DEBUG=false"

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart nannyagent
```

## Configuration Options

### Required Settings

#### `nannyapi_url` / `NANNYAPI_URL`

**Required.** The backend API endpoint.

**Examples:**
```yaml
nannyapi_url: https://api.nannyai.dev  # Production
nannyapi_url: http://localhost:8090    # Development
```

**Environment variable:**
```bash
export NANNYAPI_URL=https://api.nannyai.dev
```

### Optional Settings

#### `portal_url` / `NANNYAI_PORTAL_URL`

Portal URL for device authorization flow.

**Default:** `https://nannyai.dev`

**Examples:**
```yaml
portal_url: https://nannyai.dev  # Production
portal_url: http://localhost:8080  # Development
```

#### `token_path` / `TOKEN_PATH`

Path to store OAuth tokens.

**Default:** `/var/lib/nannyagent/token.json`

**Examples:**
```yaml
token_path: /var/lib/nannyagent/token.json  # Default
token_path: /custom/path/token.json          # Custom
```

#### `metrics_interval`

System metrics collection interval in seconds.

**Default:** `30` (30 seconds)

**Examples:**
```yaml
metrics_interval: 30   # Every 30 seconds (default)
metrics_interval: 60   # Every minute
metrics_interval: 300  # Every 5 minutes
```

**Note:** No environment variable override available for this setting.

#### `proxmox_interval`

Proxmox data collection interval in seconds.

**Default:** `300` (5 minutes)

**Examples:**
```yaml
proxmox_interval: 300   # Every 5 minutes (default)
proxmox_interval: 600   # Every 10 minutes
proxmox_interval: 1800  # Every 30 minutes
```

**Note:** No environment variable override available for this setting.

#### `token_renewal_threshold_days`

How many days before the refresh token expires that the agent should proactively renew it.

The agent periodically calls the API to check the remaining lifetime of the refresh token.
When fewer than this many days remain, it triggers a `renew-refresh-token` request, which
rotates the refresh token and issues a new access token.

**Default:** `7` (start renewing when fewer than 7 days remain)

**Examples:**
```yaml
token_renewal_threshold_days: 7   # Default — renew in the last week
token_renewal_threshold_days: 14  # More aggressive — renew in the last 2 weeks
token_renewal_threshold_days: 3   # Conservative — renew only in the last 3 days
```

#### `token_renewal_check_interval_secs`

How often (in **seconds**) the background renewal goroutine checks whether the refresh
token is within the renewal threshold window. Using seconds makes it easy to test with
short intervals (e.g. `60` for a 1-minute check cycle).

**Default:** `21600` (6 hours)

**Examples:**
```yaml
token_renewal_check_interval_secs: 21600  # Default — 6 hours
token_renewal_check_interval_secs: 43200  # Less frequent — 12 hours
token_renewal_check_interval_secs: 60     # 1 minute (useful for testing)
```

#### `token_renewal_retry_interval_secs`

If a renewal attempt fails (e.g., the API is temporarily unreachable), the agent will
retry after this many **seconds**. Retries continue until the renewal succeeds. The agent
**never crashes or requires a restart** on renewal failure — it just logs a warning
and retries.

**Default:** `3600` (1 hour)

**Examples:**
```yaml
token_renewal_retry_interval_secs: 3600  # Default — retry every hour
token_renewal_retry_interval_secs: 7200  # Retry every 2 hours
token_renewal_retry_interval_secs: 30    # 30 seconds (useful for testing)
```

**How the three settings work together:**

1. Every `token_renewal_check_interval_secs` seconds the agent refreshes the access token
   and checks `refresh_token_expires_in` from the API response.
2. If `refresh_token_expires_in < token_renewal_threshold_days * 86400` seconds, the
   agent calls `renew-refresh-token` to rotate the refresh token.
3. If that call fails, the next check is scheduled in `token_renewal_retry_interval_secs`
   seconds instead of the normal interval.
4. Once renewal succeeds, the agent returns to the normal check interval.

#### `debug` / `DEBUG`

Enable debug-level logging for troubleshooting.

**Default:** `false`

**Examples:**
```yaml
debug: false  # Normal logging (default)
debug: true   # Debug logging enabled
```

**Environment variable:**
```bash
export DEBUG=true  # or DEBUG=1
```

### Advanced Settings

#### `http_transport` - HTTP Transport Configuration

Fine-tune HTTP connection behavior for reliability and error recovery. These settings help the agent recover from transient connection issues, stale HTTP/2 connections, and API outages.

**Config structure:**
```yaml
http_transport:
  max_idle_conns: 10            # Max idle connections across all hosts
  max_idle_conns_per_host: 5    # Max idle connections per host
  idle_conn_timeout_sec: 30     # Seconds before idle connection is closed
  response_header_timeout_sec: 30  # Seconds to wait for response headers
  disable_http2: false          # Disable HTTP/2 (use HTTP/1.1 only)
  transport_reset_threshold: 3  # Reset transport after N consecutive errors
  initial_retry_delay_sec: 30   # Initial retry delay (exponential backoff)
  max_retry_delay_sec: 1800     # Maximum retry delay (30 minutes)
```

**Defaults:**
| Setting | Default | Description |
|---------|---------|-------------|
| `max_idle_conns` | 10 | Maximum idle connections to keep in pool |
| `max_idle_conns_per_host` | 5 | Maximum idle connections per host |
| `idle_conn_timeout_sec` | 30 | Timeout before closing idle connections |
| `disable_http2` | false | When true, forces HTTP/1.1 only |
| `transport_reset_threshold` | 3 | Number of consecutive connection errors before full transport reset |
| `initial_retry_delay_sec` | 30 | Starting delay for exponential backoff |
| `max_retry_delay_sec` | 1800 | Maximum delay between retries (30 minutes) |

**Important Behavior:**

The agent **never gives up** on connecting to the API:

1. **Connection Errors**: When HTTP/2 connections become stale (common after server restarts or Cloudflare timeouts), the agent uses exponential backoff and eventually resets the entire HTTP transport to create fresh connections.

2. **API Outages**: If the API is unreachable, the agent retries indefinitely with exponential backoff up to the maximum delay.

3. **Server Errors (5xx)**: Retried with exponential backoff - the agent waits for the API to recover.

4. **Token Refresh Failures**: 
   - Temporary failures (network issues): Retried with backoff
   - Permanent failures (refresh token expired): The agent clears the invalid token, logs a clear message requesting re-registration, and waits for the user to run `sudo nannyagent --register`

**Note:** Omitting a setting (or setting it to `0`) applies the default value shown above.

**When to Adjust:**
- If experiencing frequent "response body closed" errors, try decreasing `idle_conn_timeout_sec` so it stays below the server/proxy idle timeout
- If behind a corporate proxy with HTTP/2 issues, set `disable_http2: true`
- For high-latency networks, increase `response_header_timeout_sec`
- For faster recovery from API restarts, decrease `transport_reset_threshold`

## Usage Examples

### Standard Configuration

**File:** `/etc/nannyagent/config.yaml`
```yaml
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
token_path: /var/lib/nannyagent/token.json
metrics_interval: 30
proxmox_interval: 300
token_renewal_threshold_days: 7
token_renewal_check_interval_secs: 21600
token_renewal_retry_interval_secs: 3600
debug: false
```

**Usage:**
```bash
# All commands use config file
sudo nannyagent --status
sudo nannyagent --register
sudo nannyagent --diagnose "nginx is down"
```

### Development Configuration

**File:** `/etc/nannyagent/config.yaml`
```yaml
nannyapi_url: http://localhost:8090
portal_url: http://localhost:8080
debug: true
metrics_interval: 60
proxmox_interval: 600
```

**Usage:**
```bash
# Test against local backend
sudo nannyagent --status
```

### Temporary Override

**File:** `/etc/nannyagent/config.yaml` (production settings)
```yaml
nannyapi_url: https://api.nannyai.dev
debug: false
```

**Override temporarily:**
```bash
# Use staging API for one command
export NANNYAPI_URL=https://staging-api.nannyai.dev
sudo nannyagent --status

# Or inline
sudo NANNYAPI_URL=https://staging-api.nannyai.dev nannyagent --status
```

### Systemd Service

The systemd service automatically loads `/etc/nannyagent/config.yaml`:

```bash
# Start daemon
sudo systemctl start nannyagent

# Check status
sudo systemctl status nannyagent

# View logs
sudo journalctl -u nannyagent -f
```

**Service file example:** `/etc/systemd/system/nannyagent.service`
```ini
[Unit]
Description=NannyAgent - AI-Powered Linux Diagnostic Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/nannyagent --daemon
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

# Optional: Override settings
# Environment="DEBUG=true"

[Install]
WantedBy=multi-user.target
```

## Security Best Practices

### 1. Protect Configuration Files

```bash
# YAML config should be root-only readable
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

### 2. Protect Token Storage

```bash
# Token file contains OAuth credentials
sudo mkdir -p /var/lib/nannyagent
sudo chmod 700 /var/lib/nannyagent
sudo chmod 600 /var/lib/nannyagent/token.json
```

### 3. Use HTTPS Only

```yaml
# ALWAYS use HTTPS for production
nannyapi_url: https://api.nannyai.dev  # ✓ Secure

# NEVER use HTTP in production
# nannyapi_url: http://api.nannyai.dev  # ✗ Insecure
```

### 4. Limit Debug Mode

```yaml
# Disable debug in production (avoid sensitive data in logs)
debug: false
```

### 5. Review Logs Regularly

```bash
# Check agent logs for suspicious activity
sudo journalctl -u nannyagent | grep -i "error\|auth\|failed"
```

## Troubleshooting

### "missing required configuration: NANNYAPI_URL must be set"

**Cause:** No configuration file or `NANNYAPI_URL` not set.

**Solution:**
```bash
# Create config file
sudo mkdir -p /etc/nannyagent
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
EOF
sudo chmod 600 /etc/nannyagent/config.yaml

# Or use environment variable
export NANNYAPI_URL=https://api.nannyai.dev
```

### Configuration File Not Found

**Check if file exists:**
```bash
ls -la /etc/nannyagent/config.yaml
```

**If missing, create it:**
```bash
sudo mkdir -p /etc/nannyagent
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
EOF
sudo chmod 600 /etc/nannyagent/config.yaml
```

### Permission Denied Reading Config

**Check permissions:**
```bash
ls -la /etc/nannyagent/config.yaml
# Should be: -rw------- 1 root root
```

**Fix permissions:**
```bash
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

**Run as root:**
```bash
# Agent requires root for eBPF
sudo nannyagent --status
```

### Invalid YAML Syntax

**Check YAML syntax:**
```bash
# Install yamllint
sudo apt-get install yamllint  # Ubuntu/Debian

# Validate syntax
yamllint /etc/nannyagent/config.yaml
```

**Common YAML mistakes:**
```yaml
# WRONG: Missing space after colon
nannyapi_url:https://api.nannyai.dev

# CORRECT: Space after colon
nannyapi_url: https://api.nannyai.dev

# WRONG: Using tabs for indentation
debug:	true

# CORRECT: Use spaces for indentation
debug: true
```

### View Loaded Configuration

**Check what the agent sees:**
```bash
# Run with debug to see config loading
sudo DEBUG=true nannyagent --status 2>&1 | grep -i config

# Expected output:
# INFO: Loaded configuration from /etc/nannyagent/config.yaml
```

### Verify Environment Variables

**Check what's set:**
```bash
# Show all NANNY* variables
env | grep NANNY

# Check specific variable
echo $NANNYAPI_URL
```

### Systemd Service Configuration Issues

**Check service environment:**
```bash
# View service environment
sudo systemctl show nannyagent --property=Environment

# View full service file
sudo systemctl cat nannyagent
```

**Check logs for config errors:**
```bash
# View agent logs
sudo journalctl -u nannyagent -n 50

# Filter for config-related messages
sudo journalctl -u nannyagent | grep -i "config\|load"
```

---

## Complete Configuration Example

**Production Configuration:**

```yaml
# /etc/nannyagent/config.yaml

# Backend API endpoint (required)
nannyapi_url: https://api.nannyai.dev

# Portal URL for device authorization
portal_url: https://nannyai.dev

# Token storage location
token_path: /var/lib/nannyagent/token.json

# Metrics collection every 30 seconds
metrics_interval: 30

# Proxmox data collection every 5 minutes
proxmox_interval: 300

# Disable debug logging in production
debug: false
```

**Permissions:**
```bash
-rw------- 1 root root /etc/nannyagent/config.yaml
```

---

**For more information:**
- [Installation Guide](INSTALLATION.md)
- [Architecture Documentation](ARCHITECTURE.md)
- [API Integration Guide](API_INTEGRATION.md)
