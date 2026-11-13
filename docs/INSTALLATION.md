# Installation Guide

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>NannyAgent Installation</h1>
</div>

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Install](#quick-install)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Registration](#registration)
- [Verification](#verification)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Operating System

**Supported Linux Distributions:**
- Ubuntu 20.04, 22.04, 24.04
- Debian 10, 11, 12
- CentOS 7, 8
- RHEL 7, 8, 9
- Fedora 35+
- Arch Linux
- openSUSE / SUSE Linux Enterprise

**Not Supported:**
- Docker containers
- LXC containers (agent can manage them, but cannot run inside them)
- macOS, Windows, BSD

### Kernel Version

**Required:** Linux kernel 5.x or higher

Check your kernel version:
```bash
uname -r
# Example: 5.15.0-56-generic
```

If your kernel is older than 5.x, NannyAgent will not work due to eBPF requirements.

### Architecture

**Supported:**
- `amd64` / `x86_64` (Intel/AMD 64-bit)
- `arm64` / `aarch64` (ARM 64-bit)

**Not Supported:**
- `i386` / `i686` (32-bit)
- `armv7` (ARM 32-bit)

### Dependencies

**Automatically Installed:**
- `bpftrace` - eBPF tracing tool (required for kernel monitoring)
- `unzip` - Archive extraction utility

**System Requirements:**
- Root/sudo privileges (required for eBPF & OS updates)
- Network connectivity to NannyAPI backend
- ~50MB disk space for installation
- ~10MB RAM for agent process

## Quick Install

### One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

Or with `wget`:
```bash
wget -qO- https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

This will:
1. Check system requirements (kernel version, architecture)
2. Install dependencies (bpftrace, unzip)
3. Download latest pre-built binary
4. Install to `/usr/sbin/nannyagent`
5. Create configuration directory `/etc/nannyagent/`
6. Install systemd service
7. Create data directory `/var/lib/nannyagent/`

## Installation Methods

### Method 1: Pre-built Binary (Recommended)

**Install latest version:**
```bash
curl -fsSL https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

**Install specific version:**
```bash
export INSTALL_VERSION=1.2.3
curl -fsSL https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

### Method 2: Build from Source

**Prerequisites:**
- Go 1.24 or higher
- Git

**Steps:**

1. **Clone repository:**
```bash
git clone https://github.com/nannyagent/nannyagent.git
cd nannyagent
```

2. **Install dependencies:**
```bash
make install
```

3. **Build binary:**
```bash
make build
```

4. **Install system-wide:**
```bash
sudo make install-system
```

This will:
- Copy binary to `/usr/sbin/nannyagent`
- Create `/etc/nannyagent/config.yaml` with default settings
- Install systemd service
- Reload systemd daemon

### Method 3: Using Install Script with Build Flag

Force build from source even if pre-built binary exists:

```bash
export INSTALL_FROM_SOURCE=true
curl -fsSL https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash
```

### Method 4: Manual Installation

**Download binary manually:**

```bash
# For amd64 (x86_64)
wget https://github.com/nannyagent/nannyagent/releases/latest/download/nannyagent_linux_amd64.tar.gz
tar -xzf nannyagent_linux_amd64.tar.gz

# For arm64 (aarch64)
wget https://github.com/nannyagent/nannyagent/releases/latest/download/nannyagent_linux_arm64.tar.gz
tar -xzf nannyagent_linux_arm64.tar.gz

# Install binary
sudo mv nannyagent /usr/sbin/
sudo chmod +x /usr/sbin/nannyagent

# Create directories
sudo mkdir -p /etc/nannyagent
sudo mkdir -p /var/lib/nannyagent
sudo chmod 700 /var/lib/nannyagent

# Install bpftrace
sudo apt-get install bpftrace  # Ubuntu/Debian
# sudo dnf install bpftrace     # Fedora/RHEL
# sudo yum install bpftrace     # CentOS

# Create config file (see Configuration section)
sudo nano /etc/nannyagent/config.yaml

# Download and install systemd service
sudo wget -O /etc/systemd/system/nannyagent.service \
  https://raw.githubusercontent.com/nannyagent/nannyagent/main/nannyagent.service
sudo systemctl daemon-reload
```

## Configuration

### Create Configuration File

After installation, create `/etc/nannyagent/config.yaml`:

```bash
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
# NannyAPI backend URL (required)
nannyapi_url: https://api.nannyai.dev

# Portal URL for device authorization
portal_url: https://nannyai.dev

# Token storage path
token_path: /var/lib/nannyagent/token.json

# Metrics collection interval (seconds)
metrics_interval: 30

# Debug logging
debug: false
EOF
```

**Secure permissions:**
```bash
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

### Environment Variables (Alternative)

You can also use environment variables instead of or to override config file:

```bash
export NANNYAPI_URL=https://api.nannyai.dev
export NANNYAI_PORTAL_URL=https://nannyai.dev
export DEBUG=false
```

For more details, see [Configuration Guide](CONFIGURATION.md).

## Registration

### Register Agent with NannyAI

```bash
sudo nannyagent --register
```

**Output:**
```text
NannyAgent - Device Registration

Visit: https://nannyai.dev/device
Enter code: ABCD1234

Waiting for authorization...
```

**Steps:**
1. Open https://nannyai.dev/device in your browser
2. Log in with your NannyAI account
3. Enter the code displayed (e.g., `ABCD1234`)
4. Click "Authorize Device"
5. Wait for confirmation

**Success output:**
```text
✓ Device authorized successfully!
✓ Agent registered with ID: agent-550e8400-e29b-41d4-a716-446655440000
✓ Token stored: /var/lib/nannyagent/token.json

Agent is now ready to use!
```

## Verification

### Check Agent Status

```bash
nannyagent --status
```

**Expected output:**
```text
NannyAgent Status

✓ Agent ID: agent-550e8400-e29b-41d4-a716-446655440000
✓ Registered: Yes
✓ Token Valid: Yes
✓ API Connectivity: OK
✓ eBPF Supported: Yes
✓ bpftrace: /usr/bin/bpftrace (v0.19.0)

System Information:
  Hostname: prod-web-01
  Platform: ubuntu 22.04
  Kernel: 5.15.0-56-generic
  Architecture: x86_64
  CPU Cores: 16
  Memory: 64GB
```

### Test Diagnostic Capabilities

```bash
sudo nannyagent --diagnose "test connection to database"
```

### Start Systemd Service

```bash
# Enable service to start on boot
sudo systemctl enable nannyagent

# Start service
sudo systemctl start nannyagent

# Check service status
sudo systemctl status nannyagent
```

**Expected output:**
```text
● nannyagent.service - NannyAgent - AI-Powered Linux Diagnostic Agent
     Loaded: loaded (/etc/systemd/system/nannyagent.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2025-12-30 10:30:00 UTC; 5min ago
   Main PID: 12345 (nannyagent)
      Tasks: 12 (limit: 38400)
     Memory: 42.3M
        CPU: 2.456s
     CGroup: /system.slice/nannyagent.service
             └─12345 /usr/sbin/nannyagent --daemon

Dec 30 10:30:00 prod-web-01 systemd[1]: Started NannyAgent.
Dec 30 10:30:00 prod-web-01 nannyagent[12345]: INFO: Agent started in daemon mode
Dec 30 10:30:00 prod-web-01 nannyagent[12345]: INFO: Connected to NannyAPI
```

### View Logs

```bash
# Follow logs in real-time
sudo journalctl -u nannyagent -f

# View last 100 lines
sudo journalctl -u nannyagent -n 100

# View logs from today
sudo journalctl -u nannyagent --since today
```

## Uninstallation

### Stop and Disable Service

```bash
sudo systemctl stop nannyagent
sudo systemctl disable nannyagent
```

### Remove Files

```bash
# Remove binary
sudo rm -f /usr/sbin/nannyagent

# Remove systemd service
sudo rm -f /etc/systemd/system/nannyagent.service
sudo systemctl daemon-reload

# Remove configuration (optional - preserves agent registration)
sudo rm -rf /etc/nannyagent

# Remove data directory (WARNING: removes token and registration)
sudo rm -rf /var/lib/nannyagent

# Remove dependencies (optional)
sudo apt-get remove bpftrace  # Ubuntu/Debian
# sudo dnf remove bpftrace     # Fedora/RHEL
# sudo yum remove bpftrace     # CentOS
```

## Troubleshooting

### Installation Issues

#### "This installer must be run as root"

**Solution:**
```bash
# Use sudo
sudo bash install.sh
```

#### "Unsupported operating system"

**Cause:** Not running on Linux

**Solution:** NannyAgent only supports Linux. Use a Linux VM or WSL2 if on Windows/macOS.

#### "Unsupported architecture"

**Cause:** Running on 32-bit or unsupported architecture

**Solution:** Use a 64-bit system (amd64 or arm64).

#### "Container environment detected"

**Cause:** Trying to install inside Docker or LXC

**Solution:** Install on the host system, not inside containers.

#### "Kernel version X.X is not supported"

**Cause:** Kernel older than 5.x

**Solution:** Upgrade kernel to 5.x or higher:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install linux-generic-hwe-$(lsb_release -rs)
sudo reboot
```

#### "Failed to install eBPF tools"

**Cause:** Package manager issues or network problems

**Solution:**
```bash
# Update package lists
sudo apt-get update  # Ubuntu/Debian
sudo dnf update      # Fedora/RHEL

# Manually install bpftrace
sudo apt-get install bpftrace  # Ubuntu/Debian
sudo dnf install bpftrace      # Fedora/RHEL
sudo yum install bpftrace      # CentOS
```

#### "Failed to download binary"

**Cause:** Network connectivity or GitHub API rate limit

**Solution:**
```bash
# Try building from source instead
export INSTALL_FROM_SOURCE=true
bash install.sh

# Or manually download from releases page
wget https://github.com/nannyagent/nannyagent/releases/latest/download/nannyagent_linux_amd64.tar.gz
```

### Configuration Issues

#### "missing required configuration: NANNYAPI_URL must be set"

**Solution:**
```bash
# Create config file
sudo mkdir -p /etc/nannyagent
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
EOF
sudo chmod 600 /etc/nannyagent/config.yaml
```

#### "Permission denied" when reading config

**Solution:**
```bash
# Fix permissions
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml

# Run with sudo
sudo nannyagent --status
```

### Registration Issues

#### "Failed to connect to portal"

**Cause:** Network connectivity or firewall blocking HTTPS

**Solution:**
```bash
# Test connectivity
curl -I https://api.nannyai.dev
curl -I https://nannyai.dev

# Check firewall
sudo ufw status  # Ubuntu/Debian
sudo firewall-cmd --list-all  # RHEL/CentOS
```

#### "Device code expired"

**Cause:** Waited too long to authorize (codes expire after 10 minutes)

**Solution:** Run `--register` again to get a new code.

### Runtime Issues

#### "This program must be run as root"

**Cause:** eBPF requires root privileges

**Solution:**
```bash
sudo nannyagent --status
sudo nannyagent --diagnose "issue description"
```

#### Service fails to start

**Check logs:**
```bash
sudo journalctl -u nannyagent -n 50
```

**Common causes:**
- Missing configuration file
- Invalid YAML syntax
- Token file corrupted
- Network connectivity issues

**Solution:**
```bash
# Verify config
cat /etc/nannyagent/config.yaml

# Test manually
sudo nannyagent --status

# Re-register if needed
sudo nannyagent --register
```

#### "bpftrace: command not found"

**Solution:**
```bash
# Install bpftrace
sudo apt-get install bpftrace  # Ubuntu/Debian
sudo dnf install bpftrace      # Fedora/RHEL
sudo yum install bpftrace      # CentOS

# Verify installation
which bpftrace
bpftrace --version
```

### Getting Help

If you continue to experience issues:

1. **Check logs:**
   ```bash
   sudo journalctl -u nannyagent -n 100
   ```

2. **Run with debug mode:**
   ```bash
   sudo DEBUG=true nannyagent --status
   ```

3. **Verify system requirements:**
   ```bash
   uname -r  # Kernel version (must be 5.x+)
   uname -m  # Architecture (must be x86_64 or aarch64)
   which bpftrace  # bpftrace installed
   ```

4. **Contact support:**
   - Email: support@nannyai.dev
   - GitHub Issues: https://github.com/nannyagent/nannyagent/issues

---

## Post-Installation

Once installed and registered, you can:

1. **Use daemon mode** (runs in background):
   ```bash
   sudo systemctl start nannyagent
   ```

2. **Run one-off diagnostics**:
   ```bash
   sudo nannyagent --diagnose "nginx is slow"
   ```

3. **Check status**:
   ```bash
   nannyagent --status
   ```

4. **View documentation**:
   - [Configuration Guide](CONFIGURATION.md)
   - [Architecture Documentation](ARCHITECTURE.md)
   - [eBPF Monitoring Guide](EBPF_MONITORING.md)
   - [API Integration](API_INTEGRATION.md)

---

**Congratulations! NannyAgent is now installed and ready to use.** 🎉
