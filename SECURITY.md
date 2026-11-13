# Security Policy

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Security</h1>
</div>

## Reporting Security Vulnerabilities

We take security seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report a Security Issue

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing:

📧 **support@nannyai.dev**

### What to Include in Your Report

To help us better understand and address the issue, please include:

- **Type of issue**: (e.g., buffer overflow, SQL injection, cross-site scripting, privilege escalation)
- **Affected component**: Which part of NannyAgent is affected (e.g., eBPF module, authentication, API client)
- **Full paths**: Source file(s) related to the vulnerability
- **Location**: Tag/branch/commit or direct URL of the affected code
- **Step-by-step reproduction**: Detailed instructions to reproduce the issue
- **Proof-of-concept**: Exploit code (if possible)
- **Impact**: What an attacker could achieve by exploiting this issue
- **Suggested fix**: If you have ideas on how to remediate

### What to Expect

- **Acknowledgment**: We'll acknowledge receipt of your vulnerability report
- **Initial assessment**: We'll provide an initial assessment
- **Regular updates**: We'll keep you informed of progress toward a fix
- **Fix timeline**: We aim to release fixes for critical vulnerabilities as soon as we can
- **Credit**: We'll credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

### For Users

#### 1. Keep NannyAgent Updated

Always use the latest version:

```bash
# Check current version
nannyagent --version

# Download latest release
curl -fsSL https://raw.githubusercontent.com/nannyagent/nannyagent/main/install.sh | sudo bash ## installer script bumps version automatically
```

#### 2. Secure Configuration

**Protect configuration files:**

```bash
# Configuration file should not be world-readable
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

**Protect token storage:**

```bash
# Token file contains sensitive credentials
sudo chmod 600 /var/lib/nannyagent/token.json
sudo chown root:root /var/lib/nannyagent/token.json
```

#### 3. Minimize Privileges

While NannyAgent requires root for eBPF functionality, you should:

- Run it only on systems where diagnostic capabilities are needed
- Monitor agent activity through system logs
- Restrict network access to NannyAPI endpoints only

#### 4. Network Security

**Use TLS/HTTPS only:**

```yaml
# config.yaml
nannyapi_url: https://api.nannyai.dev
```

**Firewall rules:**

```bash
# Allow only necessary outbound connections
sudo ufw allow out to api.nannyai.dev port 443 proto tcp
```

#### 5. Audit eBPF Scripts

Before running custom eBPF scripts:

- Review the bpftrace script source code
- Understand what kernel functions are being probed
- Verify scripts come from trusted sources
- Monitor script execution and output

### For Developers

#### 1. Secure Coding Practices

**Command Execution:**

```go
// Use exec.Command properly - no shell expansion
cmd := exec.Command("bpftrace", scriptPath)
// DON'T: exec.Command("sh", "-c", userInput)
```

**Path Traversal Prevention:**

```go
// Sanitize file paths
func sanitizePath(path string) (string, error) {
    cleaned := filepath.Clean(path)
    if strings.Contains(cleaned, "..") {
        return "", fmt.Errorf("path traversal detected")
    }
    return cleaned, nil
}
```

#### 2. Secrets Management

**Never commit secrets:**

```bash
# Add to .gitignore
/etc/nannyagent/config.yaml
/var/lib/nannyagent/token.json
*.key
*.pem
.env*
```

**Use environment variables for sensitive data:**

```go
// Use environment variables for API keys
apiKey := os.Getenv("NANNYAPI_KEY")
if apiKey == "" {
    return fmt.Errorf("NANNYAPI_KEY not set")
}
```

#### 3. Dependency Security

**Keep dependencies updated:**

```bash
# Check for vulnerabilities
go list -m all | nancy sleuth

# Update dependencies
go get -u ./...
go mod tidy
```

#### 4. Code Review

All security-sensitive code must be reviewed:

- Authentication mechanisms
- Authorization checks
- eBPF script generation
- Command execution
- File operations
- Network communication

## Security Features

### Built-in Security Measures

#### 1. OAuth 2.0 Device Flow

- No password storage on agent
- Short-lived access tokens (1 hour)
- Automatic token refresh
- Secure token storage with restricted permissions

#### 2. Command Execution Safety

- **Timeout protection**: Commands limited to 10 seconds by default
- **Output size limits**: Prevents memory exhaustion
- **No shell expansion**: Direct command execution without shell
- **Error handling**: Proper error propagation and logging

#### 3. eBPF Safety

- **Kernel verification**: eBPF programs verified before loading
- **Resource limits**: Prevents kernel resource exhaustion
- **Read-only access**: eBPF programs cannot modify kernel state
- **Timeout enforcement**: Traces limited by duration parameter

#### 4. TLS/HTTPS Enforcement

- All API communication over HTTPS only
- Certificate validation enabled
- No insecure HTTP fallback

#### 5. Logging and Auditing

- All actions logged via syslog
- Authentication events recorded
- Command execution logged
- eBPF trace invocations tracked

## Known Security Considerations

### Root Privileges Required

**Why:** eBPF programs require `CAP_BPF` and `CAP_PERFMON` capabilities (or root)

**Mitigation:**
- No unnecessary system modifications
- All operations logged for audit

### Network Communication

**Risk:** Agent communicates with remote API

**Mitigation:**
- HTTPS/TLS encryption enforced
- OAuth 2.0 authentication
- Token-based authorization
- Rate limiting on backend

### Command Execution

**Risk:** Agent executes diagnostic commands

**Mitigation:**
- Whitelisted command patterns from AI
- Timeout and resource limits
- No arbitrary user-provided commands
- Output sanitization (to be done in upcoming releases)

### bpftrace Script Execution

**Risk:** eBPF scripts can observe kernel behavior

**Mitigation:**
- Scripts generated from validated AI requests only
- No direct user-provided bpftrace scripts
- eBPF kernel verification layer
- Limited trace duration (maximum 20 seconds)
- Output parsing and sanitization

## Vulnerability Disclosure Policy

### Disclosure Timeline

1. **Day 0**: Vulnerability reported to support@nannyai.dev
2. **Day 1-2**: Acknowledgment sent to reporter
3. **Day 3-5**: Initial assessment and severity classification
4. **Day 6-30**: Development and testing of fix
5. **Day 31**: Coordinated public disclosure and fixed release

### Severity Levels

- **Critical**: Remote code execution, privilege escalation
- **High**: Authentication bypass, data exposure
- **Medium**: Denial of service, information disclosure
- **Low**: Minor information leaks, configuration issues

### Security Advisories

Published at: https://github.com/nannyagent/nannyagent/security/advisories

## Security Updates

Subscribe to security notifications:

- **GitHub**: Watch the repository for security advisories
- **Email**: Contact support@nannyai.dev to subscribe to security mailing list

## Bug Bounty Program

Currently, NannyAI does not have a formal bug bounty program. However, we greatly appreciate security researchers who report vulnerabilities responsibly. We'll publicly acknowledge your contribution (unless you prefer anonymity) and may offer rewards on a case-by-case basis.

## Compliance

### Data Handling

- **No PII collection**: Agent doesn't collect personally identifiable information
- **System metrics only**: Only technical system metrics collected
- **Encrypted transit**: All data encrypted in transit via TLS
- **Token storage**: Access tokens stored securely with restricted permissions

### Audit Logs

All agent operations are logged via syslog:

```bash
# View agent logs
sudo journalctl -u nannyagent -f

# View authentication events
sudo grep "nannyagent" /var/log/syslog | grep "auth"

# View command executions
sudo grep "nannyagent" /var/log/syslog | grep "executed command"
```

## Additional Resources

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [eBPF Security Considerations](https://ebpf.io/what-is-ebpf/#security)
- [Go Security Best Practices](https://golang.org/doc/security/)

## Contact

For security-related questions or concerns:

📧 **support@nannyai.dev**

**Please do not use public channels for security discussions.**

---

Thank you for helping keep NannyAgent and its users safe!
