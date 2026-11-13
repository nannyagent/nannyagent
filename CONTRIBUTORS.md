# Contributing to NannyAgent

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Welcome Contributors!</h1>
</div>

Thank you for your interest in contributing to NannyAgent! We appreciate all contributions, whether they're bug reports, feature requests, documentation improvements, or code contributions.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/nannyagent.git
   cd nannyagent
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/nannyagent/nannyagent.git
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-new-feature
   ```

## How to Contribute

### Types of Contributions

We welcome the following types of contributions:

- **Bug fixes**: Fix issues identified in the [issue tracker](https://github.com/nannyagent/nannyagent/issues)
- **New features**: Add new functionality (please discuss in an issue first)
- **Documentation**: Improve docs, add examples, fix typos
- **Tests**: Add or improve test coverage
- **Performance**: Optimize existing code
- **eBPF scripts**: Contribute new bpftrace monitoring scripts

## Development Setup

### Prerequisites

- **Go 1.24+**: [Install Go](https://go.dev/doc/install)
- **Linux kernel 5.x+**: Required for eBPF support
- **bpftrace**: Install via package manager
  ```bash
  # Ubuntu/Debian
  sudo apt-get install bpftrace
  
  # Fedora/RHEL
  sudo dnf install bpftrace
  ```
- **Root privileges**: Required for testing eBPF functionality

### Local Development

1. **Install dependencies**:
   ```bash
   make install
   ```

2. **Build the agent**:
   ```bash
   make build
   ```

3. **Run tests**:
   ```bash
   make test
   ```

4. **Format code**:
   ```bash
   make fmt
   ```

5. **Run linter** (optional):
   ```bash
   make lint
   ```

### Environment Configuration

Create a configuration file for testing:

```bash
sudo mkdir -p /etc/nannyagent
sudo tee /etc/nannyagent/config.yaml <<EOF
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
token_path: /var/lib/nannyagent/token.json
metrics_interval: 30
debug: true
EOF
```

Or use environment variables:

```bash
export NANNYAPI_URL="https://api.nannyai.dev"
export DEBUG=true
```

## Coding Standards

### Go Code Style

- Follow standard Go formatting: `gofmt` and `goimports`
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Keep functions focused and concise
- Handle errors explicitly

### Example:

```go
// GatherSystemMetrics collects comprehensive system metrics including CPU,
// memory, disk, and network statistics. Returns an error if critical metrics
// cannot be collected.
func (c *Collector) GatherSystemMetrics() (*types.SystemMetrics, error) {
    metrics := &types.SystemMetrics{
        Timestamp: time.Now(),
    }
    
    // CPU metrics
    if percentages, err := cpu.Percent(time.Second, false); err == nil {
        metrics.CPUUsage = percentages[0]
    } else {
        return nil, fmt.Errorf("failed to collect CPU metrics: %w", err)
    }
    
    return metrics, nil
}
```

### eBPF/bpftrace Scripts

- Use clear, descriptive probe names
- Add header comments explaining the script purpose
- Include example output in comments
- Keep scripts focused on specific monitoring tasks
- Use proper formatting for bpftrace syntax

### Example:

```bash
#!/usr/bin/env bpftrace

// TCP Connection Monitor
// Tracks all TCP connection attempts system-wide
// Output: timestamp, process, PID, destination IP:port

BEGIN {
    printf("%-8s %-16s %-6s %-20s\n", "TIME", "COMM", "PID", "DESTINATION");
}

kprobe:tcp_connect {
    printf("%-8s %-16s %-6d %-20s\n",
           strftime("%H:%M:%S", nsecs),
           comm,
           pid,
           ntop(arg0));
}
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific package tests
go test -v ./internal/metrics/...

# Run with coverage
go test -v -cover ./...

# Run integration tests
go test -v -tags=integration ./...
```

### Writing Tests

- Write unit tests for all new functions
- Use table-driven tests when appropriate
- Mock external dependencies
- Test error conditions

### Example:

```go
func TestCollectorGatherSystemMetrics(t *testing.T) {
    tests := []struct {
        name    string
        want    *types.SystemMetrics
        wantErr bool
    }{
        {
            name:    "successful collection",
            wantErr: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            c := NewCollector("test", "https://api.test.com")
            got, err := c.GatherSystemMetrics()
            
            if (err != nil) != tt.wantErr {
                t.Errorf("GatherSystemMetrics() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if got == nil {
                t.Error("GatherSystemMetrics() returned nil metrics")
            }
        })
    }
}
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests**:
   ```bash
   make test
   ```

3. **Format code**:
   ```bash
   make fmt
   ```

4. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add TCP connection monitoring to eBPF manager"
   ```

### Commit Message Format

Use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### Creating a Pull Request

1. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```

2. **Create PR** on GitHub with:
   - Clear title describing the change
   - Description of what changed and why
   - Reference to related issues (if any)
   - Screenshots/logs (if applicable)

3. **Review process**:
   - Maintainers will review your PR
   - Address any requested changes
   - Once approved, your PR will be merged

### PR Checklist

- [ ] Code follows Go coding standards
- [ ] Tests added/updated and passing
- [ ] Documentation updated (if needed)
- [ ] Commit messages follow conventions
- [ ] No merge conflicts with main branch
- [ ] PR description is clear and complete

## Reporting Bugs

### Before Reporting

1. Check if the bug has already been reported in [Issues](https://github.com/nannyagent/nannyagent/issues)
2. Verify you're using the latest version
3. Test on a clean environment if possible

### Bug Report Template

Include the following information:

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. See error '...'

**Expected behavior**
What you expected to happen.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Kernel version: [e.g., 5.15.0-56-generic]
- NannyAgent version: [e.g., 1.0.0]
- bpftrace version: [e.g., v0.19.0]

**Logs**
```
Paste relevant logs here
```

**Additional context**
Any other relevant information.
```

## Suggesting Features

### Feature Request Process

1. **Check existing requests**: Review [Issues](https://github.com/nannyagent/nannyagent/issues) to avoid duplicates
2. **Open a new issue** with the `enhancement` label
3. **Describe the feature**:
   - What problem does it solve?
   - How would it work?
   - Any implementation ideas?

### Feature Request Template

```markdown
**Feature Description**
Clear description of the proposed feature.

**Use Case**
Explain the problem this feature solves.

**Proposed Solution**
How you envision this working.

**Alternatives Considered**
Other solutions you've considered.

**Additional Context**
Screenshots, diagrams, or examples.
```

## Documentation

### Documentation Contributions

Documentation improvements are always welcome!

- Fix typos or unclear explanations
- Add examples and use cases
- Improve installation instructions
- Create tutorials or guides

### Documentation Structure

- `README.md`: Main project documentation
- `docs/ARCHITECTURE.md`: System architecture
- `docs/API_INTEGRATION.md`: API documentation
- `docs/EBPF_MONITORING.md`: eBPF monitoring guide
- `docs/CONFIGURATION.md`: Configuration guide
- `docs/INSTALLATION.md`: Installation instructions

## Community

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Email**: support@nannyai.dev for general questions
- **Documentation**: https://nannyai.dev/documentation

### Stay Updated

- Watch the repository for updates
- Follow releases on GitHub
- Join discussions in issue threads

## License

By contributing to NannyAgent, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE) file).

---

**Thank you for contributing to NannyAgent!** 🎉

Every contribution, no matter how small, helps make NannyAgent better for everyone.
