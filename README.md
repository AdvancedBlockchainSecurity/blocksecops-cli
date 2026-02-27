# Apogee CLI

Command-line interface for Apogee smart contract security scanning.

## Installation

```bash
pip install 0xapogee-cli
```

## Quick Start

1. **Authenticate with your API key:**
   ```bash
   0xapogee auth login
   ```

2. **Scan a smart contract:**
   ```bash
   0xapogee scan run contract.sol
   ```

3. **Get scan results:**
   ```bash
   0xapogee scan results <scan-id>
   ```

## Commands

### Authentication

```bash
# Login with API key
0xapogee auth login

# Check authentication status
0xapogee auth status

# Show current user info
0xapogee auth whoami

# Logout
0xapogee auth logout
```

### Scanning

```bash
# Scan a contract file
0xapogee scan run contract.sol

# Scan with specific output format
0xapogee scan run contract.sol --output json
0xapogee scan run contract.sol --output sarif
0xapogee scan run contract.sol --output junit

# Save results to file
0xapogee scan run contract.sol --output sarif --output-file results.sarif

# Fail on specific severity level
0xapogee scan run contract.sol --fail-on high

# Use specific scanners
0xapogee scan run contract.sol --scanner slither --scanner aderyn

# Start scan without waiting
0xapogee scan run contract.sol --no-wait

# Check scan status
0xapogee scan status <scan-id>

# Get results for completed scan
0xapogee scan results <scan-id>

# List recent scans
0xapogee scan list
```

## Output Formats

- **table** (default): Rich terminal output with colors
- **json**: Machine-readable JSON format
- **sarif**: Static Analysis Results Interchange Format for CI/CD integration
- **junit**: JUnit XML format for test reporting

## Pre-commit Integration

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/0xapogee/0xapogee-cli
    rev: v0.1.0
    hooks:
      - id: 0xapogee-scan
```

Or use the standalone hook:

```bash
# Copy the hook to your repo
cp hooks/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Environment Variables

- `APOGEE_API_KEY`: API key for authentication
- `APOGEE_API_URL`: Custom API URL (default: https://api.0xapogee.com)
- `APOGEE_FAIL_ON`: Default severity threshold for pre-commit hooks (default: high)

## Configuration

Configuration is stored in:
- Linux/macOS: `~/.0xapogee/`
- Windows: `%APPDATA%\0xapogee\`

API keys are stored securely using the system keyring.

## License

MIT License
