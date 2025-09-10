# Using the Ethereum RPC Fingerprinter CLI

## Installation

### From PyPI (when published)
```bash
pip install ethereum-rpc-fingerprinter
```

### From Source
```bash
git clone https://github.com/yourusername/ethereum-rpc-fingerprinter.git
cd ethereum-rpc-fingerprinter
pip install -e .
```

## CLI Commands

The tool provides two command-line interfaces:

1. **`ethereum-rpc-fingerprinter`** - Full command name
2. **`erf`** - Short alias for convenience

### Main Commands

#### 1. Fingerprint Endpoints

```bash
# Single endpoint
ethereum-rpc-fingerprinter fingerprint http://localhost:8545

# Multiple endpoints with async processing
erf fingerprint -a http://localhost:8545 https://eth.llamarpc.com

# With custom timeout and verbose output
erf fingerprint -v -t 30 https://cloudflare-eth.com

# Export results to JSON
erf fingerprint -o results.json https://eth.llamarpc.com

# Multiple formats supported
erf fingerprint --format json https://cloudflare-eth.com
erf fingerprint --format yaml https://cloudflare-eth.com
erf fingerprint --format table https://cloudflare-eth.com  # default

# Quiet mode (no formatted output)
erf fingerprint -q --format json https://cloudflare-eth.com
```

#### 2. Parse Client Version Strings

```bash
# Single version string
erf parse-version "Geth/v1.13.5-stable/linux-amd64/go1.21.4"

# Multiple version strings
erf parse-version "Geth/v1.13.5-stable/linux-amd64/go1.21.4" "Besu/v23.4.0/linux-x86_64/openjdk-java-17"

# Real-world examples
erf parse-version "Nethermind/v1.20.3+77d89dbe/windows-x64/dotnet8.0.0"
erf parse-version "anvil 0.2.0 (a1b2c3d 2024-01-15T10:30:45.123456789Z)"
```

#### 3. List Supported Implementations

```bash
# Production clients only
erf list-implementations

# Include development/testing tools
erf list-implementations --include-dev
```

### Options Reference

#### Global Options
- `--version` - Show version information
- `--help` - Show help message

#### Fingerprint Options
- `-t, --timeout INTEGER` - Request timeout in seconds (default: 10)
- `-a, --async-mode` - Use async fingerprinting for multiple endpoints
- `-o, --output PATH` - Output file for results
- `-q, --quiet` - Only output data, no formatted display
- `--format [table|json|yaml]` - Output format (default: table)
- `--max-concurrent INTEGER` - Max concurrent requests for async mode (default: 10)
- `-v, --verbose` - Enable verbose output

## Usage Examples

### Basic Fingerprinting

```bash
# Test a local Ethereum node
erf fingerprint http://localhost:8545

# Test multiple public endpoints
erf fingerprint -a \
  https://eth.llamarpc.com \
  https://cloudflare-eth.com \
  https://rpc.ankr.com/eth
```

### Advanced Usage

```bash
# Comprehensive analysis with verbose output and JSON export
erf fingerprint -v -a -o comprehensive_analysis.json \
  --format json \
  --timeout 30 \
  --max-concurrent 5 \
  http://localhost:8545 \
  https://eth.llamarpc.com \
  https://cloudflare-eth.com

# Quick client version analysis
erf parse-version \
  "Geth/v1.13.5-stable/linux-amd64/go1.21.4" \
  "Besu/v23.4.0/darwin-aarch64/openjdk-java-17" \
  "Nethermind/v1.20.3+77d89dbe/windows-x64/dotnet8.0.0"
```

### Automation & Scripting

```bash
# Generate JSON report for monitoring
erf fingerprint --format json --quiet http://localhost:8545 > node_status.json

# Parse multiple endpoints and save results
endpoints=(
  "http://localhost:8545"
  "https://eth.llamarpc.com"
  "https://cloudflare-eth.com"
)

erf fingerprint -a --format json "${endpoints[@]}" | jq '.[].node_implementation'
```

### YAML Output Example

```bash
erf fingerprint --format yaml https://cloudflare-eth.com
```

Output:
```yaml
- endpoint: https://cloudflare-eth.com
  client_version: cloudflare-ethereum
  node_implementation: Unknown
  network_id: '1'
  chain_id: 1
  response_time: 0.095
  # ... more fields
```

## Integration Examples

### Shell Scripting

```bash
#!/bin/bash
# Monitor multiple RPC endpoints
ENDPOINTS=(
  "http://localhost:8545"
  "https://eth.llamarpc.com"
  "https://cloudflare-eth.com"
)

echo "RPC Endpoint Health Check - $(date)"
echo "=================================="

for endpoint in "${ENDPOINTS[@]}"; do
  echo "Checking: $endpoint"
  result=$(erf fingerprint --format json --quiet "$endpoint")
  
  if [ $? -eq 0 ]; then
    impl=$(echo "$result" | jq -r '.[0].node_implementation')
    version=$(echo "$result" | jq -r '.[0].client_version')
    echo "  ✅ $impl ($version)"
  else
    echo "  ❌ Failed to connect"
  fi
  echo
done
```

### Python Integration

```python
import subprocess
import json

def fingerprint_endpoint(url):
    """Fingerprint an RPC endpoint using the CLI tool"""
    result = subprocess.run([
        'erf', 'fingerprint', 
        '--format', 'json', 
        '--quiet', 
        url
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        return json.loads(result.stdout)[0]
    else:
        return None

# Usage
endpoint_info = fingerprint_endpoint('https://cloudflare-eth.com')
if endpoint_info:
    print(f"Node: {endpoint_info['node_implementation']}")
    print(f"Language: {endpoint_info['programming_language']}")
```

## Help System

Each command has detailed help available:

```bash
# Main help
erf --help

# Command-specific help
erf fingerprint --help
erf parse-version --help
erf list-implementations --help
```

## Exit Codes

- `0` - Success
- `1` - General error (connection failed, invalid arguments, etc.)
- `2` - Command line parsing error

## Environment Variables

The tool respects standard HTTP proxy environment variables:
- `HTTP_PROXY`
- `HTTPS_PROXY` 
- `NO_PROXY`
