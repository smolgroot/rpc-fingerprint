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

# From file (one URL per line)
erf fingerprint -f endpoints.txt

# From file with async mode
erf fingerprint -f endpoints.txt -a

# Combine file and direct URLs
erf fingerprint -f endpoints.txt http://localhost:8545 https://eth.llamarpc.com

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

# File input with JSON output
erf fingerprint -f endpoints.txt --format json --output results.json
```

##### File Format for Endpoint Lists

Create a text file with one URL per line. Comments (lines starting with `#`) and empty lines are ignored:

```text
# Ethereum Mainnet endpoints
https://ethereum-rpc.publicnode.com
https://eth.llamarpc.com
https://cloudflare-eth.com

# BSC endpoints  
https://binance.llamarpc.com
https://bsc-dataseed.bnbchain.org

# Local development (commented out)
# http://localhost:8545
```

The tool will automatically validate URLs and skip invalid entries with warnings in verbose mode.

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
- `-a, --async` - Use async fingerprinting for multiple endpoints
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

### File-Based Scanning

The tool supports reading endpoints from files, making it ideal for penetration testing and bulk analysis workflows.

#### Basic File Scanning

```bash
# Scan all endpoints in a file
erf fingerprint -f rpc_endpoints.txt

# Async scanning for better performance
erf fingerprint -f rpc_endpoints.txt --async --max-concurrent 10

# Export results for further analysis
erf fingerprint -f rpc_endpoints.txt --format json --output scan_results.json

# Verbose mode for detailed progress
erf fingerprint -f rpc_endpoints.txt --verbose --timeout 15
```

#### Advanced File Operations

```bash
# Combine file input with direct URLs
erf fingerprint -f known_endpoints.txt https://new-endpoint.com

# Scan with specific timeout and concurrency
erf fingerprint -f large_endpoint_list.txt -a --timeout 5 --max-concurrent 20

# Generate YAML report
erf fingerprint -f endpoints.txt --format yaml --output report.yaml

# Quiet JSON output for processing
erf fingerprint -f endpoints.txt --quiet --format json | jq '.[] | select(.node_implementation == "Geth")'
```

#### File Format Examples

**Simple endpoint list:**
```text
https://ethereum-rpc.publicnode.com
https://eth.llamarpc.com
https://cloudflare-eth.com
```

**Commented endpoint list:**
```text
# Production endpoints
https://ethereum-rpc.publicnode.com
https://cloudflare-eth.com

# BSC endpoints
https://binance.llamarpc.com
https://bsc-dataseed.bnbchain.org

# Test endpoints (disabled)
# http://localhost:8545
# http://localhost:8546
```

**Mixed protocol support:**
```text
# HTTP endpoints
https://ethereum-rpc.publicnode.com
http://localhost:8545

# WebSocket endpoints  
wss://ethereum-rpc.publicnode.com
ws://localhost:8546
```

#### Pentesting Workflow

```bash
# 1. Prepare target list
cat > targets.txt << EOF
https://target1.example.com:8545
https://target2.example.com:8545
https://target3.example.com:3000
EOF

# 2. Fast initial scan
erf fingerprint -f targets.txt --async --timeout 3 --format json --quiet > initial_scan.json

# 3. Filter responsive endpoints
jq -r '.[] | select(.client_version != null) | .endpoint' initial_scan.json > responsive.txt

# 4. Detailed scan of responsive endpoints
erf fingerprint -f responsive.txt --verbose --timeout 30 --format yaml --output detailed_results.yaml

# 5. Extract specific information
jq '.[] | {endpoint, implementation: .node_implementation, version: .client_version, accounts: .accounts}' initial_scan.json
```

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
