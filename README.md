# Ethereum RPC Fingerprinting Tool

A comprehensive Python tool for fingerprinting Ethereum/EVM chains RPC endpoints to identify node implementations, versions, network configurations, and security characteristics.

[![PyPI version](https://badge.fury.io/py/ethereum-rpc-fingerprinter.svg)](https://badge.fury.io/py/ethereum-rpc-fingerprinter)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![asciicast](https://asciinema.org/a/740150.svg)](https://asciinema.org/a/740150)

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Command Line Usage](#command-line-usage)
    - [Basic Fingerprinting](#basic-fingerprinting)
    - [Bulk Scanning](#bulk-scanning-perfect-for-pentesting) 
- [Advanced CLI Usage](#advanced-cli-usage)
- [Python API Usage](#python-api-usage)
- [Example Output](#example-output)
- [Supported Implementations](#supported-implementations)
- [CVE Vulnerability Detection](#cve-vulnerability-detection-🛡️)
- [CLI Documentation](#cli-documentation)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Changelog](#changelog)


## Features

- 🔍 **Enhanced Node Detection**: Identify Geth, Parity/OpenEthereum, Besu, Nethermind, Erigon, Reth, EthereumJS, Anvil, Hardhat, Ganache, TurboGeth
- 🧬 **Detailed Client Analysis**: Extract programming language, version, OS, and architecture from client version strings
- �️ **CVE Vulnerability Detection**: Automatically check for known security vulnerabilities based on detected node implementation and version
- �📊 **Network Information**: Chain ID, network ID, block height, gas prices, peer count
- 🚀 **Async Support**: Fingerprint multiple endpoints concurrently with configurable limits
- 📁 **Bulk Scanning**: Read endpoint lists from files (one URL per line) - perfect for pentesting workflows
- 🔐 **Security Analysis**: Detect exposed accounts, admin interfaces, debug capabilities
- 📋 **Method Discovery**: Enumerate supported RPC methods
- 📄 **Multiple Formats**: Output results in table, JSON, or YAML format
- 🐍 **Python API**: Use as a library in your Python projects

### Client Version Parsing

The tool can extract detailed information from client version strings:

- **Programming Language**: Go, Rust, Java, .NET, JavaScript/TypeScript
- **Language Version**: Specific version (e.g., Go 1.21.4, Java 17, .NET 8.0.0)
- **Operating System**: Linux, Windows, macOS, FreeBSD, OpenBSD
- **Architecture**: x86_64, amd64, arm64, ARM, etc.
- **Node Version**: Exact node software version
- **Build Information**: Commit hashes, timestamps (where available)

Example parsed information:
```
Client Version: Geth/v1.13.5-stable/linux-amd64/go1.21.4
├── Implementation: Geth  
├── Node Version: 1.13.5-stable
├── Programming Language: Go
├── Language Version: 1.21.4
├── Operating System: Linux
└── Architecture: amd64
```

## Installation

### From PyPI (Recommended)

```bash
pip install ethereum-rpc-fingerprinter
```

### From Source

```bash
git clone https://github.com/yourusername/ethereum-rpc-fingerprinter.git
cd ethereum-rpc-fingerprinter
pip install -e .
```

## Quick Start

### Command Line Usage

The tool provides a modern CLI with two command names:
- `ethereum-rpc-fingerprinter` (full name)
- `erf` (short alias)

#### Basic Fingerprinting

```bash
# Fingerprint a single endpoint
erf fingerprint http://localhost:8545

# Multiple endpoints with async processing
erf fingerprint -a http://localhost:8545 https://eth.llamarpc.com

# From file (one URL per line) - great for pentesting
erf fingerprint -f endpoints.txt

# From file with async processing
erf fingerprint -f endpoints.txt -a --max-concurrent 10

# Export results to JSON
erf fingerprint -o results.json http://localhost:8545

# Different output formats
erf fingerprint --format json http://localhost:8545
erf fingerprint --format yaml http://localhost:8545
erf fingerprint --format table http://localhost:8545  # default

# Verbose output with progress
erf fingerprint -v -a http://localhost:8545 https://cloudflare-eth.com
```

#### Bulk Scanning (Perfect for Pentesting) 🎯

```bash
# Scan from file with beautiful progress tracking
erf fingerprint -f endpoints.txt --async --verbose

# High-performance bulk scanning with custom concurrency
erf fingerprint -f endpoints.txt --async --max-concurrent 20 --timeout 5

# Export bulk results to file
erf fingerprint -f endpoints.txt --async -o scan_results.json --format json

# Quiet mode for automation (progress bar only)
erf fingerprint -f endpoints.txt --async --quiet --format json
```

#### Client Version Analysis

```bash
# Parse client version strings
erf parse-version "Geth/v1.13.5-stable/linux-amd64/go1.21.4"

# Multiple versions at once
erf parse-version \
  "Geth/v1.13.5-stable/linux-amd64/go1.21.4" \
  "Besu/v23.4.0/linux-x86_64/openjdk-java-17" \
  "Nethermind/v1.20.3+77d89dbe/windows-x64/dotnet8.0.0"
```

#### Additional Commands

```bash
# List supported implementations
erf list-implementations

# Include development tools
erf list-implementations --include-dev

# Get help for any command
erf --help
erf fingerprint --help
```

### Advanced CLI Usage

```bash
# Comprehensive analysis with all options
erf fingerprint \
  --verbose \
  --async \
  --timeout 30 \
  --max-concurrent 5 \
  --format json \
  --output comprehensive_report.json \
  http://localhost:8545 \
  https://eth.llamarpc.com \
  https://cloudflare-eth.com

# Automation-friendly (quiet mode)
erf fingerprint --quiet --format json http://localhost:8545 | jq '.[]'
```

### Python API Usage

```python
import asyncio
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter

# Create fingerprinter instance
fingerprinter = EthereumRPCFingerprinter()

# Synchronous fingerprinting
result = fingerprinter.fingerprint("http://localhost:8545")
print(f"Implementation: {result.implementation}")
print(f"Node Version: {result.node_version}")
print(f"Programming Language: {result.programming_language}")
print(f"Language Version: {result.language_version}")
print(f"Operating System: {result.operating_system}")
print(f"Architecture: {result.architecture}")

# Asynchronous fingerprinting
async def fingerprint_multiple():
    results = await fingerprinter.fingerprint_async([
        "http://localhost:8545",
        "https://eth.llamarpc.com",
        "https://cloudflare-eth.com"
    ])
    
    for result in results:
        print(f"{result.endpoint}: {result.implementation} {result.node_version}")

asyncio.run(fingerprint_multiple())

# Client version parsing
version_info = fingerprinter.parse_client_version("Geth/v1.13.5-stable/linux-amd64/go1.21.4")
print(f"Language: {version_info.programming_language} {version_info.language_version}")
print(f"Platform: {version_info.operating_system} {version_info.architecture}")
```

## Example Output

### Geth Node
```
Fingerprinting: http://localhost:8545

🔍 Basic Information:
┌─────────────────┬─────────────────────────────────┐
│ Endpoint        │ http://localhost:8545           │
│ Implementation  │ Geth                            │
│ Client Version  │ Geth/v1.13.5-stable-3f...      │
│ Node Version    │ 1.13.5-stable                  │
│ Language        │ Go 1.21.4                      │
│ Platform        │ Linux amd64                     │
│ Chain ID        │ 1 (Ethereum Mainnet)           │
│ Network ID      │ 1                               │
│ Block Height    │ 18,750,123                      │
│ Syncing         │ No                              │
└─────────────────┴─────────────────────────────────┘

📊 Network Status:
┌─────────────────┬─────────────────────────────────┐
│ Gas Price       │ 15.2 Gwei                       │
│ Peer Count      │ 47 peers                        │
│ Mining          │ No                              │
│ Hashrate        │ 0 H/s                           │
└─────────────────┴─────────────────────────────────┘

🔒 Security Information:
┌─────────────────┬─────────────────────────────────┐
│ Accounts        │ None exposed                    │
│ Debug Interface │ Not detected                    │
│ Admin Interface │ Not detected                    │
└─────────────────┴─────────────────────────────────┘

🛠️ Supported Methods:
eth_accounts, eth_blockNumber, eth_call, eth_chainId, eth_estimateGas,
eth_gasPrice, eth_getBalance, eth_getBlockByHash, eth_getBlockByNumber,
eth_getCode, eth_getLogs, eth_getStorageAt, eth_getTransactionByHash,
eth_getTransactionCount, eth_getTransactionReceipt, eth_hashrate,
eth_mining, eth_sendRawTransaction, eth_syncing, net_listening,
net_peerCount, net_version, web3_clientVersion, web3_sha3
```

### Hardhat Development Node
```
Fingerprinting: http://localhost:8545

🔍 Basic Information:
┌─────────────────┬─────────────────────────────────┐
│ Endpoint        │ http://localhost:8545           │
│ Implementation  │ Hardhat                         │
│ Client Version  │ HardhatNetwork/2.17.2/@hard... │
│ Node Version    │ 2.17.2                          │
│ Language        │ JavaScript (Node.js)            │
│ Platform        │ Unknown                         │
│ Chain ID        │ 31337 (Hardhat Network)         │
│ Network ID      │ 31337                           │
│ Block Height    │ 0                               │
│ Syncing         │ No                              │
└─────────────────┴─────────────────────────────────┘

🔒 Security Information:
┌─────────────────┬─────────────────────────────────┐
│ Accounts        │ 20 accounts exposed            │
│ Debug Interface │ Available                       │
│ Admin Interface │ Not detected                    │
└─────────────────┴─────────────────────────────────┘

⚠️  Development Environment Detected
```

## Supported Implementations

### Production Nodes
- **Geth** (Go Ethereum) - Go implementation
- **Besu** (Hyperledger Besu) - Java implementation  
- **Nethermind** - .NET implementation
- **Erigon** (formerly TurboGeth) - Go implementation
- **Reth** - Rust implementation (modern)
- **Parity/OpenEthereum** - Rust implementation (legacy)
- **EthereumJS** - TypeScript implementation (beta)

### Development Tools
- **Hardhat Network** - JavaScript/TypeScript
- **Ganache** - JavaScript
- **Anvil** (Foundry) - Rust

## CVE Vulnerability Detection 🛡️

The tool includes an integrated CVE database that automatically checks for known security vulnerabilities based on the detected node implementation and version. This feature provides critical security intelligence for blockchain infrastructure assessment.

### Security Assessment Features

- **Automated CVE Scanning**: Real-time vulnerability assessment during fingerprinting
- **Comprehensive Database**: Covers all major Ethereum client implementations
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW risk levels with CVSS scores
- **Actionable Recommendations**: Specific upgrade paths and mitigation strategies

### Supported CVE Coverage

The vulnerability database includes security advisories for:

- **Geth** (Go Ethereum): Consensus vulnerabilities, DoS attacks, memory exhaustion
- **Parity/OpenEthereum**: Light client vulnerabilities, consensus issues
- **Besu** (Hyperledger): P2P protocol vulnerabilities, information disclosure
- **Nethermind**: JSON-RPC DoS vulnerabilities
- **Erigon**: State sync vulnerabilities, consensus issues
- **Reth**: Memory exhaustion vulnerabilities

### Example Security Output

When vulnerabilities are detected, the tool displays comprehensive security information:

```
╭─────────────────────────────── 🔒 Security Assessment ───────────────────────────────╮
│ 🚨 CRITICAL security risk - 3 vulnerability(s) found                                 │
╰───────────────────────────────────────────────────────────────────────────────────────╯

                     ⚠️ Vulnerability Details (3 found)                      
╭────────────────┬──────────┬──────┬──────────────────────────────┬──────────╮
│ CVE ID         │ Severity │ CVSS │ Title                        │ Fixed In │
├────────────────┼──────────┼──────┼──────────────────────────────┼──────────┤
│ CVE-2021-39137 │ CRITICAL │ 9.8  │ Geth consensus flaw in       │ 1.10.8   │
│                │          │      │ London hard fork             │          │
│ CVE-2021-41173 │ HIGH     │ 7.5  │ Geth DoS via malformed trie  │ 1.10.9   │
│                │          │      │ node                         │          │
│ CVE-2022-23328 │ HIGH     │ 7.5  │ Geth memory exhaustion via   │ 1.10.15  │
│                │          │      │ large RPC requests           │          │
╰────────────────┴──────────┴──────┴──────────────────────────────┴──────────╯

                        🔧 Security Recommendations                        
╭──────────┬─────────────────────────────────────────────────────────────╮
│ Priority │ Recommendation                                              │
├──────────┼─────────────────────────────────────────────────────────────┤
│ URGENT   │ Critical update required - upgrade to v1.10.8+ immediately │
│ HIGH     │ Update to Geth v1.10.9 or later immediately                │
│ HIGH     │ Upgrade to Geth v1.10.15 or configure request size limits  │
╰──────────┴─────────────────────────────────────────────────────────────╯
```

### CVE Database Management

The CVE database is automatically loaded and maintained:

- **Database Location**: `cve_database.json` (included with installation)
- **Update Frequency**: Updated with each package release
- **Custom Databases**: Support for custom CVE database files
- **Version Matching**: Intelligent version range and pattern matching

### Security Use Cases

- **Infrastructure Auditing**: Identify vulnerable nodes in production environments
- **Penetration Testing**: Rapid vulnerability assessment during security testing  
- **Compliance Monitoring**: Track security posture of blockchain infrastructure
- **Incident Response**: Quick vulnerability identification during security incidents
- **Upgrade Planning**: Prioritize node updates based on security risk levels

## CLI Documentation

For comprehensive CLI usage, see [CLI_USAGE.md](docs/CLI_USAGE.md).

## Security Considerations

This tool is designed for:
- ✅ Security research and auditing
- ✅ Network analysis and monitoring
- ✅ Development and testing
- ✅ Educational purposes

**Important**: Only use this tool on endpoints you own or have explicit permission to test. Unauthorized scanning of RPC endpoints may violate terms of service or be considered malicious activity.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`python tests/test_runner.py`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Publishing

For maintainers, use the automated publish script to release new versions:

```bash
# Test with dry run first
./publish.sh --dry-run

# Publish patch version to Test PyPI
./publish.sh patch --test

# Publish to production PyPI
./publish.sh patch
```

See [PUBLISHING.md](PUBLISHING.md) for detailed publishing instructions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.2.0 (2025-09-16) - Current Release
- **CVE Vulnerability Detection**: Integrated comprehensive CVE database for automatic security vulnerability assessment
- **Security Intelligence**: Real-time vulnerability scanning based on detected node implementation and version
- **Risk Assessment**: CRITICAL/HIGH/MEDIUM/LOW risk classification with CVSS scores and color-coded alerts
- **Comprehensive CVE Coverage**: Database includes vulnerabilities for Geth, Parity/OpenEthereum, Besu, Nethermind, Erigon, and Reth
- **Rich Security Display**: Beautiful security assessment panels with color-coded severity levels and detailed vulnerability tables
- **Actionable Recommendations**: Specific upgrade paths and mitigation strategies for detected vulnerabilities
- **Security-First Design**: Automated security assessment integrated into all fingerprinting operations
- **Enhanced Test Suite**: 59 comprehensive unit tests including full CVE database and vulnerability detection coverage

### v1.1.2 (2025-09-15)
- **Rich Progress Consistency**: Fixed synchronous mode to use Rich progress bars instead of basic click progress
- **Enhanced Node Support**: Added comprehensive support for Reth (Rust) and EthereumJS implementations  
- **Improved Detection**: Enhanced node implementation extraction with better coverage of official Ethereum clients
- **Unified Progress Experience**: Both sync and async modes now provide beautiful Rich progress bars with consistent styling
- **Build Information Handling**: Improved parsing and display of build information from client version strings

### v1.1.1 (2025-09-13)
- **New Node Implementations**: Added support for Reth (modern Rust implementation) and EthereumJS (TypeScript beta)
- **Complete Official Coverage**: Now supports all production Ethereum execution clients listed on ethereum.org
- **Enhanced Build Info**: Improved handling and formatting of build information in async fingerprinting
- **Better Detection**: Enhanced node implementation detection with improved pattern matching

### v1.1.0 (2025-09-12)
- **File Input Support**: Added `--file` / `-f` option to read endpoint lists from files (one URL per line)
- **Rich Integration**: Beautiful progress bars with real-time completion tracking, elapsed time, and ETA
- **Enhanced Tables**: Modern rounded tables with color-coded values and professional styling
- **Improved UX**: Spinner animations, better visual feedback, and emoji icons for different sections
- **Progress Tracking**: Real-time progress bars for async scanning with completion rates and timing
- **Better CLI**: Enhanced verbose output with Rich console formatting and improved readability
- **Bulk Scanning**: Perfect for pentesting workflows - scan thousands of endpoints with visual progress

### v1.0.0 (2025-09-11)
- **Major Release**: Migrated to Click CLI framework with modern interface
- **Async Processing**: Added async support for multiple endpoints with configurable concurrency
- **Enhanced Output**: Colored tables, improved formatting, and better error handling
- **YAML Support**: Added YAML output format alongside JSON and table formats
- **PyPI Publication**: Published to PyPI with easy `pip install` and automated publishing
- **Documentation**: Added comprehensive CLI documentation and usage examples
- **Improved Parsing**: Enhanced client version parsing with better language/OS detection

### v0.3.0
- Migrated to Click CLI framework with modern interface
- Added async processing for multiple endpoints
- Enhanced output formatting with colored tables
- Added YAML output support
- Published to PyPI with easy installation
- Added comprehensive CLI documentation
- Improved error handling and progress indication

### v0.2.0
- Added detailed client version parsing
- Enhanced security analysis with language/OS detection
- Improved method detection and categorization
- Better error handling and timeout management

### v0.1.0
- Initial release with basic fingerprinting
- Support for major Ethereum client implementations
- JSON export functionality
- Basic client version detection
