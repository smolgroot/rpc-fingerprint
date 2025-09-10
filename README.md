# Ethereum RPC Fingerprinting Tool

A comprehensive Python tool for fingerprinting Ethereum/EVM chains RPC endpoints to identify node implementations, versions, network configurations, and security characteristics.

[![PyPI version](https://badge.fury.io/py/ethereum-rpc-fingerprinter.svg)](https://badge.fury.io/py/ethereum-rpc-fingerprinter)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔍 **Enhanced Node Detection**: Identify Geth, Parity/OpenEthereum, Besu, Nethermind, Erigon, Anvil, Hardhat, Ganache, TurboGeth
- 🧬 **Detailed Client Analysis**: Extract programming language, version, OS, and architecture from client version strings
- 📊 **Network Information**: Chain ID, network ID, block height, gas prices, peer count
- 🚀 **Async Support**: Fingerprint multiple endpoints concurrently
- 🔐 **Security Analysis**: Detect exposed accounts, admin interfaces, debug capabilities
- 📋 **Method Discovery**: Enumerate supported RPC methods
- 🎨 **Modern CLI**: Clean Click-based command-line interface with progress bars and colored output
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

# Export results to JSON
erf fingerprint -o results.json http://localhost:8545

# Different output formats
erf fingerprint --format json http://localhost:8545
erf fingerprint --format yaml http://localhost:8545
erf fingerprint --format table http://localhost:8545  # default

# Verbose output with progress
erf fingerprint -v -a http://localhost:8545 https://cloudflare-eth.com
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
  --async-mode \
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
- **Parity/OpenEthereum** - Rust implementation (legacy)

### Development Tools
- **Hardhat Network** - JavaScript/TypeScript
- **Ganache** - JavaScript
- **Anvil** (Foundry) - Rust

## CLI Documentation

For comprehensive CLI usage, see [CLI_USAGE.md](CLI_USAGE.md).

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
4. Run tests (`python -m pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v0.3.0 (Latest)
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
