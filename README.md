# Ethereum RPC Fingerprinting Tool

A comprehensive Python tool for fingerprinting Ethereum RPC endpoints to identify node implementations, versions, network configurations, and security characteristics.

## Features

- 🔍 **Enhanced Node Detection**: Identify Geth, Parity/OpenEthereum, Besu, Nethermind, Erigon, Anvil, Hardhat, Ganache, TurboGeth
- 🧬 **Detailed Client Analysis**: Extract programming language, version, OS, and architecture from client version strings
- 📊 **Network Information**: Chain ID, network ID, block height, gas prices, peer count
- 🚀 **Async Support**: Fingerprint multiple endpoints concurrently
- 🔐 **Security Analysis**: Detect exposed accounts, admin interfaces, debug capabilities
- 📋 **Method Discovery**: Enumerate supported RPC methods
- 🎨 **Formatted Output**: Colored terminal output with tables
- 📄 **JSON Export**: Export results to JSON for further analysis

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

```bash
# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Command Line Usage

```bash
# Fingerprint a single endpoint
python ethereum_rpc_fingerprinter.py http://localhost:8545

# Fingerprint multiple endpoints
python ethereum_rpc_fingerprinter.py http://localhost:8545 http://localhost:8546

# Use async mode for multiple endpoints
python ethereum_rpc_fingerprinter.py --async-mode http://localhost:8545 http://localhost:8546

# Export results to JSON
python ethereum_rpc_fingerprinter.py --output results.json http://localhost:8545

# Quiet mode (JSON only)
python ethereum_rpc_fingerprinter.py --quiet --output results.json http://localhost:8545
```

### Python Library Usage

```python
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, print_fingerprint_result

# Create fingerprinter instance
fingerprinter = EthereumRPCFingerprinter(timeout=10)

# Fingerprint an endpoint
result = fingerprinter.fingerprint("http://localhost:8545")

# Print formatted result
print_fingerprint_result(result)

# Access individual fields
print(f"Node Implementation: {result.node_implementation}")
print(f"Client Version: {result.client_version}")
print(f"Chain ID: {result.chain_id}")
```

### Async Fingerprinting

```python
import asyncio
from ethereum_rpc_fingerprinter import AsyncEthereumRPCFingerprinter

async def fingerprint_multiple():
    fingerprinter = AsyncEthereumRPCFingerprinter(timeout=10, max_concurrent=5)
    
    endpoints = [
        "http://localhost:8545",
        "http://localhost:8546",
        "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
    ]
    
    results = await fingerprinter.fingerprint_multiple(endpoints)
    
    for result in results:
        print(f"Endpoint: {result.endpoint}")
        print(f"Implementation: {result.node_implementation}")

# Run async fingerprinting
asyncio.run(fingerprint_multiple())
```

## Examples

Run the example script to see various usage patterns:

```bash
python example_usage.py
```

## What Gets Fingerprinted

### Basic Information
- Client version string
- Node implementation (Geth, Parity, etc.)
- Network ID and Chain ID
- Protocol version
- Response time

### Network Status
- Current block number
- Gas price
- Peer count
- Syncing status
- Mining status and hashrate

### Security Information
- Exposed accounts
- Admin namespace availability
- Debug namespace availability
- Transaction pool access

### Method Discovery
- Enumerate all supported RPC methods
- Group by namespace (eth, net, web3, etc.)

### Advanced Features
- Block structure analysis
- Implementation-specific namespace detection
- Custom method testing

## Node Implementation Detection

The tool can identify these Ethereum client implementations:

- **Geth** - Most common Ethereum client
- **Parity/OpenEthereum** - Rust-based client
- **Besu** - Java-based enterprise client
- **Nethermind** - .NET-based client
- **Erigon** - Go-based archive node
- **Anvil** - Local development node (Foundry)
- **Hardhat** - Development environment
- **Ganache** - Testing blockchain

## Security Considerations

This tool is designed for:
- ✅ Security research and auditing
- ✅ Network analysis and monitoring
- ✅ Development and testing
- ✅ Educational purposes

**Important**: Only use this tool on endpoints you own or have explicit permission to test. Unauthorized scanning of RPC endpoints may violate terms of service or be considered malicious activity.

## Output Format

### Terminal Output
- Colored, formatted tables showing all gathered information
- Grouped by categories (Basic Info, Network Status, etc.)
- Error reporting for failed operations

### JSON Output
```json
{
  "endpoint": "http://localhost:8545",
  "client_version": "Geth/v1.10.26-stable/linux-amd64/go1.18.5",
  "node_implementation": "Geth",
  "network_id": 1,
  "chain_id": 1,
  "block_number": 18500000,
  "gas_price": 20000000000,
  "peer_count": 25,
  "syncing": false,
  "mining": false,
  "supported_methods": ["web3_clientVersion", "eth_blockNumber", ...],
  "additional_info": {
    "admin_namespace": true,
    "debug_namespace": true,
    "txpool_namespace": true
  },
  "errors": []
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any RPC endpoints. The authors are not responsible for any misuse of this tool.
