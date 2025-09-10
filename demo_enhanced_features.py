#!/usr/bin/env python3
"""
Enhanced Ethereum RPC Fingerprinting Tool Usage Examples

This script demonstrates the enhanced client version parsing functionality.
"""

from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, FingerprintResult, print_fingerprint_result
import json

def create_sample_results():
    """Create sample fingerprint results to demonstrate the enhanced functionality"""
    
    # Sample result for Geth node
    geth_result = FingerprintResult(
        endpoint="http://example-geth.com:8545",
        client_version="Geth/v1.13.5-stable/linux-amd64/go1.21.4",
        node_implementation="Geth",
        node_version="1.13.5-stable",
        programming_language="Go",
        language_version="1.21.4", 
        operating_system="Linux",
        architecture="amd64",
        network_id=1,
        chain_id=1,
        block_number=19500000,
        gas_price=25000000000,
        peer_count=42,
        syncing=False,
        mining=False,
        response_time=0.234,
        supported_methods=["web3_clientVersion", "eth_blockNumber", "eth_getBalance"],
        additional_info={
            "admin_namespace": True,
            "debug_namespace": True,
            "txpool_namespace": True
        },
        errors=[]
    )
    
    # Sample result for Besu node
    besu_result = FingerprintResult(
        endpoint="http://example-besu.com:8545",
        client_version="Besu/v23.4.0/linux-x86_64/openjdk-java-17",
        node_implementation="Besu",
        node_version="23.4.0",
        programming_language="Java", 
        language_version="17",
        operating_system="Linux",
        architecture="x86_64",
        network_id=137,
        chain_id=137,
        block_number=52000000,
        gas_price=30000000000,
        peer_count=28,
        syncing=False,
        mining=False,
        response_time=0.156,
        supported_methods=["web3_clientVersion", "eth_blockNumber", "eth_call"],
        additional_info={
            "admin_namespace": False,
            "debug_namespace": True,
            "txpool_namespace": False
        },
        errors=[]
    )
    
    # Sample result for Anvil (development)
    anvil_result = FingerprintResult(
        endpoint="http://localhost:8545",
        client_version="anvil 0.2.0 (a1b2c3d 2024-01-15T10:30:45.123456789Z)",
        node_implementation="Anvil",
        node_version="0.2.0",
        programming_language="Rust",
        operating_system=None,
        architecture=None,
        build_info={"commit_timestamp": "a1b2c3d 2024-01-15T10:30:45.123456789Z"},
        network_id=31337,
        chain_id=31337,
        block_number=0,
        gas_price=0,
        peer_count=0,
        syncing=False,
        mining=False,
        response_time=0.003,
        supported_methods=["web3_clientVersion", "eth_blockNumber", "eth_accounts"],
        additional_info={
            "admin_namespace": False,
            "debug_namespace": True,
            "txpool_namespace": False
        },
        errors=[]
    )
    
    # Sample result for Nethermind
    nethermind_result = FingerprintResult(
        endpoint="http://example-nethermind.com:8545",
        client_version="Nethermind/v1.20.3+77d89dbe/windows-x64/dotnet8.0.0",
        node_implementation="Nethermind", 
        node_version="1.20.3",
        programming_language=".NET",
        language_version="8.0.0",
        operating_system="Windows",
        architecture="x64",
        network_id=1,
        chain_id=1,
        block_number=19500000,
        gas_price=22000000000,
        peer_count=35,
        syncing=False,
        mining=False,
        response_time=0.187,
        supported_methods=["web3_clientVersion", "eth_blockNumber"],
        additional_info={
            "admin_namespace": True,
            "debug_namespace": True,
            "txpool_namespace": True
        },
        errors=[]
    )
    
    return [geth_result, besu_result, anvil_result, nethermind_result]

def main():
    """Main demo function"""
    print("🚀 Enhanced Ethereum RPC Fingerprinting Tool Demo")
    print("=" * 80)
    print()
    print("This demo shows the enhanced client version parsing capabilities")
    print("that can extract detailed information from Ethereum client version strings.")
    print()
    
    # Create sample results
    sample_results = create_sample_results()
    
    # Display each result
    for i, result in enumerate(sample_results, 1):
        print(f"\n📊 Example {i}: {result.node_implementation} Node")
        print_fingerprint_result(result)
        
        if i < len(sample_results):
            input("\nPress Enter to continue to next example...")
    
    print(f"\n🎯 Key Features Demonstrated:")
    print("=" * 80)
    print("✅ Node Implementation Detection (Geth, Besu, Anvil, Nethermind, etc.)")
    print("✅ Programming Language Identification (Go, Java, Rust, .NET)")
    print("✅ Language Version Extraction")
    print("✅ Operating System Detection") 
    print("✅ Architecture Identification (amd64, x86_64, ARM64, etc.)")
    print("✅ Node Version Parsing")
    print("✅ Build Information (where available)")
    print("✅ Comprehensive Network Analysis")
    print()
    print("🔍 How to Use with Real Endpoints:")
    print("-" * 40)
    print("# Single endpoint")
    print("python ethereum_rpc_fingerprinter.py http://localhost:8545")
    print()
    print("# Multiple endpoints (async)")
    print("python ethereum_rpc_fingerprinter.py --async-mode \\")
    print("    http://localhost:8545 \\")
    print("    https://eth.llamarpc.com \\")
    print("    https://rpc.ankr.com/eth")
    print()
    print("# Export to JSON")
    print("python ethereum_rpc_fingerprinter.py --output results.json http://localhost:8545")

if __name__ == "__main__":
    main()
