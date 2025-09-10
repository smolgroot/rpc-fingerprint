#!/usr/bin/env python3
"""
Test client version parsing functionality
"""

from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter

def test_client_version_parsing():
    """Test the client version parsing with various real-world examples"""
    
    fingerprinter = EthereumRPCFingerprinter()
    
    # Real-world client version examples
    test_versions = [
        "Geth/v1.10.26-stable/linux-amd64/go1.18.5",
        "Geth/v1.13.5-stable/darwin-arm64/go1.21.4",
        "Parity-Ethereum/v2.7.2-stable/x86_64-linux-gnu/rustc1.41.0",
        "OpenEthereum/v3.3.5-stable/x86_64-unknown-linux-gnu/rustc1.56.1",
        "Besu/v22.10.3/linux-x86_64/openjdk-java-11",
        "Besu/v23.4.0/darwin-aarch64/openjdk-java-17",
        "Nethermind/v1.14.6+6c21356f/linux-x64/dotnet6.0.11",
        "Nethermind/v1.20.3+77d89dbe/windows-x64/dotnet8.0.0",
        "erigon/2.48.1/linux-amd64/go1.19.2",
        "erigon/2.55.0/darwin-arm64/go1.21.4",
        "anvil 0.1.0 (fdd321b 2023-10-04T00:21:13.119600000Z)",
        "anvil 0.2.0 (a1b2c3d 2024-01-15T10:30:45.123456789Z)",
        "HardhatNetwork/2.17.1/@ethereumjs/vm/5.9.3/node/v18.17.0",
        "TestRPC/v2.13.2/ethereum-js",
        "Ganache/v7.9.1/linux/node/v16.20.1",
        "TurboGeth/v2021.03.4-alpha/linux-amd64/go1.16.2",
        # Edge cases
        "CustomClient/v1.0.0",
        "SomeNode/beta-0.5.2/freebsd-amd64/rust1.60.0",
        "",  # Empty string
        "InvalidFormat",  # No version pattern
    ]
    
    print("🧪 Testing Client Version Parsing")
    print("=" * 80)
    
    for version_str in test_versions:
        print(f"\n📋 Testing: {version_str or '(empty string)'}")
        print("-" * 60)
        
        try:
            parsed = fingerprinter._parse_client_version(version_str)
            implementation = fingerprinter._extract_node_implementation(version_str)
            
            print(f"Implementation:        {implementation}")
            print(f"Node Version:          {parsed.get('node_version', 'N/A')}")
            print(f"Programming Language:  {parsed.get('programming_language', 'N/A')}")
            print(f"Language Version:      {parsed.get('language_version', 'N/A')}")
            print(f"Operating System:      {parsed.get('operating_system', 'N/A')}")
            print(f"Architecture:          {parsed.get('architecture', 'N/A')}")
            
            if parsed.get('build_info') and any(parsed['build_info'].values()):
                print(f"Build Info:            {parsed['build_info']}")
                
        except Exception as e:
            print(f"❌ Error parsing: {e}")
    
    print(f"\n🎯 Summary")
    print("=" * 80)
    print("Client version parsing tests completed!")
    print("The tool can extract detailed information from various client version formats.")

if __name__ == "__main__":
    test_client_version_parsing()
