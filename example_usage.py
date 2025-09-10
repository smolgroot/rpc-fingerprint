#!/usr/bin/env python3
"""
Example usage of the Ethereum RPC Fingerprinting Tool
"""

from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, AsyncEthereumRPCFingerprinter, print_fingerprint_result
import asyncio
import json

def main():
    """Example usage of the fingerprinting tool"""
    
    # Example RPC endpoints (you can replace these with real endpoints)
    endpoints = [
        "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",  # Replace with real Infura endpoint
        "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY",  # Replace with real Alchemy endpoint
        "http://localhost:8545",  # Local Geth/other node
        "http://localhost:8546",  # Local Parity/other node
    ]
    
    print("🔍 Ethereum RPC Fingerprinting Tool Demo")
    print("=" * 50)
    
    # Example 1: Single endpoint fingerprinting
    print("\n📍 Example 1: Single Endpoint Fingerprinting")
    print("-" * 50)
    
    fingerprinter = EthereumRPCFingerprinter(timeout=5)
    
    # Test with a public endpoint (you may need to replace with working endpoint)
    test_endpoint = "http://localhost:8545"
    print(f"Testing endpoint: {test_endpoint}")
    
    result = fingerprinter.fingerprint(test_endpoint)
    print_fingerprint_result(result)
    
    # Example 2: Multiple endpoints with async fingerprinting
    print("\n📍 Example 2: Multiple Endpoints (Async)")
    print("-" * 50)
    
    async def async_example():
        async_fingerprinter = AsyncEthereumRPCFingerprinter(timeout=5, max_concurrent=3)
        
        # Filter to only localhost endpoints for demo
        test_endpoints = [ep for ep in endpoints if "localhost" in ep]
        
        print(f"Testing {len(test_endpoints)} endpoints asynchronously...")
        
        results = await async_fingerprinter.fingerprint_multiple(test_endpoints)
        
        for result in results:
            print_fingerprint_result(result)
    
    # Run async example
    try:
        asyncio.run(async_example())
    except Exception as e:
        print(f"Async example failed: {e}")
    
    # Example 3: Analyze specific node characteristics
    print("\n📍 Example 3: Node Implementation Analysis")
    print("-" * 50)
    
    def analyze_node_implementation(endpoint):
        """Analyze specific characteristics of a node implementation"""
        result = fingerprinter.fingerprint(endpoint)
        
        if result.node_implementation:
            print(f"Detected Implementation: {result.node_implementation}")
            
            # Implementation-specific analysis
            if result.node_implementation == 'Geth':
                print("🔹 Geth-specific features detected:")
                if result.additional_info and result.additional_info.get('admin_namespace'):
                    print("  ✓ Admin namespace available")
                if result.additional_info and result.additional_info.get('txpool_namespace'):
                    print("  ✓ Txpool namespace available")
                    
            elif result.node_implementation == 'Parity/OpenEthereum':
                print("🔹 Parity/OpenEthereum-specific features:")
                # Add Parity-specific checks
                
            elif result.node_implementation in ['Anvil', 'Hardhat', 'Ganache']:
                print(f"🔹 {result.node_implementation} (Development/Testing node)")
                print("  ⚠️  This appears to be a development environment")
        
        return result
    
    # Test localhost endpoint
    analyze_node_implementation("http://localhost:8545")
    
    # Example 4: Security-focused fingerprinting
    print("\n📍 Example 4: Security Analysis")
    print("-" * 50)
    
    def security_analysis(endpoint):
        """Perform security-focused analysis"""
        result = fingerprinter.fingerprint(endpoint)
        
        security_issues = []
        
        # Check for exposed accounts
        if result.accounts and len(result.accounts) > 0:
            security_issues.append(f"⚠️  {len(result.accounts)} accounts exposed")
        
        # Check for mining capability
        if result.mining:
            security_issues.append("⚠️  Mining is active")
        
        # Check for admin namespace
        if result.additional_info and result.additional_info.get('admin_namespace'):
            security_issues.append("⚠️  Admin namespace is accessible")
        
        # Check for debug namespace
        if result.additional_info and result.additional_info.get('debug_namespace'):
            security_issues.append("⚠️  Debug namespace is accessible")
        
        if security_issues:
            print("🚨 Security concerns detected:")
            for issue in security_issues:
                print(f"  {issue}")
        else:
            print("✅ No obvious security issues detected")
        
        return security_issues
    
    security_analysis("http://localhost:8545")

if __name__ == "__main__":
    main()
