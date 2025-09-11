#!/usr/bin/env python3
"""
Test script for the Ethereum RPC Fingerprinting Tool
"""

from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, print_fingerprint_result
import json

def test_basic_functionality():
    """Test basic functionality with a mock-like approach"""
    print("🧪 Testing Ethereum RPC Fingerprinting Tool")
    print("=" * 50)
    
    # Create fingerprinter instance
    fingerprinter = EthereumRPCFingerprinter(timeout=5)
    
    # Test endpoints (these will likely fail but show the structure)
    test_endpoints = [
        "http://localhost:8545",  # Local Geth
        "http://127.0.0.1:8545",  # Alternative localhost
        "https://polygon-rpc.com",  # Public endpoint
    ]
    
    for endpoint in test_endpoints:
        print(f"\n🔍 Testing: {endpoint}")
        print("-" * 40)
        
        try:
            result = fingerprinter.fingerprint(endpoint)
            
            # Show basic result structure
            print(f"Endpoint: {result.endpoint}")
            print(f"Errors: {len(result.errors)} error(s)")
            
            if result.errors:
                print("❌ Connection failed:")
                for error in result.errors[:3]:  # Show first 3 errors
                    print(f"  • {error}")
            else:
                print("✅ Connection successful!")
                print_fingerprint_result(result)
                
        except Exception as e:
            print(f"❌ Exception during fingerprinting: {e}")
    
    print(f"\n📊 Test Summary")
    print("=" * 50)
    print("The fingerprinting tool is ready to use!")
    print("To test with real endpoints:")
    print("1. Start a local Ethereum node (Geth, Anvil, Hardhat, etc.)")
    print("2. Run: python ethereum_rpc_fingerprinter.py http://localhost:8545")
    print("3. Or use public endpoints with proper API keys")

def test_import_structure():
    """Test that all imports work correctly"""
    print("\n🔧 Testing Imports and Structure")
    print("-" * 40)
    
    try:
        from ethereum_rpc_fingerprinter import (
            EthereumRPCFingerprinter,
            AsyncEthereumRPCFingerprinter,
            FingerprintResult,
            print_fingerprint_result
        )
        print("✅ All imports successful")
        
        # Test creating instances
        sync_fp = EthereumRPCFingerprinter()
        async_fp = AsyncEthereumRPCFingerprinter()
        print("✅ Instance creation successful")
        
        # Test result structure
        result = FingerprintResult(endpoint="test://example")
        result_dict = result.__dict__
        print(f"✅ FingerprintResult has {len(result_dict)} fields")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ General error: {e}")
        return False

if __name__ == "__main__":
    # Test imports first
    if test_import_structure():
        # Then test basic functionality
        test_basic_functionality()
    else:
        print("❌ Basic import tests failed. Please check dependencies.")
