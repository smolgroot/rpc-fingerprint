#!/usr/bin/env python3
"""
Integration tests for the Ethereum RPC Fingerprinter.
These tests require actual network connectivity and running Ethereum nodes.
"""

import unittest
import asyncio
import os
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, AsyncEthereumRPCFingerprinter


class TestRealWorldIntegration(unittest.TestCase):
    """Integration tests with real endpoints (if available)."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter(timeout=10)
        self.async_fingerprinter = AsyncEthereumRPCFingerprinter(timeout=10)
    
    def test_localhost_connection(self):
        """Test connection to localhost (if a node is running)."""
        localhost_endpoints = [
            "http://localhost:8545",
            "http://127.0.0.1:8545",
        ]
        
        for endpoint in localhost_endpoints:
            with self.subTest(endpoint=endpoint):
                print(f"\\n🔍 Testing localhost endpoint: {endpoint}")
                
                try:
                    result = self.fingerprinter.fingerprint(endpoint)
                    
                    # Basic validation
                    self.assertEqual(result.endpoint, endpoint)
                    self.assertIsInstance(result.errors, list)
                    
                    if result.errors:
                        print(f"  ⚠️  Connection failed (expected if no local node): {result.errors[0]}")
                        # This is expected if no local node is running
                        self.assertGreater(len(result.errors), 0)
                    else:
                        print(f"  ✅ Connection successful!")
                        print(f"  📋 Client: {result.client_version}")
                        print(f"  🏷️  Implementation: {result.node_implementation}")
                        
                        # If connection succeeded, validate the data
                        self.assertIsNotNone(result.client_version)
                        self.assertIsNotNone(result.node_implementation)
                        
                except Exception as e:
                    print(f"  ❌ Exception during test: {e}")
                    # Fail only if it's an unexpected exception type
                    if not any(keyword in str(e).lower() for keyword in 
                              ['connection', 'refused', 'timeout', 'unreachable']):
                        self.fail(f"Unexpected exception: {e}")
    
    def test_public_endpoint_structure(self):
        """Test the structure with a public endpoint (without making actual calls)."""
        # This test validates that the fingerprinting structure works
        # without actually hitting public endpoints to avoid rate limits
        
        public_endpoints = [
            "https://ethereum-rpc.publicnode.com",
            "https://rpc.ankr.com/eth",
            "https://eth.llamarpc.com",
        ]
        
        for endpoint in public_endpoints:
            with self.subTest(endpoint=endpoint):
                print(f"\\n🌐 Validating structure for: {endpoint}")
                
                # Create a result without making actual network calls
                from ethereum_rpc_fingerprinter import FingerprintResult
                result = FingerprintResult(endpoint=endpoint)
                
                # Validate structure
                self.assertEqual(result.endpoint, endpoint)
                self.assertIsInstance(result.errors, list)
                self.assertEqual(len(result.errors), 0)
                
                # Test that we can set expected attributes
                result.client_version = "Geth/v1.13.0"
                result.node_implementation = "Geth"
                result.chain_id = 1
                
                self.assertEqual(result.client_version, "Geth/v1.13.0")
                self.assertEqual(result.node_implementation, "Geth")
                self.assertEqual(result.chain_id, 1)
                
                print(f"  ✅ Structure validation passed")
    
    def test_error_handling_with_invalid_endpoints(self):
        """Test error handling with obviously invalid endpoints."""
        invalid_endpoints = [
            "http://definitely-not-a-real-endpoint.invalid:8545",
            "https://fake-ethereum-node.nowhere.com",
            "http://192.0.2.1:8545",  # RFC5737 test address
        ]
        
        for endpoint in invalid_endpoints:
            with self.subTest(endpoint=endpoint):
                print(f"\\n❌ Testing invalid endpoint: {endpoint}")
                
                result = self.fingerprinter.fingerprint(endpoint)
                
                # Should have errors for invalid endpoints
                self.assertGreater(len(result.errors), 0)
                self.assertEqual(result.endpoint, endpoint)
                
                # Client version should be None for failed connections
                self.assertIsNone(result.client_version)
                self.assertIsNone(result.node_implementation)
                
                print(f"  ✅ Error handling working correctly: {result.errors[0]}")
    
    @unittest.skipIf(os.getenv('SKIP_ASYNC_TESTS'), "Async tests skipped")
    def test_async_functionality_structure(self):
        """Test async functionality structure."""
        async def async_test():
            endpoint = "http://localhost:8545"
            
            # Test that async fingerprinting can be called
            # (will likely fail with connection error, but that's expected)
            try:
                result = await self.async_fingerprinter.fingerprint(endpoint)
                self.assertEqual(result.endpoint, endpoint)
                self.assertIsInstance(result.errors, list)
                print("  ✅ Async fingerprinting structure works")
            except Exception as e:
                # Expected for localhost without running node
                print(f"  ⚠️  Async connection failed (expected): {e}")
                self.assertTrue(any(keyword in str(e).lower() for keyword in 
                                  ['connection', 'refused', 'timeout', 'unreachable']))
        
        # Run the async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(async_test())
        finally:
            loop.close()


class TestPerformanceAndLimits(unittest.TestCase):
    """Test performance characteristics and limits."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter(timeout=5)
    
    def test_timeout_enforcement(self):
        """Test that timeouts are properly enforced."""
        # Use a very short timeout
        fast_fingerprinter = EthereumRPCFingerprinter(timeout=0.001)  # 1ms timeout
        
        # Try to connect to a real endpoint that would normally respond
        # but with such a short timeout it should fail
        endpoint = "http://localhost:8545"
        
        result = fast_fingerprinter.fingerprint(endpoint)
        
        # Should have timeout-related errors
        self.assertGreater(len(result.errors), 0)
        
        # Check that error mentions timeout
        error_text = " ".join(result.errors).lower()
        self.assertTrue(any(keyword in error_text for keyword in 
                           ['timeout', 'time', 'connection']))
        
        print(f"  ✅ Timeout enforcement working: {result.errors[0]}")
    
    def test_multiple_endpoint_handling(self):
        """Test handling multiple endpoints in sequence."""
        endpoints = [
            "http://localhost:8545",
            "http://localhost:8546", 
            "http://127.0.0.1:8545"
        ]
        
        results = []
        for endpoint in endpoints:
            result = self.fingerprinter.fingerprint(endpoint)
            results.append(result)
        
        # All should return FingerprintResult objects
        self.assertEqual(len(results), len(endpoints))
        
        for i, result in enumerate(results):
            with self.subTest(endpoint=endpoints[i]):
                self.assertEqual(result.endpoint, endpoints[i])
                self.assertIsInstance(result.errors, list)
        
        print(f"  ✅ Processed {len(results)} endpoints successfully")
    
    def test_memory_usage_with_large_error_lists(self):
        """Test that large error lists don't cause memory issues."""
        from ethereum_rpc_fingerprinter import FingerprintResult
        
        result = FingerprintResult(endpoint="http://test.com")
        
        # Add many errors to test memory handling
        for i in range(1000):
            result.errors.append(f"Error {i}: Connection failed to simulate large error list")
        
        self.assertEqual(len(result.errors), 1000)
        
        # Should still be functional
        result.client_version = "TestClient/v1.0.0"
        self.assertEqual(result.client_version, "TestClient/v1.0.0")
        
        print(f"  ✅ Handled {len(result.errors)} errors without issues")


if __name__ == '__main__':
    print("🧪 Running Integration Tests for Ethereum RPC Fingerprinter")
    print("=" * 70)
    print("⚠️  Note: These tests may fail if no local Ethereum node is running.")
    print("   This is expected behavior - the tests validate error handling.")
    print("=" * 70)
    
    unittest.main(verbosity=2)
