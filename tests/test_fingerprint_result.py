#!/usr/bin/env python3
"""
Unit tests for FingerprintResult functionality and data structures.
"""

import unittest
from ethereum_rpc_fingerprinter import FingerprintResult


class TestFingerprintResult(unittest.TestCase):
    """Test FingerprintResult data structure and methods."""
    
    def test_fingerprint_result_initialization(self):
        """Test FingerprintResult can be initialized properly."""
        endpoint = "http://localhost:8545"
        result = FingerprintResult(endpoint=endpoint, errors=[])
        
        self.assertEqual(result.endpoint, endpoint)
        self.assertIsInstance(result.errors, list)
        self.assertEqual(len(result.errors), 0)
        
        # Test that all expected attributes exist
        expected_attributes = [
            'endpoint', 'errors', 'client_version', 'node_implementation',
            'node_version', 'programming_language', 'language_version',
            'operating_system', 'architecture', 'build_info', 'chain_id',
            'network_id', 'block_number', 'gas_price', 'protocol_version',
            'supported_methods', 'response_time'
        ]
        
        for attr in expected_attributes:
            self.assertTrue(hasattr(result, attr), f"Missing attribute: {attr}")
    
    def test_fingerprint_result_error_handling(self):
        """Test error handling in FingerprintResult."""
        result = FingerprintResult(endpoint="http://test.com", errors=[])
        
        # Test adding errors
        result.errors.append("Connection failed")
        result.errors.append("Timeout occurred")
        
        self.assertEqual(len(result.errors), 2)
        self.assertIn("Connection failed", result.errors)
        self.assertIn("Timeout occurred", result.errors)
    
    def test_fingerprint_result_attributes_are_mutable(self):
        """Test that FingerprintResult attributes can be modified."""
        result = FingerprintResult(endpoint="http://test.com", errors=[])
        
        # Test setting various attributes
        result.client_version = "Geth/v1.10.0"
        result.node_implementation = "Geth"
        result.chain_id = 1
        result.block_number = 12345
        result.supported_methods = ["eth_blockNumber", "eth_getBalance"]
        
        self.assertEqual(result.client_version, "Geth/v1.10.0")
        self.assertEqual(result.node_implementation, "Geth")
        self.assertEqual(result.chain_id, 1)
        self.assertEqual(result.block_number, 12345)
        self.assertEqual(len(result.supported_methods), 2)
    
    def test_fingerprint_result_with_build_info(self):
        """Test FingerprintResult with build_info dictionary."""
        result = FingerprintResult(endpoint="http://test.com", errors=[])
        
        build_info = {
            "commit": "abc123",
            "build_date": "2023-10-04T00:21:13.119600000Z",
            "version": "1.0.0"
        }
        result.build_info = build_info
        
        self.assertIsInstance(result.build_info, dict)
        self.assertEqual(result.build_info["commit"], "abc123")
        self.assertEqual(result.build_info["build_date"], "2023-10-04T00:21:13.119600000Z")
    
    def test_fingerprint_result_handles_none_values(self):
        """Test that FingerprintResult handles None values gracefully."""
        result = FingerprintResult(endpoint="http://test.com", errors=[])
        
        # Set various attributes to None
        result.client_version = None
        result.node_implementation = None
        result.chain_id = None
        result.block_number = None
        result.build_info = None
        
        # Should not raise exceptions
        self.assertIsNone(result.client_version)
        self.assertIsNone(result.node_implementation)
        self.assertIsNone(result.chain_id)
        self.assertIsNone(result.block_number)
        self.assertIsNone(result.build_info)
    
    def test_fingerprint_result_with_empty_collections(self):
        """Test FingerprintResult with empty lists and dictionaries."""
        result = FingerprintResult(endpoint="http://test.com", errors=[])
        
        result.supported_methods = []
        result.build_info = {}
        
        self.assertEqual(len(result.supported_methods), 0)
        self.assertEqual(len(result.build_info), 0)
        
        self.assertIsInstance(result.supported_methods, list)
        self.assertIsInstance(result.build_info, dict)


class TestFingerprintResultIntegration(unittest.TestCase):
    """Test FingerprintResult integration with main fingerprinting logic."""
    
    def setUp(self):
        """Set up test fixtures."""
        from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter
        self.fingerprinter = EthereumRPCFingerprinter()
    
    def test_result_creation_from_fingerprinting(self):
        """Test that fingerprinting creates proper FingerprintResult objects."""
        endpoint = "http://localhost:8545"
        
        # Test with a definitely invalid endpoint
        result = self.fingerprinter.fingerprint(endpoint)
        
        self.assertIsInstance(result, FingerprintResult)
        self.assertEqual(result.endpoint, endpoint)
        # Should have some result, even if it's just errors
        self.assertIsInstance(result.errors, list)
    
    def test_invalid_endpoint_handling(self):
        """Test handling of invalid endpoints."""
        invalid_endpoint = "http://definitely-not-a-real-endpoint.invalid:8545"
        
        result = self.fingerprinter.fingerprint(invalid_endpoint)
        
        self.assertIsInstance(result, FingerprintResult)
        self.assertEqual(result.endpoint, invalid_endpoint)
        # Should have errors for invalid endpoint
        self.assertIsInstance(result.errors, list)
        # Most likely will have errors, but we won't assert on the exact count
        # since it depends on network conditions


if __name__ == '__main__':
    unittest.main()
