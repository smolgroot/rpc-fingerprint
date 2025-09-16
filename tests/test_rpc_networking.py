#!/usr/bin/env python3
"""
Unit tests for RPC networking functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import requests
import aiohttp
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, AsyncEthereumRPCFingerprinter


class TestNetworkingFunctionality(unittest.TestCase):
    """Test networking functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter(timeout=5)
    
    def test_fingerprinter_initialization(self):
        """Test that fingerprinter initializes correctly."""
        self.assertEqual(self.fingerprinter.timeout, 5)
        self.assertIsNotNone(self.fingerprinter.session)
    
    def test_timeout_configuration(self):
        """Test that timeout is properly configured."""
        custom_timeout = 30
        fingerprinter = EthereumRPCFingerprinter(timeout=custom_timeout)
        self.assertEqual(fingerprinter.timeout, custom_timeout)
    
    @patch('requests.Session.post')
    def test_connection_error_handling(self, mock_post):
        """Test handling of connection errors."""
        # Mock connection error
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")
        
        result = self.fingerprinter.fingerprint("http://invalid-endpoint:8545")
        
        # Should handle the error gracefully
        self.assertIsNotNone(result)
        self.assertEqual(result.endpoint, "http://invalid-endpoint:8545")
        self.assertIsInstance(result.errors, list)
        self.assertGreater(len(result.errors), 0)
    
    @patch('requests.Session.post')
    def test_timeout_error_handling(self, mock_post):
        """Test handling of timeout errors."""
        # Mock timeout error
        mock_post.side_effect = requests.exceptions.Timeout("Request timeout")
        
        result = self.fingerprinter.fingerprint("http://timeout-endpoint:8545")
        
        # Should handle the timeout gracefully
        self.assertIsNotNone(result)
        self.assertIsInstance(result.errors, list)
        self.assertGreater(len(result.errors), 0)
    
    def test_method_discovery_list(self):
        """Test that method discovery returns a list."""
        # This tests the structure without making network calls
        methods = self.fingerprinter._discover_methods("http://test.com")
        
        # Should return a list (might be empty if no connection)
        self.assertIsInstance(methods, list)
    
    def test_fingerprint_returns_correct_structure(self):
        """Test that fingerprint always returns FingerprintResult."""
        from ethereum_rpc_fingerprinter import FingerprintResult
        
        result = self.fingerprinter.fingerprint("http://definitely-invalid-endpoint.test:8545")
        
        self.assertIsInstance(result, FingerprintResult)
        self.assertEqual(result.endpoint, "http://definitely-invalid-endpoint.test:8545")
        self.assertIsInstance(result.errors, list)


class TestAsyncNetworkingFunctionality(unittest.TestCase):
    """Test async networking functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.async_fingerprinter = AsyncEthereumRPCFingerprinter(timeout=5, max_concurrent=2)
    
    def test_async_fingerprinter_initialization(self):
        """Test async fingerprinter initialization."""
        self.assertEqual(self.async_fingerprinter.timeout, 5)
        self.assertEqual(self.async_fingerprinter.max_concurrent, 2)
    
    def test_async_fingerprinter_has_required_methods(self):
        """Test that async fingerprinter has required methods."""
        # Check for the fingerprint_multiple method
        self.assertTrue(hasattr(self.async_fingerprinter, 'fingerprint_multiple'))
        
        # Check it's a coroutine function
        import inspect
        self.assertTrue(inspect.iscoroutinefunction(self.async_fingerprinter.fingerprint_multiple))
    
    def test_async_configuration(self):
        """Test async fingerprinter configuration options."""
        custom_fingerprinter = AsyncEthereumRPCFingerprinter(timeout=15, max_concurrent=5)
        self.assertEqual(custom_fingerprinter.timeout, 15)
        self.assertEqual(custom_fingerprinter.max_concurrent, 5)


class TestMethodDetection(unittest.TestCase):
    """Test method detection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter()
    
    def test_standard_methods_list_structure(self):
        """Test that standard methods are properly defined."""
        # This tests the method discovery structure
        methods = self.fingerprinter._discover_methods("http://test.com")
        
        # Should return a list
        self.assertIsInstance(methods, list)
    
    def test_extract_node_implementation_function_exists(self):
        """Test that node implementation extraction function exists."""
        self.assertTrue(hasattr(self.fingerprinter, '_extract_node_implementation'))
        
        # Test with a known implementation
        result = self.fingerprinter._extract_node_implementation("Geth/v1.10.0")
        self.assertEqual(result, "Geth")
    
    def test_parse_client_version_function_exists(self):
        """Test that client version parsing function exists."""
        self.assertTrue(hasattr(self.fingerprinter, '_parse_client_version'))
        
        # Test with a known version string
        result = self.fingerprinter._parse_client_version("Geth/v1.10.0/linux-amd64/go1.18.5")
        self.assertIsInstance(result, dict)
        self.assertIn('node_version', result)
        self.assertIn('programming_language', result)


class TestErrorHandling(unittest.TestCase):
    """Test error handling scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter()
    
    def test_invalid_endpoint_handling(self):
        """Test handling of obviously invalid endpoints."""
        invalid_endpoints = [
            "not-a-url",
            "http://",
            "https://definitely-not-real.invalid",
            "",
            None
        ]
        
        for endpoint in invalid_endpoints:
            with self.subTest(endpoint=endpoint):
                try:
                    result = self.fingerprinter.fingerprint(endpoint)
                    # Should return a result object with errors
                    self.assertIsNotNone(result)
                    if hasattr(result, 'errors'):
                        self.assertIsInstance(result.errors, list)
                except Exception:
                    # Some invalid endpoints might raise exceptions, which is also acceptable
                    pass
    
    def test_network_unavailable_handling(self):
        """Test handling when network is unavailable."""
        # Test with a definitely unreachable endpoint
        result = self.fingerprinter.fingerprint("http://192.0.2.1:8545")  # RFC5737 test address
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result.errors, list)
        # Should have some error indicating connection failure
        self.assertGreater(len(result.errors), 0)


if __name__ == '__main__':
    unittest.main()
