#!/usr/bin/env python3
"""
Unit tests for client version parsing functionality.
"""

import unittest
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter


class TestClientVersionParsing(unittest.TestCase):
    """Test client version parsing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter()
    
    def test_version_parsing_structure(self):
        """Test that version parsing returns expected structure."""
        test_cases = [
            "Geth/v1.10.26-stable/linux-amd64/go1.18.5",
            "Parity-Ethereum/v2.7.2-stable/x86_64-linux-gnu/rustc1.41.0",
            "Besu/v22.10.3/linux-x86_64/openjdk-java-11",
            "Nethermind/v1.14.6+6c21356f/linux-x64/dotnet6.0.11",
            "erigon/2.48.1/linux-amd64/go1.19.2",
            "anvil 0.1.0 (fdd321b 2023-10-04T00:21:13.119600000Z)",
            "HardhatNetwork/2.17.1/@ethereumjs/vm/5.9.3/node/v18.17.0"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._parse_client_version(version_str)
                
                # Check that result is a dictionary
                self.assertIsInstance(result, dict)
                
                # Check that expected keys exist
                expected_keys = ['node_version', 'programming_language', 'language_version', 
                               'operating_system', 'architecture', 'build_info']
                for key in expected_keys:
                    self.assertIn(key, result)
                
                # Check that node_version is extracted for known clients
                if any(client in version_str.lower() for client in 
                      ['geth', 'parity', 'besu', 'nethermind', 'erigon', 'anvil', 'hardhat']):
                    self.assertIsNotNone(result['node_version'], 
                                       f"node_version should be extracted from {version_str}")
                
                # Check that programming_language is detected for known clients
                if any(client in version_str.lower() for client in 
                      ['geth', 'parity', 'besu', 'nethermind', 'erigon', 'anvil', 'hardhat']):
                    self.assertIsNotNone(result['programming_language'], 
                                       f"programming_language should be detected for {version_str}")
    
    def test_geth_parsing_specifics(self):
        """Test specific Geth parsing behavior."""
        version_str = "Geth/v1.10.26-stable/linux-amd64/go1.18.5"
        result = self.fingerprinter._parse_client_version(version_str)
        
        # Geth removes 'v' prefix from version
        self.assertEqual(result['node_version'], "1.10.26-stable")
        self.assertEqual(result['programming_language'], "Go")
        # Go version parsing removes 'go' prefix
        self.assertEqual(result['language_version'], "1.18.5")
        self.assertEqual(result['operating_system'], "Linux")
        self.assertEqual(result['architecture'], "amd64")
    
    def test_besu_parsing_specifics(self):
        """Test specific Besu parsing behavior."""
        version_str = "Besu/v22.10.3/linux-x86_64/openjdk-java-11"
        result = self.fingerprinter._parse_client_version(version_str)
        
        self.assertEqual(result['node_version'], "22.10.3")
        self.assertEqual(result['programming_language'], "Java")
        # Java version extracts just the version number
        self.assertEqual(result['language_version'], "11")
        self.assertEqual(result['operating_system'], "Linux")
        self.assertEqual(result['architecture'], "x86_64")
    
    def test_nethermind_parsing_specifics(self):
        """Test specific Nethermind parsing behavior."""
        version_str = "Nethermind/v1.14.6+6c21356f/linux-x64/dotnet6.0.11"
        result = self.fingerprinter._parse_client_version(version_str)
        
        # Nethermind version parsing removes commit hash
        self.assertEqual(result['node_version'], "1.14.6")
        self.assertEqual(result['programming_language'], ".NET")
        # .NET version extracts version number
        self.assertEqual(result['language_version'], "6.0.11")
        self.assertEqual(result['operating_system'], "Linux")
        self.assertEqual(result['architecture'], "x64")
    
    def test_anvil_parsing_specifics(self):
        """Test specific Anvil parsing behavior."""
        version_str = "anvil 0.1.0 (fdd321b 2023-10-04T00:21:13.119600000Z)"
        result = self.fingerprinter._parse_client_version(version_str)
        
        self.assertEqual(result['node_version'], "0.1.0")
        self.assertEqual(result['programming_language'], "Rust")
        # Anvil stores commit info in build_info
        self.assertIsInstance(result['build_info'], dict)
        # Check that some build info is captured
        self.assertGreater(len(result['build_info']), 0)
    
    def test_empty_and_invalid_input(self):
        """Test parsing with empty and invalid input."""
        test_cases = [
            "",  # Empty string
            None,  # None value
            "   ",  # Whitespace only
            "InvalidFormat",  # No recognizable pattern
        ]
        
        for input_str in test_cases:
            with self.subTest(input=repr(input_str)):
                result = self.fingerprinter._parse_client_version(input_str)
                
                if not input_str:
                    # Empty or None should return empty dict or dict with None values
                    self.assertIsInstance(result, dict)
                else:
                    # Invalid format should still return a dict structure
                    self.assertIsInstance(result, dict)
                    # But most fields should be None for unrecognized formats
                    if input_str and input_str.strip() and "Invalid" in input_str:
                        self.assertIsNone(result.get('programming_language'))
    
    def test_case_insensitive_parsing(self):
        """Test that parsing works regardless of case."""
        test_cases = [
            ("GETH/V1.10.0/LINUX-AMD64/GO1.18.5", "Go"),
            ("besu/v22.10.3/linux-x86_64/openjdk-java-11", "Java"),
            ("NETHERMIND/v1.14.6/linux-x64/dotnet6.0.11", ".NET"),
        ]
        
        for version_str, expected_lang in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._parse_client_version(version_str)
                self.assertEqual(result['programming_language'], expected_lang)
    
    def test_parsing_preserves_structure(self):
        """Test that parsing always returns expected dict structure."""
        result = self.fingerprinter._parse_client_version("Unknown/1.0.0")
        
        expected_keys = ['node_version', 'programming_language', 'language_version', 
                        'operating_system', 'architecture', 'build_info']
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        # build_info should be a dict
        self.assertIsInstance(result['build_info'], dict)


if __name__ == '__main__':
    unittest.main()
