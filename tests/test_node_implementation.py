#!/usr/bin/env python3
"""
Unit tests for node implementation detection functionality.
"""

import unittest
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter


class TestNodeImplementationDetection(unittest.TestCase):
    """Test node implementation detection from client version strings."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter()
    
    def test_geth_detection(self):
        """Test Geth implementation detection."""
        test_cases = [
            "Geth/v1.10.26-stable/linux-amd64/go1.18.5",
            "Geth/v1.13.5-stable/darwin-arm64/go1.21.4",
            "geth/v1.9.0-unstable/windows-amd64/go1.13.4",
            "GETH/v1.8.0/freebsd-amd64/go1.10.1",
            "TurboGeth/v2021.03.4-alpha/linux-amd64/go1.16.2",
            "turbogeth/v2020.12.1/darwin-amd64/go1.15.6"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Geth', f"Failed to detect Geth in: {version_str}")
    
    def test_parity_openethereum_detection(self):
        """Test Parity/OpenEthereum implementation detection."""
        test_cases = [
            "Parity-Ethereum/v2.7.2-stable/x86_64-linux-gnu/rustc1.41.0",
            "OpenEthereum/v3.3.5-stable/x86_64-unknown-linux-gnu/rustc1.56.1",
            "parity/v2.5.13/windows-msvc/rustc1.40.0",
            "OPENETHEREUM/v3.2.6/darwin-x86_64/rustc1.52.1"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Parity/OpenEthereum', f"Failed to detect Parity/OpenEthereum in: {version_str}")
    
    def test_besu_detection(self):
        """Test Besu implementation detection."""
        test_cases = [
            "Besu/v22.10.3/linux-x86_64/openjdk-java-11",
            "Besu/v23.4.0/darwin-aarch64/openjdk-java-17",
            "besu/v21.1.0/windows-x86_64/openjdk-java-8",
            "BESU/v24.1.0/linux-aarch64/openjdk-java-21"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Besu', f"Failed to detect Besu in: {version_str}")
    
    def test_nethermind_detection(self):
        """Test Nethermind implementation detection."""
        test_cases = [
            "Nethermind/v1.14.6+6c21356f/linux-x64/dotnet6.0.11",
            "Nethermind/v1.20.3+77d89dbe/windows-x64/dotnet8.0.0",
            "nethermind/v1.18.0+12345678/darwin-arm64/dotnet7.0.5",
            "NETHERMIND/v1.25.0/freebsd-x64/dotnet9.0.0"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Nethermind', f"Failed to detect Nethermind in: {version_str}")
    
    def test_erigon_detection(self):
        """Test Erigon implementation detection."""
        test_cases = [
            "erigon/2.48.1/linux-amd64/go1.19.2",
            "erigon/2.55.0/darwin-arm64/go1.21.4",
            "Erigon/v2.60.0/windows-amd64/go1.22.1",
            "ERIGON/3.0.0-alpha/linux-arm64/go1.23.0"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Erigon', f"Failed to detect Erigon in: {version_str}")
    
    def test_reth_detection(self):
        """Test Reth implementation detection."""
        test_cases = [
            "reth/0.1.0-alpha/linux-x86_64/rustc1.75.0",
            "Reth/v0.2.0-beta/darwin-aarch64/rustc1.76.0",
            "RETH/1.0.0/windows-x86_64/rustc1.77.0",
            "reth/0.5.0-dev/freebsd-amd64/rustc1.78.0"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Reth', f"Failed to detect Reth in: {version_str}")
    
    def test_ethereumjs_detection(self):
        """Test EthereumJS implementation detection."""
        test_cases = [
            "EthereumJS/0.6.0/linux-x64/node16.20.0",
            "ethereumjs/0.7.0-beta/darwin-arm64/node18.17.0",
            "ETHEREUMJS/1.0.0/windows-x64/node20.5.0",
            "EthereumJS-Client/0.8.0/linux-aarch64/node19.8.1"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'EthereumJS', f"Failed to detect EthereumJS in: {version_str}")
    
    def test_anvil_detection(self):
        """Test Anvil implementation detection."""
        test_cases = [
            "anvil 0.1.0 (fdd321b 2023-10-04T00:21:13.119600000Z)",
            "anvil 0.2.0 (a1b2c3d 2024-01-15T10:30:45.123456789Z)",
            "Anvil/v1.0.0/linux-x86_64/rustc1.75.0",
            "ANVIL 2.0.0-alpha (12345ab 2024-05-20T15:30:00.000000000Z)"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Anvil', f"Failed to detect Anvil in: {version_str}")
    
    def test_hardhat_detection(self):
        """Test Hardhat implementation detection."""
        test_cases = [
            "HardhatNetwork/2.17.1/@ethereumjs/vm/5.9.3/node/v18.17.0",
            "hardhat/2.19.0/node/v20.5.0",
            "Hardhat/v2.20.0/ethereum-js/node16.20.0",
            "HARDHAT-NETWORK/3.0.0/@ethereumjs/vm/6.0.0/node/v21.0.0"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Hardhat', f"Failed to detect Hardhat in: {version_str}")
    
    def test_ganache_detection(self):
        """Test Ganache implementation detection."""
        test_cases = [
            "Ganache/v7.9.1/linux/node/v16.20.1",
            "TestRPC/v2.13.2/ethereum-js",
            "ganache/v8.0.0/darwin/node/v18.17.0",
            "GANACHE-CLI/v6.12.2/windows/node/v14.21.3"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Ganache', f"Failed to detect Ganache in: {version_str}")
    
    def test_unknown_implementation(self):
        """Test unknown implementation detection."""
        test_cases = [
            "CustomClient/v1.0.0",
            "SomeNode/beta-0.5.2/freebsd-amd64/rust1.60.0",
            "UnknownEthereumClient/v2.0.0/linux-x64/java11",
            "MyCustomNode/experimental/darwin-arm64/python3.9"
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, 'Unknown', f"Should detect as Unknown: {version_str}")
    
    def test_empty_and_none_input(self):
        """Test edge cases with empty and None input."""
        test_cases = [
            "",  # Empty string
            None,  # None value
            "   ",  # Whitespace only
        ]
        
        for version_str in test_cases:
            with self.subTest(version_str=repr(version_str)):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertIsNone(result, f"Should return None for: {repr(version_str)}")
    
    def test_case_insensitive_detection(self):
        """Test that detection is case-insensitive."""
        base_versions = [
            ("geth", "Geth"),
            ("GETH", "Geth"),
            ("Geth", "Geth"),
            ("besu", "Besu"),
            ("BESU", "Besu"),
            ("Besu", "Besu"),
            ("reth", "Reth"),
            ("RETH", "Reth"),
            ("Reth", "Reth"),
        ]
        
        for version_input, expected_output in base_versions:
            version_str = f"{version_input}/v1.0.0/linux-amd64"
            with self.subTest(version_str=version_str):
                result = self.fingerprinter._extract_node_implementation(version_str)
                self.assertEqual(result, expected_output, 
                               f"Case-insensitive detection failed for: {version_str}")


if __name__ == '__main__':
    unittest.main()
