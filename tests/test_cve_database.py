#!/usr/bin/env python3
"""
Unit tests for CVE database functionality and vulnerability detection.
"""

import unittest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock
from cve_database import CVEDatabase, Vulnerability, check_software_vulnerabilities
from ethereum_rpc_fingerprinter import EthereumRPCFingerprinter, FingerprintResult


class TestVulnerabilityDataClass(unittest.TestCase):
    """Test the Vulnerability dataclass."""
    
    def test_vulnerability_creation(self):
        """Test creating a valid vulnerability."""
        vuln = Vulnerability(
            cve_id="CVE-2021-39137",
            title="Test vulnerability",
            description="Test description",
            severity="HIGH",
            cvss_score=7.5,
            affected_versions={"type": "range", "min": "1.0.0", "max": "1.10.0"},
            fixed_in="1.10.1",
            published_date="2021-01-01",
            references=["https://example.com"],
            impact="Test impact",
            recommendation="Update immediately"
        )
        
        self.assertEqual(vuln.cve_id, "CVE-2021-39137")
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.cvss_score, 7.5)
    
    def test_vulnerability_invalid_cvss(self):
        """Test that invalid CVSS scores raise ValueError."""
        with self.assertRaises(ValueError):
            Vulnerability(
                cve_id="CVE-2021-39137",
                title="Test",
                description="Test",
                severity="HIGH",
                cvss_score=11.0,  # Invalid - must be <= 10.0
                affected_versions={},
                fixed_in="1.0.0",
                published_date="2021-01-01",
                references=[],
                impact="Test",
                recommendation="Test"
            )
    
    def test_vulnerability_invalid_severity(self):
        """Test that invalid severity levels raise ValueError."""
        with self.assertRaises(ValueError):
            Vulnerability(
                cve_id="CVE-2021-39137",
                title="Test",
                description="Test",
                severity="INVALID",  # Invalid severity
                cvss_score=7.5,
                affected_versions={},
                fixed_in="1.0.0",
                published_date="2021-01-01",
                references=[],
                impact="Test",
                recommendation="Test"
            )


class TestCVEDatabase(unittest.TestCase):
    """Test CVE database functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a minimal test database
        self.test_db_data = {
            "metadata": {
                "database_version": "1.0.0",
                "last_updated": "2024-01-01"
            },
            "vulnerabilities": {
                "geth": [
                    {
                        "cve_id": "CVE-2021-39137",
                        "title": "Geth consensus flaw",
                        "description": "Test vulnerability",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "affected_versions": {
                            "type": "range",
                            "min": "1.10.0",
                            "max": "1.10.7"
                        },
                        "fixed_in": "1.10.8",
                        "published_date": "2021-08-24",
                        "references": ["https://example.com"],
                        "impact": "Could lead to chain splits",
                        "recommendation": "Update immediately"
                    }
                ],
                "parity": [
                    {
                        "cve_id": "CVE-2018-19486",
                        "title": "Parity DoS vulnerability",
                        "description": "Test DoS vulnerability",
                        "severity": "MEDIUM",
                        "cvss_score": 5.3,
                        "affected_versions": {
                            "type": "range",
                            "min": "2.0.0",
                            "max": "2.2.4"
                        },
                        "fixed_in": "2.2.5",
                        "published_date": "2018-11-26",
                        "references": ["https://example.com"],
                        "impact": "Denial of service",
                        "recommendation": "Update to 2.2.5"
                    }
                ]
            },
            "severity_mapping": {
                "CRITICAL": {"color": "red", "priority": "IMMEDIATE"},
                "HIGH": {"color": "orange", "priority": "HIGH"},
                "MEDIUM": {"color": "yellow", "priority": "MEDIUM"},
                "LOW": {"color": "green", "priority": "LOW"}
            }
        }
        
        # Create temporary database file
        self.temp_db_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(self.test_db_data, self.temp_db_file)
        self.temp_db_file.close()
        
        self.cve_db = CVEDatabase(self.temp_db_file.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.temp_db_file.name)
    
    def test_database_loading(self):
        """Test that database loads correctly."""
        self.assertEqual(len(self.cve_db.vulnerabilities), 2)
        self.assertIn('geth', self.cve_db.vulnerabilities)
        self.assertIn('parity', self.cve_db.vulnerabilities)
        self.assertEqual(len(self.cve_db.vulnerabilities['geth']), 1)
        self.assertEqual(len(self.cve_db.vulnerabilities['parity']), 1)
    
    def test_software_name_normalization(self):
        """Test software name normalization."""
        test_cases = [
            ("Geth", "geth"),
            ("GETH", "geth"),
            ("go-ethereum", "geth"),
            ("Parity-Ethereum", "parity"),
            ("OpenEthereum", "parity"),
            ("Besu", "besu"),
            ("Hyperledger_Besu", "besu"),
            ("Nethermind", "nethermind"),
            ("Unknown Client", "unknown client")
        ]
        
        for input_name, expected in test_cases:
            with self.subTest(input_name=input_name):
                result = self.cve_db._normalize_software_name(input_name)
                self.assertEqual(result, expected)
    
    def test_version_parsing(self):
        """Test version string parsing."""
        test_cases = [
            ("1.10.7", "1.10.7"),
            ("v1.10.7", "1.10.7"),
            ("1.10.7-stable", "1.10.7"),
            ("1.10.7-beta", "1.10.7"),
            ("1.10.7+build123", "1.10.7"),
            ("2.2.4-alpha.1", "2.2.4"),
            ("invalid-version", None)
        ]
        
        for input_version, expected in test_cases:
            with self.subTest(input_version=input_version):
                result = self.cve_db._parse_version(input_version)
                if expected is None:
                    self.assertIsNone(result)
                else:
                    self.assertEqual(str(result), expected)
    
    def test_version_range_checking(self):
        """Test version range vulnerability checking."""
        # Test vulnerable version
        vulnerable_versions = ["1.10.0", "1.10.3", "1.10.7"]
        for version in vulnerable_versions:
            with self.subTest(version=version):
                vulns = self.cve_db.check_vulnerabilities("Geth", version)
                self.assertEqual(len(vulns), 1)
                self.assertEqual(vulns[0].cve_id, "CVE-2021-39137")
        
        # Test safe versions
        safe_versions = ["1.9.9", "1.10.8", "1.11.0"]
        for version in safe_versions:
            with self.subTest(version=version):
                vulns = self.cve_db.check_vulnerabilities("Geth", version)
                self.assertEqual(len(vulns), 0)
    
    def test_unknown_software(self):
        """Test checking vulnerabilities for unknown software."""
        vulns = self.cve_db.check_vulnerabilities("UnknownClient", "1.0.0")
        self.assertEqual(len(vulns), 0)
    
    def test_vulnerability_sorting(self):
        """Test that vulnerabilities are sorted by severity."""
        # Add multiple vulnerabilities to test sorting
        self.test_db_data["vulnerabilities"]["testsoftware"] = [
            {
                "cve_id": "CVE-2021-LOW",
                "title": "Low severity test",
                "description": "Test",
                "severity": "LOW",
                "cvss_score": 2.0,
                "affected_versions": {"type": "range", "min": "1.0.0", "max": "1.0.1"},
                "fixed_in": "1.0.2",
                "published_date": "2021-01-01",
                "references": [],
                "impact": "Low impact",
                "recommendation": "Update when convenient"
            },
            {
                "cve_id": "CVE-2021-CRITICAL",
                "title": "Critical severity test",
                "description": "Test",
                "severity": "CRITICAL",
                "cvss_score": 9.5,
                "affected_versions": {"type": "range", "min": "1.0.0", "max": "1.0.1"},
                "fixed_in": "1.0.2",
                "published_date": "2021-01-01",
                "references": [],
                "impact": "Critical impact",
                "recommendation": "Update immediately"
            },
            {
                "cve_id": "CVE-2021-MEDIUM",
                "title": "Medium severity test",
                "description": "Test",
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "affected_versions": {"type": "range", "min": "1.0.0", "max": "1.0.1"},
                "fixed_in": "1.0.2",
                "published_date": "2021-01-01",
                "references": [],
                "impact": "Medium impact",
                "recommendation": "Update soon"
            }
        ]
        
        # Recreate database with new data
        with open(self.temp_db_file.name, 'w') as f:
            json.dump(self.test_db_data, f)
        
        cve_db = CVEDatabase(self.temp_db_file.name)
        vulns = cve_db.check_vulnerabilities("testsoftware", "1.0.1")
        
        # Check that vulnerabilities are sorted by severity (CRITICAL first)
        self.assertEqual(len(vulns), 3)
        self.assertEqual(vulns[0].severity, "CRITICAL")
        self.assertEqual(vulns[1].severity, "MEDIUM")
        self.assertEqual(vulns[2].severity, "LOW")
    
    def test_database_info(self):
        """Test getting database information."""
        info = self.cve_db.get_database_info()
        
        self.assertIn("metadata", info)
        self.assertIn("total_vulnerabilities", info)
        self.assertIn("supported_software", info)
        self.assertEqual(info["total_vulnerabilities"], 2)
        self.assertIn("geth", info["supported_software"])
        self.assertIn("parity", info["supported_software"])
    
    def test_severity_info(self):
        """Test getting severity information."""
        critical_info = self.cve_db.get_severity_info("CRITICAL")
        self.assertEqual(critical_info["color"], "red")
        self.assertEqual(critical_info["priority"], "IMMEDIATE")
        
        unknown_info = self.cve_db.get_severity_info("UNKNOWN")
        self.assertEqual(unknown_info["priority"], "UNKNOWN")
    
    def test_search_vulnerabilities(self):
        """Test vulnerability search functionality."""
        # Search by CVE ID
        results = self.cve_db.search_vulnerabilities("CVE-2021-39137")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], "geth")
        self.assertEqual(results[0][1].cve_id, "CVE-2021-39137")
        
        # Search by title
        results = self.cve_db.search_vulnerabilities("consensus")
        self.assertEqual(len(results), 1)
        
        # Search for non-existent term
        results = self.cve_db.search_vulnerabilities("nonexistent")
        self.assertEqual(len(results), 0)


class TestCVEIntegration(unittest.TestCase):
    """Test CVE integration with fingerprinter."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.fingerprinter = EthereumRPCFingerprinter()
    
    def test_risk_level_calculation(self):
        """Test security risk level calculation."""
        # Test CRITICAL risk
        critical_vuln = Vulnerability(
            cve_id="CVE-TEST-CRITICAL",
            title="Critical test",
            description="Test",
            severity="CRITICAL",
            cvss_score=9.8,
            affected_versions={},
            fixed_in="1.0.0",
            published_date="2021-01-01",
            references=[],
            impact="Critical",
            recommendation="Update"
        )
        
        risk_level = self.fingerprinter._calculate_risk_level([critical_vuln])
        self.assertEqual(risk_level, "CRITICAL")
        
        # Test no vulnerabilities
        risk_level = self.fingerprinter._calculate_risk_level([])
        self.assertEqual(risk_level, "NONE")
        
        # Test mixed severities (should return highest)
        medium_vuln = Vulnerability(
            cve_id="CVE-TEST-MEDIUM",
            title="Medium test",
            description="Test",
            severity="MEDIUM",
            cvss_score=5.0,
            affected_versions={},
            fixed_in="1.0.0",
            published_date="2021-01-01",
            references=[],
            impact="Medium",
            recommendation="Update"
        )
        
        risk_level = self.fingerprinter._calculate_risk_level([medium_vuln, critical_vuln])
        self.assertEqual(risk_level, "CRITICAL")
    
    def test_fingerprinter_cve_integration(self):
        """Test that fingerprinter integrates with CVE database."""
        # Create a result that needs vulnerability checking
        result = FingerprintResult(
            endpoint="http://test.com",
            node_implementation="Geth",
            node_version="1.10.7"
        )
        
        # Test vulnerability checking with real CVE database
        updated_result = self.fingerprinter._check_vulnerabilities(result)
        
        # Verify result was updated
        self.assertIsNotNone(updated_result.vulnerabilities)
        self.assertIsNotNone(updated_result.security_risk_level)
        
        # If CVE database loaded successfully, we should have vulnerabilities for Geth 1.10.7
        if self.fingerprinter.cve_database is not None:
            # Geth 1.10.7 is known to have vulnerabilities in our test database
            self.assertGreater(len(updated_result.vulnerabilities), 0)
            self.assertNotEqual(updated_result.security_risk_level, "NONE")
    
    def test_fingerprint_result_with_vulnerabilities(self):
        """Test FingerprintResult with vulnerability data."""
        vuln = Vulnerability(
            cve_id="CVE-2021-39137",
            title="Test vulnerability",
            description="Test description",
            severity="HIGH",
            cvss_score=7.5,
            affected_versions={},
            fixed_in="1.10.8",
            published_date="2021-01-01",
            references=[],
            impact="Test impact",
            recommendation="Update"
        )
        
        result = FingerprintResult(
            endpoint="http://test.com",
            vulnerabilities=[vuln],
            security_risk_level="HIGH"
        )
        
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].cve_id, "CVE-2021-39137")
        self.assertEqual(result.security_risk_level, "HIGH")


class TestConvenienceFunction(unittest.TestCase):
    """Test convenience function for CVE checking."""
    
    @patch('cve_database.CVEDatabase')
    def test_check_software_vulnerabilities_function(self, mock_cve_db_class):
        """Test the convenience function for checking vulnerabilities."""
        # Mock CVE database
        mock_cve_db = MagicMock()
        mock_vulns = [MagicMock()]
        mock_cve_db.check_vulnerabilities.return_value = mock_vulns
        mock_cve_db_class.return_value = mock_cve_db
        
        # Test convenience function
        result = check_software_vulnerabilities("Geth", "1.10.7")
        
        # Verify database was created and called
        mock_cve_db_class.assert_called_once_with(None)
        mock_cve_db.check_vulnerabilities.assert_called_once_with("Geth", "1.10.7")
        self.assertEqual(result, mock_vulns)


if __name__ == '__main__':
    unittest.main()