#!/usr/bin/env python3
"""
CVE Database Manager for Ethereum RPC implementations.

This module provides functionality to load, parse, and query CVE vulnerabilities
for various Ethereum client implementations based on their versions.
"""

import json
import os
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from packaging import version
from packaging.version import Version


@dataclass
class Vulnerability:
    """Represents a single CVE vulnerability."""
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    affected_versions: Dict[str, Any]
    fixed_in: str
    published_date: str
    references: List[str]
    impact: str
    recommendation: str
    
    def __post_init__(self):
        """Validate vulnerability data after initialization."""
        if self.cvss_score < 0.0 or self.cvss_score > 10.0:
            raise ValueError(f"CVSS score must be between 0.0 and 10.0, got {self.cvss_score}")
        
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if self.severity not in valid_severities:
            raise ValueError(f"Severity must be one of {valid_severities}, got {self.severity}")


class CVEDatabase:
    """
    Manages CVE database operations for Ethereum RPC implementations.
    
    This class loads vulnerability data from a JSON database and provides
    methods to query vulnerabilities based on software implementation and version.
    """
    
    def __init__(self, database_path: Optional[str] = None):
        """
        Initialize CVE database.
        
        Args:
            database_path: Path to the CVE JSON database file. If None, uses default.
        """
        if database_path is None:
            # Default to cve_database.json in the same directory as this module
            self.database_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'cve_database.json'
            )
        else:
            self.database_path = database_path
        
        self.vulnerabilities: Dict[str, List[Vulnerability]] = {}
        self.metadata: Dict[str, Any] = {}
        self.severity_mapping: Dict[str, Dict[str, Any]] = {}
        self._load_database()
    
    def _load_database(self) -> None:
        """Load and parse the CVE database from JSON file."""
        try:
            if not os.path.exists(self.database_path):
                raise FileNotFoundError(f"CVE database file not found: {self.database_path}")
            
            with open(self.database_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Load metadata
            self.metadata = data.get('metadata', {})
            self.severity_mapping = data.get('severity_mapping', {})
            
            # Parse vulnerabilities
            vulnerabilities_data = data.get('vulnerabilities', {})
            for software, vulns in vulnerabilities_data.items():
                self.vulnerabilities[software.lower()] = []
                for vuln_data in vulns:
                    try:
                        vulnerability = Vulnerability(
                            cve_id=vuln_data['cve_id'],
                            title=vuln_data['title'],
                            description=vuln_data['description'],
                            severity=vuln_data['severity'],
                            cvss_score=float(vuln_data['cvss_score']),
                            affected_versions=vuln_data['affected_versions'],
                            fixed_in=vuln_data['fixed_in'],
                            published_date=vuln_data['published_date'],
                            references=vuln_data['references'],
                            impact=vuln_data['impact'],
                            recommendation=vuln_data['recommendation']
                        )
                        self.vulnerabilities[software.lower()].append(vulnerability)
                    except (KeyError, ValueError) as e:
                        print(f"Warning: Skipping malformed vulnerability in {software}: {e}")
                        continue
        
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"Error loading CVE database: {e}")
            # Initialize with empty data if database fails to load
            self.vulnerabilities = {}
            self.metadata = {}
            self.severity_mapping = {}
    
    def _normalize_software_name(self, software_name: str) -> str:
        """
        Normalize software name for consistent lookup.
        
        Args:
            software_name: Raw software name from client version
            
        Returns:
            Normalized software name for database lookup
        """
        software_lower = software_name.lower()
        
        # Handle common name variations
        name_mappings = {
            'go-ethereum': 'geth',
            'parity-ethereum': 'parity',
            'openethereum': 'parity',  # OpenEthereum is the successor to Parity
            'hyperledger_besu': 'besu',
            'hyperledger-besu': 'besu',
            'nethermind': 'nethermind',
            'erigon': 'erigon',
            'reth': 'reth'
        }
        
        return name_mappings.get(software_lower, software_lower)
    
    def _parse_version(self, version_string: str) -> Optional[Version]:
        """
        Parse version string into a comparable version object.
        
        Args:
            version_string: Raw version string (e.g., "v1.10.9", "1.10.9-beta")
            
        Returns:
            Parsed version object or None if parsing fails
        """
        try:
            # Remove common prefixes and suffixes
            clean_version = version_string.strip()
            clean_version = re.sub(r'^[vV]', '', clean_version)  # Remove 'v' or 'V' prefix
            clean_version = re.sub(r'-(stable|beta|alpha|rc\d*|unstable).*$', '', clean_version)
            clean_version = re.sub(r'\+.*$', '', clean_version)  # Remove build metadata
            
            # Handle common version formats
            if re.match(r'^\d+\.\d+\.\d+', clean_version):
                return version.parse(clean_version)
            else:
                # Try to extract version pattern
                version_match = re.search(r'(\d+\.\d+\.\d+)', clean_version)
                if version_match:
                    return version.parse(version_match.group(1))
        except Exception:
            pass
        
        return None
    
    def _is_version_affected(self, software_version: str, affected_versions: Dict[str, Any]) -> bool:
        """
        Check if a given version is affected by a vulnerability.
        
        Args:
            software_version: Version string to check
            affected_versions: Vulnerability's affected version specification
            
        Returns:
            True if version is affected, False otherwise
        """
        parsed_version = self._parse_version(software_version)
        if not parsed_version:
            return False
        
        version_type = affected_versions.get('type', 'range')
        
        if version_type == 'range':
            min_version = affected_versions.get('min')
            max_version = affected_versions.get('max')
            excludes = affected_versions.get('exclude', [])
            
            # Check if version is in excluded list
            if software_version in excludes:
                return False
            
            # Check version range
            in_range = True
            if min_version:
                min_parsed = self._parse_version(min_version)
                if min_parsed and parsed_version < min_parsed:
                    in_range = False
            
            if max_version and in_range:
                max_parsed = self._parse_version(max_version)
                if max_parsed and parsed_version > max_parsed:
                    in_range = False
            
            return in_range
        
        elif version_type == 'exact':
            exact_versions = affected_versions.get('versions', [])
            return software_version in exact_versions
        
        return False
    
    def check_vulnerabilities(self, software_name: str, software_version: str) -> List[Vulnerability]:
        """
        Check for vulnerabilities affecting a specific software version.
        
        Args:
            software_name: Name of the software (e.g., "Geth", "Parity")
            software_version: Version string (e.g., "1.10.8")
            
        Returns:
            List of vulnerabilities affecting the given software version
        """
        normalized_name = self._normalize_software_name(software_name)
        software_vulns = self.vulnerabilities.get(normalized_name, [])
        
        affected_vulns = []
        for vuln in software_vulns:
            if self._is_version_affected(software_version, vuln.affected_versions):
                affected_vulns.append(vuln)
        
        # Sort by severity (CRITICAL first, then HIGH, MEDIUM, LOW)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        affected_vulns.sort(key=lambda v: (severity_order.get(v.severity, 4), -v.cvss_score))
        
        return affected_vulns
    
    def get_severity_info(self, severity: str) -> Dict[str, Any]:
        """
        Get severity mapping information.
        
        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            
        Returns:
            Dictionary with severity information (color, priority, description)
        """
        return self.severity_mapping.get(severity, {
            "color": "white",
            "score_range": [0.0, 10.0],
            "priority": "UNKNOWN",
            "description": "Unknown severity level"
        })
    
    def get_database_info(self) -> Dict[str, Any]:
        """
        Get database metadata information.
        
        Returns:
            Dictionary with database metadata
        """
        return {
            "metadata": self.metadata,
            "total_vulnerabilities": sum(len(vulns) for vulns in self.vulnerabilities.values()),
            "supported_software": list(self.vulnerabilities.keys()),
            "severity_levels": list(self.severity_mapping.keys())
        }
    
    def get_all_vulnerabilities_for_software(self, software_name: str) -> List[Vulnerability]:
        """
        Get all known vulnerabilities for a specific software.
        
        Args:
            software_name: Name of the software
            
        Returns:
            List of all vulnerabilities for the software
        """
        normalized_name = self._normalize_software_name(software_name)
        return self.vulnerabilities.get(normalized_name, [])
    
    def search_vulnerabilities(self, search_term: str) -> List[Tuple[str, Vulnerability]]:
        """
        Search vulnerabilities by CVE ID, title, or description.
        
        Args:
            search_term: Term to search for
            
        Returns:
            List of tuples (software_name, vulnerability) matching the search term
        """
        results = []
        search_lower = search_term.lower()
        
        for software_name, vulns in self.vulnerabilities.items():
            for vuln in vulns:
                if (search_lower in vuln.cve_id.lower() or
                    search_lower in vuln.title.lower() or
                    search_lower in vuln.description.lower()):
                    results.append((software_name, vuln))
        
        return results


# Convenience function for quick vulnerability checks
def check_software_vulnerabilities(software_name: str, software_version: str, 
                                 database_path: Optional[str] = None) -> List[Vulnerability]:
    """
    Quick function to check vulnerabilities for a software version.
    
    Args:
        software_name: Name of the software
        software_version: Version string
        database_path: Optional path to CVE database
        
    Returns:
        List of vulnerabilities affecting the software version
    """
    cve_db = CVEDatabase(database_path)
    return cve_db.check_vulnerabilities(software_name, software_version)


if __name__ == "__main__":
    # Example usage and testing
    print("🔍 CVE Database Manager - Testing")
    print("=" * 50)
    
    # Initialize database
    try:
        cve_db = CVEDatabase()
        db_info = cve_db.get_database_info()
        
        print(f"Database version: {db_info['metadata'].get('database_version', 'Unknown')}")
        print(f"Total vulnerabilities: {db_info['total_vulnerabilities']}")
        print(f"Supported software: {', '.join(db_info['supported_software'])}")
        print()
        
        # Test vulnerability checking
        test_cases = [
            ("Geth", "1.10.7"),    # Should find CVE-2021-39137 (CRITICAL)
            ("Geth", "1.10.9"),    # Should be safe from older CVEs
            ("Parity", "2.2.4"),   # Should find CVE-2018-19486
            ("Besu", "21.10.1"),   # Should find CVE-2021-43668
            ("UnknownClient", "1.0.0")  # Should find nothing
        ]
        
        for software, version_str in test_cases:
            print(f"Testing {software} v{version_str}:")
            vulns = cve_db.check_vulnerabilities(software, version_str)
            
            if vulns:
                print(f"  ⚠️  Found {len(vulns)} vulnerability(ies):")
                for vuln in vulns:
                    severity_info = cve_db.get_severity_info(vuln.severity)
                    print(f"    • {vuln.cve_id} - {vuln.severity} ({vuln.cvss_score})")
                    print(f"      {vuln.title}")
            else:
                print("  ✅ No known vulnerabilities found")
            print()
    
    except Exception as e:
        print(f"❌ Error testing CVE database: {e}")