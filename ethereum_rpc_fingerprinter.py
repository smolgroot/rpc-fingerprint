#!/usr/bin/env python3
"""
Ethereum RPC Host Fingerprinting Tool

This module provides comprehensive fingerprinting capabilities for Ethereum RPC endpoints,
helping identify node implementations, versions, networks, and other characteristics.
"""

import json
import time
import asyncio
import aiohttp
import requests
import click
import sys
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from tqdm.asyncio import tqdm as atqdm
from tqdm import tqdm
from web3 import Web3
from web3.exceptions import Web3Exception
from colorama import Fore, Style, init
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich import box
from cve_database import CVEDatabase, Vulnerability

# Initialize colorama for cross-platform colored output
init()

# Initialize Rich console
console = Console()

@dataclass
class FingerprintResult:
    """Data class to store fingerprinting results"""
    endpoint: str
    client_version: Optional[str] = None
    node_implementation: Optional[str] = None
    node_version: Optional[str] = None
    programming_language: Optional[str] = None
    language_version: Optional[str] = None
    operating_system: Optional[str] = None
    architecture: Optional[str] = None
    build_info: Optional[Dict[str, str]] = None
    network_id: Optional[int] = None
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    gas_price: Optional[int] = None
    peer_count: Optional[int] = None
    syncing: Optional[bool] = None
    mining: Optional[bool] = None
    hashrate: Optional[int] = None
    accounts: Optional[List[str]] = None
    protocol_version: Optional[str] = None
    supported_methods: Optional[List[str]] = None
    response_time: Optional[float] = None
    errors: Optional[List[str]] = None
    additional_info: Optional[Dict[str, Any]] = None
    vulnerabilities: Optional[List[Vulnerability]] = None
    security_risk_level: Optional[str] = None

class EthereumRPCFingerprinter:
    """
    Comprehensive Ethereum RPC fingerprinting tool
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
        
        # Initialize CVE database
        try:
            self.cve_database = CVEDatabase()
        except Exception as e:
            print(f"Warning: Could not load CVE database: {e}")
            self.cve_database = None
        
    def fingerprint(self, endpoint: str) -> FingerprintResult:
        """
        Perform comprehensive fingerprinting of an Ethereum RPC endpoint
        """
        result = FingerprintResult(endpoint=endpoint, errors=[])
        start_time = time.time()
        
        try:
            # Try to connect with Web3
            w3 = Web3(Web3.HTTPProvider(endpoint, request_kwargs={'timeout': self.timeout}))
            
            # Test basic connectivity
            if not w3.is_connected():
                result.errors.append("Unable to connect to endpoint")
                return result
                
            result.response_time = time.time() - start_time
            
            # Basic network information
            try:
                result.client_version = w3.client_version
                result.node_implementation = self._extract_node_implementation(result.client_version)
                
                # Parse detailed client information
                client_details = self._parse_client_version(result.client_version)
                result.node_version = client_details.get('node_version')
                result.programming_language = client_details.get('programming_language')
                result.language_version = client_details.get('language_version')
                result.operating_system = client_details.get('operating_system')
                result.architecture = client_details.get('architecture')
                result.build_info = client_details.get('build_info')
                
            except Exception as e:
                result.errors.append(f"Failed to get client version: {e}")
            
            try:
                result.network_id = w3.net.version
            except Exception as e:
                result.errors.append(f"Failed to get network ID: {e}")
                
            try:
                result.chain_id = w3.eth.chain_id
            except Exception as e:
                result.errors.append(f"Failed to get chain ID: {e}")
            
            try:
                result.block_number = w3.eth.block_number
            except Exception as e:
                result.errors.append(f"Failed to get block number: {e}")
            
            try:
                result.gas_price = w3.eth.gas_price
            except Exception as e:
                result.errors.append(f"Failed to get gas price: {e}")
            
            # Network status
            try:
                result.peer_count = w3.net.peer_count
            except Exception as e:
                result.errors.append(f"Failed to get peer count: {e}")
            
            try:
                syncing_status = w3.eth.syncing
                result.syncing = bool(syncing_status)
            except Exception as e:
                result.errors.append(f"Failed to get syncing status: {e}")
            
            try:
                result.mining = w3.eth.mining
            except Exception as e:
                result.errors.append(f"Failed to get mining status: {e}")
            
            try:
                result.hashrate = w3.eth.hashrate
            except Exception as e:
                result.errors.append(f"Failed to get hashrate: {e}")
            
            try:
                result.accounts = w3.eth.accounts
            except Exception as e:
                result.errors.append(f"Failed to get accounts: {e}")
            
            try:
                result.protocol_version = w3.eth.protocol_version
            except Exception as e:
                result.errors.append(f"Failed to get protocol version: {e}")
            
            # Method discovery
            result.supported_methods = self._discover_methods(endpoint)
            
            # Additional fingerprinting techniques
            result.additional_info = self._advanced_fingerprinting(w3, endpoint)
            
            # Check for CVE vulnerabilities
            result = self._check_vulnerabilities(result)
            
        except Exception as e:
            result.errors.append(f"General connection error: {e}")
            
        return result
    
    def _extract_node_implementation(self, client_version: str) -> Optional[str]:
        """Extract node implementation from client version string"""
        if not client_version or not client_version.strip():
            return None
            
        client_lower = client_version.lower()
        
        if 'geth' in client_lower or 'turbogeth' in client_lower:
            return 'Geth'
        elif 'parity' in client_lower or 'openethereum' in client_lower:
            return 'Parity/OpenEthereum'
        elif 'besu' in client_lower:
            return 'Besu'
        elif 'nethermind' in client_lower:
            return 'Nethermind'
        elif 'erigon' in client_lower:
            return 'Erigon'
        elif 'reth' in client_lower:
            return 'Reth'
        elif 'hardhat' in client_lower:
            return 'Hardhat'
        elif 'ethereumjs' in client_lower:
            return 'EthereumJS'
        elif 'anvil' in client_lower:
            return 'Anvil'
        elif 'ganache' in client_lower or 'testrpc' in client_lower:
            return 'Ganache'
        else:
            return 'Unknown'
    
    def _parse_client_version(self, client_version: str) -> Dict[str, Optional[str]]:
        """
        Parse client version string to extract detailed information
        
        Examples of client version strings:
        - Geth/v1.10.26-stable/linux-amd64/go1.18.5
        - Parity-Ethereum/v2.7.2-stable/x86_64-linux-gnu/rustc1.41.0
        - Besu/v22.10.3/linux-x86_64/openjdk-java-11
        - Nethermind/v1.14.6+6c21356f/linux-x64/dotnet6.0.11
        - erigon/2.48.1/linux-amd64/go1.19.2
        - anvil 0.1.0 (fdd321b 2023-10-04T00:21:13.119600000Z)
        """
        if not client_version:
            return {}
        
        result = {
            'node_version': None,
            'programming_language': None,
            'language_version': None,
            'operating_system': None,
            'architecture': None,
            'build_info': {}
        }
        
        # Normalize the client version string
        version_str = client_version.strip()
        
        try:
            # Geth format: Geth/v1.10.26-stable/linux-amd64/go1.18.5
            if version_str.lower().startswith('geth/') or 'turbogeth' in version_str.lower():
                parts = version_str.split('/')
                if len(parts) >= 4:
                    result['node_version'] = parts[1].replace('v', '')
                    result['programming_language'] = 'Go'
                    
                    # Parse OS and architecture
                    os_arch = parts[2]
                    if '-' in os_arch:
                        os_part, arch_part = os_arch.split('-', 1)
                        result['operating_system'] = os_part.title()
                        result['architecture'] = arch_part
                    
                    # Parse Go version
                    go_version = parts[3]
                    if go_version.startswith('go'):
                        result['language_version'] = go_version[2:]
                        
            # Parity format: Parity-Ethereum/v2.7.2-stable/x86_64-linux-gnu/rustc1.41.0
            elif 'parity' in version_str.lower() or 'openethereum' in version_str.lower():
                parts = version_str.split('/')
                if len(parts) >= 4:
                    result['node_version'] = parts[1].replace('v', '')
                    result['programming_language'] = 'Rust'
                    
                    # Parse architecture and OS
                    arch_os = parts[2]
                    if 'linux' in arch_os:
                        result['operating_system'] = 'Linux'
                        if arch_os.startswith('x86_64'):
                            result['architecture'] = 'x86_64'
                        elif arch_os.startswith('aarch64'):
                            result['architecture'] = 'aarch64'
                    elif 'darwin' in arch_os or 'macos' in arch_os:
                        result['operating_system'] = 'macOS'
                    elif 'windows' in arch_os:
                        result['operating_system'] = 'Windows'
                    
                    # Parse Rust version
                    rust_version = parts[3]
                    if rust_version.startswith('rustc'):
                        result['language_version'] = rust_version[5:]
                        
            # Besu format: Besu/v22.10.3/linux-x86_64/openjdk-java-11
            elif 'besu' in version_str.lower():
                parts = version_str.split('/')
                if len(parts) >= 4:
                    result['node_version'] = parts[1].replace('v', '')
                    result['programming_language'] = 'Java'
                    
                    # Parse OS and architecture
                    os_arch = parts[2]
                    if '-' in os_arch:
                        os_part, arch_part = os_arch.split('-', 1)
                        result['operating_system'] = os_part.title()
                        result['architecture'] = arch_part
                    
                    # Parse Java version
                    java_info = parts[3]
                    if 'java' in java_info:
                        # Extract version number
                        import re
                        java_match = re.search(r'java-?(\d+(?:\.\d+)*)', java_info)
                        if java_match:
                            result['language_version'] = java_match.group(1)
                            
            # Nethermind format: Nethermind/v1.14.6+6c21356f/linux-x64/dotnet6.0.11
            elif 'nethermind' in version_str.lower():
                parts = version_str.split('/')
                if len(parts) >= 4:
                    result['node_version'] = parts[1].replace('v', '').split('+')[0]  # Remove commit hash
                    result['programming_language'] = '.NET'
                    
                    # Parse OS and architecture
                    os_arch = parts[2]
                    if '-' in os_arch:
                        os_part, arch_part = os_arch.split('-', 1)
                        result['operating_system'] = os_part.title()
                        result['architecture'] = arch_part
                    
                    # Parse .NET version
                    dotnet_version = parts[3]
                    if dotnet_version.startswith('dotnet'):
                        result['language_version'] = dotnet_version[6:]
                        
            # Erigon format: erigon/2.48.1/linux-amd64/go1.19.2
            elif 'erigon' in version_str.lower():
                parts = version_str.split('/')
                if len(parts) >= 4:
                    result['node_version'] = parts[1]
                    result['programming_language'] = 'Go'
                    
                    # Parse OS and architecture
                    os_arch = parts[2]
                    if '-' in os_arch:
                        os_part, arch_part = os_arch.split('-', 1)
                        result['operating_system'] = os_part.title()
                        result['architecture'] = arch_part
                    
                    # Parse Go version
                    go_version = parts[3]
                    if go_version.startswith('go'):
                        result['language_version'] = go_version[2:]
                        
            # Anvil format: anvil 0.1.0 (fdd321b 2023-10-04T00:21:13.119600000Z)
            elif 'anvil' in version_str.lower():
                import re
                # Extract version
                version_match = re.search(r'anvil\s+(\d+\.\d+\.\d+)', version_str, re.IGNORECASE)
                if version_match:
                    result['node_version'] = version_match.group(1)
                
                result['programming_language'] = 'Rust'
                
                # Extract build info
                build_match = re.search(r'\(([^)]+)\)', version_str)
                if build_match:
                    build_info = build_match.group(1)
                    result['build_info']['commit_timestamp'] = build_info
                    
            # Hardhat Network format: varies significantly
            elif 'hardhat' in version_str.lower():
                result['programming_language'] = 'JavaScript/TypeScript'
                result['operating_system'] = 'Node.js'
                
            # Ganache format: varies
            elif 'ganache' in version_str.lower():
                result['programming_language'] = 'JavaScript'
                result['operating_system'] = 'Node.js'
                
            # Try to extract generic patterns if specific parsing failed
            if not result['node_version']:
                import re
                # Look for version patterns like v1.2.3 or 1.2.3
                version_match = re.search(r'v?(\d+\.\d+\.\d+(?:[-+][^\s/]+)?)', version_str)
                if version_match:
                    result['node_version'] = version_match.group(1)
            
            # Detect OS from common patterns if not already detected
            if not result['operating_system']:
                version_lower = version_str.lower()
                if 'linux' in version_lower:
                    result['operating_system'] = 'Linux'
                elif 'darwin' in version_lower or 'macos' in version_lower:
                    result['operating_system'] = 'macOS'
                elif 'windows' in version_lower or 'win32' in version_lower or 'win64' in version_lower:
                    result['operating_system'] = 'Windows'
                elif 'freebsd' in version_lower:
                    result['operating_system'] = 'FreeBSD'
                elif 'openbsd' in version_lower:
                    result['operating_system'] = 'OpenBSD'
            
            # Detect architecture from common patterns if not already detected
            if not result['architecture']:
                version_lower = version_str.lower()
                if 'amd64' in version_lower or 'x86_64' in version_lower or 'x64' in version_lower:
                    result['architecture'] = 'x86_64'
                elif 'arm64' in version_lower or 'aarch64' in version_lower:
                    result['architecture'] = 'ARM64'
                elif 'arm' in version_lower:
                    result['architecture'] = 'ARM'
                elif 'i386' in version_lower or 'x86' in version_lower:
                    result['architecture'] = 'x86'
            
        except Exception:
            # If parsing fails, return what we have
            pass
        
        return result
    
    def _discover_methods(self, endpoint: str) -> List[str]:
        """Discover supported RPC methods"""
        common_methods = [
            'web3_clientVersion',
            'web3_sha3',
            'net_version',
            'net_peerCount',
            'net_listening',
            'eth_protocolVersion',
            'eth_syncing',
            'eth_coinbase',
            'eth_mining',
            'eth_hashrate',
            'eth_gasPrice',
            'eth_accounts',
            'eth_blockNumber',
            'eth_getBalance',
            'eth_getStorageAt',
            'eth_getTransactionCount',
            'eth_getBlockTransactionCountByHash',
            'eth_getBlockTransactionCountByNumber',
            'eth_getUncleCountByBlockHash',
            'eth_getUncleCountByBlockNumber',
            'eth_getCode',
            'eth_sign',
            'eth_sendTransaction',
            'eth_sendRawTransaction',
            'eth_call',
            'eth_estimateGas',
            'eth_getBlockByHash',
            'eth_getBlockByNumber',
            'eth_getTransactionByHash',
            'eth_getTransactionByBlockHashAndIndex',
            'eth_getTransactionByBlockNumberAndIndex',
            'eth_getTransactionReceipt',
            'eth_getUncleByBlockHashAndIndex',
            'eth_getUncleByBlockNumberAndIndex',
            'eth_getCompilers',
            'eth_compileLLL',
            'eth_compileSolidity',
            'eth_compileSerpent',
            'eth_newFilter',
            'eth_newBlockFilter',
            'eth_newPendingTransactionFilter',
            'eth_uninstallFilter',
            'eth_getFilterChanges',
            'eth_getFilterLogs',
            'eth_getLogs',
            'eth_getWork',
            'eth_submitWork',
            'eth_submitHashrate',
            'db_putString',
            'db_getString',
            'db_putHex',
            'db_getHex',
            'shh_post',
            'shh_version',
            'shh_newIdentity',
            'shh_hasIdentity',
            'shh_newGroup',
            'shh_addToGroup',
            'shh_newFilter',
            'shh_uninstallFilter',
            'shh_getFilterChanges',
            'shh_getMessages'
        ]
        
        supported = []
        
        for method in common_methods:
            try:
                # Test method with minimal valid parameters
                payload = {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": [],
                    "id": 1
                }
                
                response = self.session.post(endpoint, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    # Method is supported if it doesn't return "method not found" error
                    if 'error' not in data or data['error']['code'] != -32601:
                        supported.append(method)
                        
            except Exception:
                continue
                
        return supported
    
    def _advanced_fingerprinting(self, w3: Web3, endpoint: str) -> Dict[str, Any]:
        """Perform advanced fingerprinting techniques"""
        info = {}
        
        try:
            # Test admin namespace (common in Geth)
            admin_payload = {
                "jsonrpc": "2.0",
                "method": "admin_nodeInfo",
                "params": [],
                "id": 1
            }
            response = self.session.post(endpoint, json=admin_payload)
            if response.status_code == 200:
                data = response.json()
                if 'result' in data:
                    info['admin_namespace'] = True
                    info['node_info'] = data['result']
                    
        except Exception:
            info['admin_namespace'] = False
        
        try:
            # Test debug namespace
            debug_payload = {
                "jsonrpc": "2.0",
                "method": "debug_traceTransaction",
                "params": ["0x0", {}],
                "id": 1
            }
            response = self.session.post(endpoint, json=debug_payload)
            if response.status_code == 200:
                data = response.json()
                # Even if it fails, if method exists it will return a different error
                if 'error' not in data or data['error']['code'] != -32601:
                    info['debug_namespace'] = True
                    
        except Exception:
            info['debug_namespace'] = False
        
        try:
            # Test txpool namespace (Geth specific)
            txpool_payload = {
                "jsonrpc": "2.0",
                "method": "txpool_status",
                "params": [],
                "id": 1
            }
            response = self.session.post(endpoint, json=txpool_payload)
            if response.status_code == 200:
                data = response.json()
                if 'result' in data:
                    info['txpool_namespace'] = True
                    info['txpool_status'] = data['result']
                    
        except Exception:
            info['txpool_namespace'] = False
        
        try:
            # Check for specific block fields that vary by implementation
            latest_block = w3.eth.get_block('latest', full_transactions=False)
            info['block_fields'] = list(latest_block.keys())
            
        except Exception as e:
            info['block_analysis_error'] = str(e)
        
        return info
    
    def _check_vulnerabilities(self, result: FingerprintResult) -> FingerprintResult:
        """
        Check for known CVE vulnerabilities based on the detected node implementation and version.
        
        Args:
            result: FingerprintResult object to check for vulnerabilities
            
        Returns:
            Updated FingerprintResult with vulnerability information
        """
        if not self.cve_database:
            return result
            
        try:
            # Check if we have enough information to perform vulnerability assessment
            if not result.node_implementation or not result.node_version:
                return result
            
            # Query CVE database for vulnerabilities
            vulnerabilities = self.cve_database.check_vulnerabilities(
                result.node_implementation,
                result.node_version
            )
            
            result.vulnerabilities = vulnerabilities
            
            # Calculate overall security risk level
            result.security_risk_level = self._calculate_risk_level(vulnerabilities)
            
        except Exception as e:
            if result.errors is None:
                result.errors = []
            result.errors.append(f"CVE vulnerability check failed: {e}")
        
        return result
    
    def _calculate_risk_level(self, vulnerabilities: List[Vulnerability]) -> str:
        """
        Calculate overall security risk level based on found vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities found
            
        Returns:
            Risk level string (CRITICAL, HIGH, MEDIUM, LOW, NONE)
        """
        if not vulnerabilities:
            return "NONE"
        
        # Determine highest severity
        severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_severity = 0
        
        for vuln in vulnerabilities:
            severity_score = severity_scores.get(vuln.severity, 0)
            max_severity = max(max_severity, severity_score)
        
        # Return the highest severity found
        for severity, score in severity_scores.items():
            if score == max_severity:
                return severity
        
        return "LOW"

class AsyncEthereumRPCFingerprinter:
    """
    Asynchronous version for fingerprinting multiple endpoints
    """
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def fingerprint_multiple(self, endpoints: List[str], show_progress: bool = True) -> List[FingerprintResult]:
        """
        Fingerprint multiple endpoints concurrently with progress tracking
        
        Args:
            endpoints: List of endpoint URLs to fingerprint
            show_progress: Whether to show progress bar
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            if show_progress:
                # Use Rich progress bar for beautiful async progress tracking
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    TextColumn("[bold blue]{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    TextColumn("•"),
                    TimeRemainingColumn(),
                    console=console,
                    transient=False
                ) as progress:
                    
                    task = progress.add_task("🔍 Fingerprinting endpoints...", total=len(endpoints))
                    
                    tasks = [self._fingerprint_single(session, endpoint) for endpoint in endpoints]
                    results = []
                    
                    # Process tasks as they complete and update progress
                    for coro in asyncio.as_completed(tasks):
                        try:
                            result = await coro
                            results.append(result)
                        except Exception as e:
                            # Create error result for failed endpoint
                            error_result = FingerprintResult(
                                endpoint="unknown",  # We'll fix this in post-processing
                                errors=[f"Async fingerprint failed: {e}"]
                            )
                            results.append(error_result)
                        
                        progress.advance(task)
                    
                    # Sort results to match original endpoint order
                    endpoint_to_result = {r.endpoint: r for r in results if r.endpoint != "unknown"}
                    ordered_results = []
                    error_count = 0
                    
                    for endpoint in endpoints:
                        if endpoint in endpoint_to_result:
                            ordered_results.append(endpoint_to_result[endpoint])
                        else:
                            # Handle unknown errors by assigning them to missing endpoints
                            error_results = [r for r in results if r.endpoint == "unknown"]
                            if error_count < len(error_results):
                                error_result = error_results[error_count]
                                error_result.endpoint = endpoint
                                ordered_results.append(error_result)
                                error_count += 1
                            else:
                                # Fallback error result
                                ordered_results.append(FingerprintResult(
                                    endpoint=endpoint,
                                    errors=["Unknown error during fingerprinting"]
                                ))
                    
                    return ordered_results
            else:
                # Original behavior without progress tracking for quiet mode
                tasks = [self._fingerprint_single(session, endpoint) for endpoint in endpoints]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Handle exceptions
                final_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        error_result = FingerprintResult(
                            endpoint=endpoints[i],
                            errors=[f"Async fingerprint failed: {result}"]
                        )
                        final_results.append(error_result)
                    else:
                        final_results.append(result)
                        
                return final_results
    
    async def _fingerprint_single(self, session: aiohttp.ClientSession, endpoint: str) -> FingerprintResult:
        """
        Fingerprint a single endpoint asynchronously
        """
        async with self.semaphore:
            result = FingerprintResult(endpoint=endpoint, errors=[])
            start_time = time.time()
            
            try:
                # Basic connectivity test
                payload = {
                    "jsonrpc": "2.0",
                    "method": "web3_clientVersion",
                    "params": [],
                    "id": 1
                }
                
                async with session.post(endpoint, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'result' in data:
                            result.client_version = data['result']
                            result.node_implementation = self._extract_node_implementation(data['result'])
                            
                            # Parse detailed client information
                            client_details = self._parse_client_version(data['result'])
                            result.node_version = client_details.get('node_version')
                            result.programming_language = client_details.get('programming_language')
                            result.language_version = client_details.get('language_version')
                            result.operating_system = client_details.get('operating_system')
                            result.architecture = client_details.get('architecture')
                            result.build_info = client_details.get('build_info')
                            
                        result.response_time = time.time() - start_time
                    else:
                        result.errors.append(f"HTTP {response.status}")
                        return result
                
                # Continue with other methods...
                await self._async_gather_info(session, endpoint, result)
                
            except Exception as e:
                result.errors.append(f"Connection error: {e}")
                
            return result
    
    async def _async_gather_info(self, session: aiohttp.ClientSession, endpoint: str, result: FingerprintResult):
        """Gather additional information asynchronously"""
        methods_to_test = [
            ("net_version", "network_id"),
            ("eth_chainId", "chain_id"),
            ("eth_blockNumber", "block_number"),
            ("eth_gasPrice", "gas_price"),
            ("net_peerCount", "peer_count"),
            ("eth_syncing", "syncing"),
            ("eth_mining", "mining"),
            ("eth_hashrate", "hashrate"),
            ("eth_accounts", "accounts"),
            ("eth_protocolVersion", "protocol_version")
        ]
        
        for method, attr_name in methods_to_test:
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": [],
                    "id": 1
                }
                
                async with session.post(endpoint, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'result' in data:
                            value = data['result']
                            # Convert hex values to int where appropriate
                            if method in ['net_version', 'eth_chainId', 'eth_blockNumber', 'eth_gasPrice', 'net_peerCount', 'eth_hashrate']:
                                if isinstance(value, str) and value.startswith('0x'):
                                    value = int(value, 16)
                                elif isinstance(value, str) and value.isdigit():
                                    value = int(value)
                            setattr(result, attr_name, value)
                            
            except Exception as e:
                result.errors.append(f"Failed to get {method}: {e}")

    def _extract_node_implementation(self, client_version: str) -> Optional[str]:
        """Extract node implementation from client version string"""
        if not client_version or not client_version.strip():
            return None
            
        client_lower = client_version.lower()
        
        if 'geth' in client_lower or 'turbogeth' in client_lower:
            return 'Geth'
        elif 'parity' in client_lower or 'openethereum' in client_lower:
            return 'Parity/OpenEthereum'
        elif 'besu' in client_lower:
            return 'Besu'
        elif 'nethermind' in client_lower:
            return 'Nethermind'
        elif 'erigon' in client_lower:
            return 'Erigon'
        elif 'reth' in client_lower:
            return 'Reth'
        elif 'hardhat' in client_lower:
            return 'Hardhat'
        elif 'ethereumjs' in client_lower:
            return 'EthereumJS'
        elif 'anvil' in client_lower:
            return 'Anvil'
        elif 'ganache' in client_lower or 'testrpc' in client_lower:
            return 'Ganache'
        else:
            return 'Unknown'
    
    def _parse_client_version(self, client_version: str) -> Dict[str, Optional[str]]:
        """
        Parse client version string to extract detailed information
        """
        
        result = {
            'node_version': None,
            'programming_language': None,
            'language_version': None,
            'operating_system': None,
            'architecture': None,
            'build_info': {}
        }
        
        if not client_version:
            return result
        
        # Normalize the version string
        version_str = client_version.strip()
        
        # Extract the main implementation name and version
        if '/' in version_str:
            parts = version_str.split('/')
            
            # First part usually contains implementation and version
            impl_part = parts[0]
            
            # Extract version number (look for patterns like v1.2.3, 1.2.3, etc.)
            import re
            version_match = re.search(r'v?(\d+\.\d+\.\d+(?:[.-]\w+)*)', impl_part)
            if version_match:
                result['node_version'] = version_match.group(1)
            
            # Process subsequent parts for platform info
            for i, part in enumerate(parts[1:], 1):
                part_lower = part.lower()
                
                # Operating System detection
                if any(os_name in part_lower for os_name in ['linux', 'windows', 'darwin', 'macos', 'freebsd', 'openbsd']):
                    if 'linux' in part_lower:
                        result['operating_system'] = 'Linux'
                    elif 'windows' in part_lower:
                        result['operating_system'] = 'Windows'
                    elif 'darwin' in part_lower or 'macos' in part_lower:
                        result['operating_system'] = 'macOS'
                    elif 'freebsd' in part_lower:
                        result['operating_system'] = 'FreeBSD'
                    elif 'openbsd' in part_lower:
                        result['operating_system'] = 'OpenBSD'
                
                # Architecture detection
                elif any(arch in part_lower for arch in ['amd64', 'x86_64', 'arm64', 'arm', 'x64', 'x86']):
                    if 'amd64' in part_lower or 'x86_64' in part_lower:
                        result['architecture'] = 'amd64'
                    elif 'x64' in part_lower:
                        result['architecture'] = 'x64'
                    elif 'arm64' in part_lower:
                        result['architecture'] = 'arm64'
                    elif 'arm' in part_lower:
                        result['architecture'] = 'ARM'
                    elif 'x86' in part_lower:
                        result['architecture'] = 'x86'
                
                # Programming language and version detection
                elif 'go' in part_lower:
                    result['programming_language'] = 'Go'
                    # Extract Go version (e.g., go1.21.4)
                    go_match = re.search(r'go(\d+\.\d+(?:\.\d+)?)', part_lower)
                    if go_match:
                        result['language_version'] = go_match.group(1)
                
                elif 'java' in part_lower or 'openjdk' in part_lower:
                    result['programming_language'] = 'Java'
                    # Extract Java version (e.g., java-17, openjdk-java-17)
                    java_match = re.search(r'java[-]?(\d+)', part_lower)
                    if java_match:
                        result['language_version'] = java_match.group(1)
                
                elif 'dotnet' in part_lower or '.net' in part_lower:
                    result['programming_language'] = '.NET'
                    # Extract .NET version (e.g., dotnet8.0.0)
                    dotnet_match = re.search(r'dotnet(\d+\.\d+(?:\.\d+)?)', part_lower)
                    if dotnet_match:
                        result['language_version'] = dotnet_match.group(1)
                
                elif 'rust' in part_lower:
                    result['programming_language'] = 'Rust'
                    # Extract Rust version if present
                    rust_match = re.search(r'rust[-]?(\d+\.\d+(?:\.\d+)?)', part_lower)
                    if rust_match:
                        result['language_version'] = rust_match.group(1)
                
                # Build info (commit hashes, timestamps, etc.)
                elif re.match(r'^[a-f0-9]{7,}', part) or '+' in part:
                    # Try to identify what type of build info this is
                    if re.match(r'^[a-f0-9]{7,}$', part):
                        result['build_info']['commit_hash'] = part
                    elif '+' in part:
                        result['build_info']['build_info'] = part
                    else:
                        result['build_info']['build_info'] = part
        
        # Special handling for specific implementations
        impl_lower = client_version.lower()
        
        # Hardhat detection
        if 'hardhat' in impl_lower:
            result['programming_language'] = 'JavaScript/TypeScript'
            if 'node.js' in impl_lower:
                result['language_version'] = 'Node.js'
        
        # Ganache detection
        elif 'ganache' in impl_lower:
            result['programming_language'] = 'JavaScript'
        
        # Anvil detection (Foundry)
        elif 'anvil' in impl_lower:
            result['programming_language'] = 'Rust'
        
        # Erigon (Go-based)
        elif 'erigon' in impl_lower or 'turbogeth' in impl_lower:
            if not result['programming_language']:
                result['programming_language'] = 'Go'
        
        # Geth (Go-based)
        elif 'geth' in impl_lower:
            if not result['programming_language']:
                result['programming_language'] = 'Go'
        
        # Besu (Java-based)
        elif 'besu' in impl_lower:
            if not result['programming_language']:
                result['programming_language'] = 'Java'
        
        # Nethermind (.NET-based)
        elif 'nethermind' in impl_lower:
            if not result['programming_language']:
                result['programming_language'] = '.NET'
        
        # Parity/OpenEthereum (Rust-based)
        elif 'parity' in impl_lower or 'openethereum' in impl_lower:
            if not result['programming_language']:
                result['programming_language'] = 'Rust'
        
        return result


def print_fingerprint_result(result: FingerprintResult):
    """Print fingerprint result using Rich formatting"""
    
    # Create a panel for the endpoint
    endpoint_text = Text(result.endpoint, style="bold yellow")
    panel = Panel(endpoint_text, title="🔍 RPC Endpoint", border_style="cyan", box=box.ROUNDED)
    console.print(panel)
    
    # Show errors if any
    if result.errors:
        error_table = Table(title="❌ Errors", show_header=False, box=box.SIMPLE)
        error_table.add_column("Error", style="red")
        for error in result.errors:
            error_table.add_row(f"• {error}")
        console.print(error_table)
    
    # Basic Information Table
    basic_table = Table(title="📊 Basic Information", box=box.ROUNDED)
    basic_table.add_column("Property", style="cyan", no_wrap=True)
    basic_table.add_column("Value", style="white")
    
    basic_info = [
        ("Client Version", result.client_version),
        ("Node Implementation", result.node_implementation),
        ("Node Version", result.node_version),
        ("Programming Language", result.programming_language),
        ("Language Version", result.language_version),
        ("Operating System", result.operating_system),
        ("Architecture", result.architecture),
        ("Network ID", result.network_id),
        ("Chain ID", result.chain_id),
        ("Protocol Version", result.protocol_version),
        ("Response Time", f"{result.response_time:.3f}s" if result.response_time else None)
    ]
    
    for prop, value in basic_info:
        if value is not None:
            # Style certain values
            if prop == "Node Implementation" and value != "Unknown":
                value = f"[bold green]{value}[/bold green]"
            elif prop == "Response Time":
                # Color code response times
                time_val = float(value.replace('s', ''))
                if time_val < 0.1:
                    value = f"[bold green]{value}[/bold green]"
                elif time_val < 0.5:
                    value = f"[yellow]{value}[/yellow]"
                else:
                    value = f"[red]{value}[/red]"
            
            basic_table.add_row(prop, str(value))
    
    if basic_table.row_count > 0:
        console.print(basic_table)
    
    # Build Information (if available)
    if result.build_info:
        # Handle both dict and string formats for backward compatibility
        if isinstance(result.build_info, dict) and any(result.build_info.values()):
            build_table = Table(title="🔧 Build Information", box=box.ROUNDED)
            build_table.add_column("Property", style="cyan", no_wrap=True)
            build_table.add_column("Value", style="white")
            
            for key, value in result.build_info.items():
                if value:
                    build_table.add_row(key.replace('_', ' ').title(), str(value))
            
            if build_table.row_count > 0:
                console.print(build_table)
        elif isinstance(result.build_info, str):
            # Handle legacy string format
            build_table = Table(title="🔧 Build Information", box=box.ROUNDED)
            build_table.add_column("Property", style="cyan", no_wrap=True)
            build_table.add_column("Value", style="white")
            build_table.add_row("Build Info", result.build_info)
            console.print(build_table)
    
    # Network Status Table
    network_table = Table(title="🌐 Network Status", box=box.ROUNDED)
    network_table.add_column("Property", style="cyan", no_wrap=True)
    network_table.add_column("Value", style="white")
    
    network_info = [
        ("Block Number", result.block_number),
        ("Gas Price", f"{result.gas_price} wei" if result.gas_price else None),
        ("Peer Count", result.peer_count),
        ("Syncing", result.syncing),
        ("Mining", result.mining),
        ("Hashrate", result.hashrate)
    ]
    
    for prop, value in network_info:
        if value is not None:
            # Style certain values
            if prop == "Syncing":
                value = f"[red]{value}[/red]" if value else f"[green]{value}[/green]"
            elif prop == "Mining":
                value = f"[yellow]{value}[/yellow]" if value else f"[dim]{value}[/dim]"
            elif prop == "Peer Count" and isinstance(value, int):
                if value == 0:
                    value = f"[red]{value}[/red]"
                elif value < 5:
                    value = f"[yellow]{value}[/yellow]"
                else:
                    value = f"[green]{value}[/green]"
            
            network_table.add_row(prop, str(value))
    
    if network_table.row_count > 0:
        console.print(network_table)
    
    # Accounts
    if result.accounts:
        accounts_table = Table(title=f"👤 Accounts ({len(result.accounts)})", box=box.ROUNDED)
        accounts_table.add_column("#", style="dim", width=3)
        accounts_table.add_column("Address", style="yellow")
        
        for i, account in enumerate(result.accounts[:10]):  # Show first 10
            accounts_table.add_row(str(i+1), account)
        
        if len(result.accounts) > 10:
            accounts_table.add_row("...", f"and {len(result.accounts) - 10} more")
        
        console.print(accounts_table)
    
    # Supported Methods
    if result.supported_methods:
        methods_table = Table(title=f"⚙️ Supported Methods ({len(result.supported_methods)})", box=box.ROUNDED)
        methods_table.add_column("Namespace", style="cyan", no_wrap=True)
        methods_table.add_column("Methods", style="white")
        
        # Group methods by namespace
        namespaces = {}
        for method in result.supported_methods:
            namespace = method.split('_')[0]
            if namespace not in namespaces:
                namespaces[namespace] = []
            namespaces[namespace].append(method)
        
        for namespace, methods in sorted(namespaces.items()):
            method_names = [m.split('_', 1)[1] if '_' in m else m for m in methods]
            methods_table.add_row(namespace, ", ".join(method_names))
        
        console.print(methods_table)
    
    # Additional Information
    if result.additional_info:
        additional_table = Table(title="ℹ️ Additional Information", box=box.ROUNDED)
        additional_table.add_column("Property", style="cyan", no_wrap=True)
        additional_table.add_column("Value", style="white")
        
        for key, value in result.additional_info.items():
            additional_table.add_row(key.replace('_', ' ').title(), str(value))
        
        console.print(additional_table)
    
    # Security Vulnerabilities (NEW SECTION)
    if result.vulnerabilities is not None:
        # Create security overview panel
        security_style = "green"
        security_symbol = "🛡️"
        security_message = "No known vulnerabilities found"
        
        if result.vulnerabilities:
            # Determine overall security status style based on highest severity
            if result.security_risk_level == "CRITICAL":
                security_style = "bold red"
                security_symbol = "🚨"
                security_message = f"CRITICAL security risk - {len(result.vulnerabilities)} vulnerability(s) found"
            elif result.security_risk_level == "HIGH":
                security_style = "bold orange3"
                security_symbol = "⚠️"
                security_message = f"HIGH security risk - {len(result.vulnerabilities)} vulnerability(s) found"
            elif result.security_risk_level == "MEDIUM":
                security_style = "yellow"
                security_symbol = "⚠️"
                security_message = f"MEDIUM security risk - {len(result.vulnerabilities)} vulnerability(s) found"
            elif result.security_risk_level == "LOW":
                security_style = "bright_blue"
                security_symbol = "ℹ️"
                security_message = f"LOW security risk - {len(result.vulnerabilities)} vulnerability(s) found"
        
        # Security overview panel
        security_text = Text(f"{security_symbol} {security_message}", style=security_style)
        security_panel = Panel(
            security_text, 
            title="🔒 Security Assessment", 
            border_style=security_style,
            box=box.ROUNDED
        )
        console.print(security_panel)
        
        # Detailed vulnerability table if vulnerabilities exist
        if result.vulnerabilities:
            vuln_table = Table(title=f"⚠️ Vulnerability Details ({len(result.vulnerabilities)} found)", box=box.ROUNDED)
            vuln_table.add_column("CVE ID", style="cyan", no_wrap=True)
            vuln_table.add_column("Severity", style="white", no_wrap=True)
            vuln_table.add_column("CVSS", style="white", no_wrap=True, justify="center")
            vuln_table.add_column("Title", style="white", max_width=40)
            vuln_table.add_column("Fixed In", style="green", no_wrap=True)
            
            for vuln in result.vulnerabilities:
                # Style severity with colors
                severity_styles = {
                    "CRITICAL": "bold red",
                    "HIGH": "bold orange3", 
                    "MEDIUM": "yellow",
                    "LOW": "bright_blue"
                }
                severity_style = severity_styles.get(vuln.severity, "white")
                
                # Style CVSS score with colors
                cvss_style = "white"
                if vuln.cvss_score >= 9.0:
                    cvss_style = "bold red"
                elif vuln.cvss_score >= 7.0:
                    cvss_style = "bold orange3"
                elif vuln.cvss_score >= 4.0:
                    cvss_style = "yellow"
                else:
                    cvss_style = "green"
                
                vuln_table.add_row(
                    vuln.cve_id,
                    f"[{severity_style}]{vuln.severity}[/{severity_style}]",
                    f"[{cvss_style}]{vuln.cvss_score}[/{cvss_style}]",
                    vuln.title,
                    vuln.fixed_in
                )
            
            console.print(vuln_table)
            
            # Recommendations section for critical/high vulnerabilities
            critical_high_vulns = [v for v in result.vulnerabilities if v.severity in ["CRITICAL", "HIGH"]]
            if critical_high_vulns:
                rec_table = Table(title="🔧 Security Recommendations", box=box.ROUNDED)
                rec_table.add_column("Priority", style="red", no_wrap=True)
                rec_table.add_column("Recommendation", style="white")
                
                for vuln in critical_high_vulns:
                    priority = "URGENT" if vuln.severity == "CRITICAL" else "HIGH"
                    rec_table.add_row(
                        f"[bold red]{priority}[/bold red]" if priority == "URGENT" else f"[orange3]{priority}[/orange3]",
                        vuln.recommendation
                    )
                
                console.print(rec_table)
    
    # Add some spacing
    console.print()


def _save_results(results: List[FingerprintResult], output_path: str, format_type: str, verbose: bool = False):
    """Save results to file in specified format"""
    if verbose:
        click.echo(f"💾 Saving results to {output_path} in {format_type} format")
    
    data = [asdict(result) for result in results]
    
    try:
        with open(output_path, 'w') as f:
            if format_type == 'json':
                json.dump(data, f, indent=2, default=str)
            elif format_type == 'yaml':
                import yaml
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            else:  # table format - save as JSON but display as table
                json.dump(data, f, indent=2, default=str)
    except Exception as e:
        click.echo(f"❌ Failed to save results: {e}", err=True)
        raise


def _display_results(results: List[FingerprintResult], format_type: str):
    """Display results in specified format"""
    if format_type == 'json':
        data = [asdict(result) for result in results]
        click.echo(json.dumps(data, indent=2, default=str))
    elif format_type == 'yaml':
        import yaml
        data = [asdict(result) for result in results]
        click.echo(yaml.dump(data, default_flow_style=False, sort_keys=False))
    else:  # table format (default)
        for i, result in enumerate(results):
            if i > 0:
                click.echo()  # Add spacing between results
            print_fingerprint_result(result)


# CLI Configuration
@click.group()
@click.version_option(version='1.0.0', prog_name='ethereum-rpc-fingerprinter')
def cli():
    """Ethereum RPC Fingerprinting Tool Suite"""
    pass


@cli.command()
@click.argument('client_versions', nargs=-1, required=True)
def parse_version(client_versions):
    """
    Parse client version strings to extract detailed information.
    
    CLIENT_VERSIONS: One or more client version strings to parse
    
    Example:
    erf parse-version "Geth/v1.13.5-stable/linux-amd64/go1.21.4"
    """
    fingerprinter = EthereumRPCFingerprinter()
    
    for version_str in client_versions:
        click.echo(f"\n📋 Parsing: {version_str}")
        click.echo("-" * 60)
        
        implementation = fingerprinter._extract_node_implementation(version_str)
        parsed = fingerprinter._parse_client_version(version_str)
        
        # Create a table of parsed information
        table_data = [
            ["Implementation", implementation or "Unknown"],
            ["Node Version", parsed.get('node_version', 'N/A')],
            ["Programming Language", parsed.get('programming_language', 'N/A')],
            ["Language Version", parsed.get('language_version', 'N/A')],
            ["Operating System", parsed.get('operating_system', 'N/A')],
            ["Architecture", parsed.get('architecture', 'N/A')],
        ]
        
        # Add build info if available
        if parsed.get('build_info') and any(parsed['build_info'].values()):
            for key, value in parsed['build_info'].items():
                table_data.append([f"Build {key.replace('_', ' ').title()}", value])
        
        click.echo(tabulate(table_data, headers=["Property", "Value"], tablefmt="grid"))


@cli.command()
@click.option('--include-dev', is_flag=True, help='Include development/testing nodes')
def list_implementations(include_dev):
    """List supported Ethereum client implementations."""
    
    implementations = {
        "Production Clients": [
            ("Geth", "Go-based Ethereum client (most popular)"),
            ("Besu", "Java-based enterprise Ethereum client"),
            ("Nethermind", ".NET-based Ethereum client"),
            ("Erigon", "Go-based archive node with performance focus"),
            ("Parity/OpenEthereum", "Rust-based Ethereum client (deprecated)")
        ],
        "Development/Testing": [
            ("Anvil", "Local development node (Foundry)"),
            ("Hardhat Network", "Ethereum development environment"),
            ("Ganache", "Personal blockchain for development")
        ]
    }
    
    for category, clients in implementations.items():
        if category == "Development/Testing" and not include_dev:
            continue
            
        click.echo(f"\n{Fore.GREEN}{category}:{Style.RESET_ALL}")
        for name, description in clients:
            click.echo(f"  • {Fore.CYAN}{name}{Style.RESET_ALL}: {description}")


# Add the main command to the CLI group as the default
@cli.command(name='fingerprint')
@click.argument('endpoints', nargs=-1, required=False)
@click.option('--file', '-f', 'endpoints_file', type=click.Path(exists=True, readable=True), 
              help='File containing URLs (one per line) to fingerprint')
@click.option('--timeout', '-t', default=10, help='Request timeout in seconds', show_default=True)
@click.option('--async', '-a', 'async_mode', is_flag=True, help='Use async fingerprinting for multiple endpoints')
@click.option('--output', '-o', type=click.Path(), help='Output file for JSON results')
@click.option('--quiet', '-q', is_flag=True, help='Only output JSON, no formatted display')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), 
              default='table', help='Output format', show_default=True)
@click.option('--max-concurrent', default=10, help='Maximum concurrent requests for async mode', show_default=True)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def fingerprint_command(endpoints, endpoints_file, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose):
    """
    Fingerprint Ethereum RPC endpoints.
    
    ENDPOINTS: One or more RPC endpoint URLs to fingerprint (optional if --file is used)
    
    Examples:
    
    \b
    # Single endpoint
    erf fingerprint http://localhost:8545
    
    \b
    # Multiple endpoints with async mode
    erf fingerprint -a http://localhost:8545 https://eth.llamarpc.com
    
    \b
    # From file with URLs (one per line)
    erf fingerprint -f endpoints.txt
    
    \b
    # From file with async mode
    erf fingerprint -f endpoints.txt -a
    
    \b
    # Export to JSON
    erf fingerprint -o results.json http://localhost:8545
    
    \b
    # Combine file and direct URLs
    erf fingerprint -f endpoints.txt http://localhost:8545 https://eth.llamarpc.com
    """
    # Validate input: either endpoints or file must be provided
    if not endpoints and not endpoints_file:
        raise click.UsageError("Either provide endpoint URLs or use --file option")
    
    # Collect all endpoints
    all_endpoints = list(endpoints) if endpoints else []
    
    # Read endpoints from file if provided
    if endpoints_file:
        if verbose:
            click.echo(f"📁 Reading endpoints from file: {endpoints_file}")
        
        try:
            with open(endpoints_file, 'r', encoding='utf-8') as f:
                file_endpoints = []
                line_num = 0
                for line in f:
                    line_num += 1
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Basic URL validation
                    if not (line.startswith('http://') or line.startswith('https://') or line.startswith('wss://') or line.startswith('ws://')):
                        if verbose:
                            click.echo(f"⚠️  Skipping invalid URL on line {line_num}: {line}", err=True)
                        continue
                    
                    file_endpoints.append(line)
                
                all_endpoints.extend(file_endpoints)
                
                if verbose:
                    click.echo(f"📄 Loaded {len(file_endpoints)} endpoints from file")
        
        except Exception as e:
            raise click.ClickException(f"Error reading file {endpoints_file}: {str(e)}")
    
    if not all_endpoints:
        raise click.ClickException("No valid endpoints found")
    
    if verbose:
        click.echo(f"🎯 Total endpoints to fingerprint: {len(all_endpoints)}")
    
    return main(all_endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose)


def main(endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose):
    """Core fingerprinting logic"""
    if verbose:
        console.print("🔍 Starting fingerprinting of [bold cyan]{}[/bold cyan] endpoint(s)...".format(len(endpoints)))
        console.print("⚙️  Configuration: timeout=[yellow]{}s[/yellow], async=[cyan]{}[/cyan], format=[green]{}[/green]".format(timeout, async_mode, output_format))
    
    try:
        # Choose fingerprinting method
        if async_mode and len(endpoints) > 1:
            if verbose:
                console.print("🚀 Using [bold green]async fingerprinting mode[/bold green]")
            
            async def run_async():
                fingerprinter = AsyncEthereumRPCFingerprinter(timeout=timeout, max_concurrent=max_concurrent)
                return await fingerprinter.fingerprint_multiple(list(endpoints), show_progress=not quiet)
            
            results = asyncio.run(run_async())
        else:
            if verbose:
                console.print("🔄 Using [bold blue]synchronous fingerprinting mode[/bold blue]")
            
            fingerprinter = EthereumRPCFingerprinter(timeout=timeout)
            results = []
            
            if len(endpoints) > 1 and not quiet:
                # Use Rich progress bar for beautiful synchronous progress tracking
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=console,
                    refresh_per_second=10,
                ) as progress:
                    task = progress.add_task("🔍 Fingerprinting endpoints...", total=len(endpoints))
                    
                    for endpoint in endpoints:
                        result = fingerprinter.fingerprint(endpoint)
                        results.append(result)
                        progress.advance(task)
            else:
                for endpoint in endpoints:
                    result = fingerprinter.fingerprint(endpoint)
                    results.append(result)
        
        # Handle output
        if output:
            _save_results(results, output, output_format, verbose)
            if not quiet:
                click.echo(f"✅ Results saved to {output}")
        
        # Display results unless quiet mode
        if not quiet:
            _display_results(results, output_format)
            
    except KeyboardInterrupt:
        click.echo("\n❌ Operation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


if __name__ == "__main__":
    # When called directly, use the simple main function for backwards compatibility
    @click.command()
    @click.argument('endpoints', nargs=-1, required=True)
    @click.option('--timeout', '-t', default=10, help='Request timeout in seconds', show_default=True)
    @click.option('--async', '-a', 'async_mode', is_flag=True, help='Use async fingerprinting for multiple endpoints')
    @click.option('--output', '-o', type=click.Path(), help='Output file for JSON results')
    @click.option('--quiet', '-q', is_flag=True, help='Only output JSON, no formatted display')
    @click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), 
                  default='table', help='Output format', show_default=True)
    @click.option('--max-concurrent', default=10, help='Maximum concurrent requests for async mode', show_default=True)
    @click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
    @click.version_option(version='1.0.0', prog_name='ethereum-rpc-fingerprinter')
    def standalone_main(endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose):
        """
        Ethereum RPC Host Fingerprinting Tool
        
        A comprehensive tool for fingerprinting Ethereum RPC endpoints to identify
        node implementations, versions, network configurations, and security characteristics.
        """
        main(endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose)
    
    standalone_main()
