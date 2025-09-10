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
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from web3 import Web3
from web3.exceptions import Web3Exception
import sys
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama for cross-platform colored output
init()

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

class EthereumRPCFingerprinter:
    """
    Comprehensive Ethereum RPC fingerprinting tool
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
        
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
            
        except Exception as e:
            result.errors.append(f"General connection error: {e}")
            
        return result
    
    def _extract_node_implementation(self, client_version: str) -> Optional[str]:
        """Extract node implementation from client version string"""
        if not client_version:
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
        elif 'anvil' in client_lower:
            return 'Anvil'
        elif 'hardhat' in client_lower:
            return 'Hardhat'
        elif 'ganache' in client_lower:
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

class AsyncEthereumRPCFingerprinter:
    """
    Asynchronous version for fingerprinting multiple endpoints
    """
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def fingerprint_multiple(self, endpoints: List[str]) -> List[FingerprintResult]:
        """
        Fingerprint multiple endpoints concurrently
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
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

def print_fingerprint_result(result: FingerprintResult):
    """Print fingerprint result in a formatted way"""
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Endpoint: {Style.RESET_ALL}{result.endpoint}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    if result.errors:
        print(f"\n{Fore.RED}Errors:{Style.RESET_ALL}")
        for error in result.errors:
            print(f"  • {error}")
    
    # Basic Information
    basic_info = [
        ["Client Version", result.client_version],
        ["Node Implementation", result.node_implementation],
        ["Node Version", result.node_version],
        ["Programming Language", result.programming_language],
        ["Language Version", result.language_version],
        ["Operating System", result.operating_system],
        ["Architecture", result.architecture],
        ["Network ID", result.network_id],
        ["Chain ID", result.chain_id],
        ["Protocol Version", result.protocol_version],
        ["Response Time", f"{result.response_time:.3f}s" if result.response_time else None]
    ]
    
    print(f"\n{Fore.GREEN}Basic Information:{Style.RESET_ALL}")
    print(tabulate([row for row in basic_info if row[1] is not None], 
                  headers=["Property", "Value"], tablefmt="grid"))
    
    # Build Information (if available)
    if result.build_info and any(result.build_info.values()):
        print(f"\n{Fore.GREEN}Build Information:{Style.RESET_ALL}")
        build_table = [[key.replace('_', ' ').title(), value] for key, value in result.build_info.items() if value]
        if build_table:
            print(tabulate(build_table, headers=["Property", "Value"], tablefmt="grid"))
    
    # Network Status
    network_info = [
        ["Block Number", result.block_number],
        ["Gas Price", f"{result.gas_price} wei" if result.gas_price else None],
        ["Peer Count", result.peer_count],
        ["Syncing", result.syncing],
        ["Mining", result.mining],
        ["Hashrate", result.hashrate]
    ]
    
    print(f"\n{Fore.GREEN}Network Status:{Style.RESET_ALL}")
    print(tabulate([row for row in network_info if row[1] is not None], 
                  headers=["Property", "Value"], tablefmt="grid"))
    
    # Accounts
    if result.accounts:
        print(f"\n{Fore.GREEN}Accounts ({len(result.accounts)}):{Style.RESET_ALL}")
        for i, account in enumerate(result.accounts[:5]):  # Show first 5
            print(f"  {i+1:2d}. {account}")
        if len(result.accounts) > 5:
            print(f"  ... and {len(result.accounts) - 5} more")
    
    # Supported Methods
    if result.supported_methods:
        print(f"\n{Fore.GREEN}Supported Methods ({len(result.supported_methods)}):{Style.RESET_ALL}")
        # Group methods by namespace
        namespaces = {}
        for method in result.supported_methods:
            namespace = method.split('_')[0]
            if namespace not in namespaces:
                namespaces[namespace] = []
            namespaces[namespace].append(method)
        
        for namespace, methods in namespaces.items():
            print(f"  {Fore.BLUE}{namespace}:{Style.RESET_ALL} {', '.join([m.split('_', 1)[1] for m in methods])}")
    
    # Additional Information
    if result.additional_info:
        print(f"\n{Fore.GREEN}Additional Information:{Style.RESET_ALL}")
        for key, value in result.additional_info.items():
            if isinstance(value, dict):
                print(f"  {key}: {json.dumps(value, indent=2)}")
            else:
                print(f"  {key}: {value}")


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
    ethereum-rpc-fingerprinter parse-version "Geth/v1.13.5-stable/linux-amd64/go1.21.4"
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
@click.argument('endpoints', nargs=-1, required=True)
@click.option('--timeout', '-t', default=10, help='Request timeout in seconds', show_default=True)
@click.option('--async-mode', '-a', is_flag=True, help='Use async fingerprinting for multiple endpoints')
@click.option('--output', '-o', type=click.Path(), help='Output file for JSON results')
@click.option('--quiet', '-q', is_flag=True, help='Only output JSON, no formatted display')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'yaml']), 
              default='table', help='Output format', show_default=True)
@click.option('--max-concurrent', default=10, help='Maximum concurrent requests for async mode', show_default=True)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def fingerprint_command(endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose):
    """
    Fingerprint Ethereum RPC endpoints.
    
    ENDPOINTS: One or more RPC endpoint URLs to fingerprint
    
    Examples:
    
    \b
    # Single endpoint
    ethereum-rpc-fingerprinter fingerprint http://localhost:8545
    
    \b
    # Multiple endpoints with async mode
    ethereum-rpc-fingerprinter fingerprint -a http://localhost:8545 https://eth.llamarpc.com
    
    \b
    # Export to JSON
    ethereum-rpc-fingerprinter fingerprint -o results.json http://localhost:8545
    """
    return main(endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose)


def main(endpoints, timeout, async_mode, output, quiet, output_format, max_concurrent, verbose):
    """Core fingerprinting logic"""
    if verbose:
        click.echo(f"🔍 Starting fingerprinting of {len(endpoints)} endpoint(s)...")
        click.echo(f"⚙️  Configuration: timeout={timeout}s, async={async_mode}, format={output_format}")
    
    try:
        # Choose fingerprinting method
        if async_mode and len(endpoints) > 1:
            if verbose:
                click.echo("🚀 Using async fingerprinting mode")
            
            async def run_async():
                fingerprinter = AsyncEthereumRPCFingerprinter(timeout=timeout, max_concurrent=max_concurrent)
                return await fingerprinter.fingerprint_multiple(list(endpoints))
            
            results = asyncio.run(run_async())
        else:
            if verbose:
                click.echo("🔄 Using synchronous fingerprinting mode")
            
            fingerprinter = EthereumRPCFingerprinter(timeout=timeout)
            results = []
            
            if len(endpoints) > 1 and not quiet:
                with click.progressbar(endpoints, label='Fingerprinting endpoints') as bar:
                    for endpoint in bar:
                        result = fingerprinter.fingerprint(endpoint)
                        results.append(result)
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
    @click.option('--async-mode', '-a', is_flag=True, help='Use async fingerprinting for multiple endpoints')
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
