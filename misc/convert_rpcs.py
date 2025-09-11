#!/usr/bin/env python3
"""
Convert rpcs.json to endpoints.txt for scanning purposes.
Extracts only RPC URLs (http/https/ws/wss) excluding block explorers.
"""

import json
import re

def is_rpc_url(url):
    """Check if URL is an RPC endpoint (not explorer/faucet)"""
    # RPC URLs typically start with http/https/ws/wss
    if not re.match(r'^(https?|wss?)://', url):
        return False
    
    # Skip obvious block explorers and non-RPC services
    skip_patterns = [
        'explorer', 'scan', 'etherscan', 'blockscout', 'dexguru',
        'routescan', 'polygonscan', 'arbiscan', 'basescan',
        'faucet', 'bridge', 'swap', 'dex', 'superscan'
    ]
    
    url_lower = url.lower()
    for pattern in skip_patterns:
        if pattern in url_lower:
            return False
    
    return True

def extract_rpc_urls(json_file_path, output_file_path):
    """Extract RPC URLs from chains JSON file"""
    
    with open(json_file_path, 'r') as f:
        chains = json.load(f)
    
    rpc_urls = set()  # Use set to avoid duplicates
    
    for chain in chains:
        # Extract from 'rpc' field
        if 'rpc' in chain:
            for rpc_entry in chain['rpc']:
                if isinstance(rpc_entry, dict) and 'url' in rpc_entry:
                    url = rpc_entry['url']
                elif isinstance(rpc_entry, str):
                    url = rpc_entry
                else:
                    continue
                
                # Clean up URL (remove trailing slashes, etc.)
                url = url.strip().rstrip('/')
                
                # Skip template URLs with placeholders
                if '${' in url or '{' in url:
                    continue
                
                # Check if it's a valid RPC URL
                if is_rpc_url(url):
                    rpc_urls.add(url)
    
    # Convert to sorted list for consistent output
    sorted_urls = sorted(list(rpc_urls))
    
    # Write to output file
    with open(output_file_path, 'w') as f:
        for url in sorted_urls:
            f.write(url + '\n')
    
    print(f"✅ Extracted {len(sorted_urls)} unique RPC endpoints")
    print(f"📝 Written to: {output_file_path}")
    
    # Show some statistics
    http_count = sum(1 for url in sorted_urls if url.startswith('http://'))
    https_count = sum(1 for url in sorted_urls if url.startswith('https://'))
    ws_count = sum(1 for url in sorted_urls if url.startswith('ws://'))
    wss_count = sum(1 for url in sorted_urls if url.startswith('wss://'))
    
    print(f"\n📊 URL Statistics:")
    print(f"   HTTP:  {http_count}")
    print(f"   HTTPS: {https_count}")
    print(f"   WS:    {ws_count}")
    print(f"   WSS:   {wss_count}")
    
    # Show first few URLs as preview
    print(f"\n🔍 Preview (first 10 URLs):")
    for i, url in enumerate(sorted_urls[:10]):
        print(f"   {i+1:2d}. {url}")
    
    if len(sorted_urls) > 10:
        print(f"   ... and {len(sorted_urls) - 10} more")

if __name__ == "__main__":
    extract_rpc_urls("rpcs.json", "endpoints.txt")
