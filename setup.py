#!/usr/bin/env python3
"""
Setup script for ethereum-rpc-fingerprinter package
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    with open(readme_path, 'r', encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    with open(req_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="ethereum-rpc-fingerprinter",
    version="1.1.2",
    author="smolgroot",
    author_email="smolgroot@example.com",
    description="A comprehensive tool for fingerprinting Ethereum RPC endpoints",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/smolgroot/ethereum-rpc-fingerprinter",
    packages=find_packages(),
    py_modules=["ethereum_rpc_fingerprinter"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "ethereum-rpc-fingerprinter=ethereum_rpc_fingerprinter:cli",
            "erf=ethereum_rpc_fingerprinter:cli",
        ],
    },
    keywords=[
        "ethereum", "rpc", "fingerprinting", "blockchain", "web3", 
        "geth", "besu", "nethermind", "erigon", "security", "analysis"
    ],
    project_urls={
        "Bug Reports": "https://github.com/smolgroot/ethereum-rpc-fingerprinter/issues",
        "Source": "https://github.com/smolgroot/ethereum-rpc-fingerprinter",
        "Documentation": "https://github.com/smolgroot/ethereum-rpc-fingerprinter#readme",
    },
    include_package_data=True,
    zip_safe=False,
)
