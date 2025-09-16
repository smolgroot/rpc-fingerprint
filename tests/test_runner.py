#!/usr/bin/env python3
"""
Test runner that executes all unit tests for the Ethereum RPC Fingerprinter.
"""

import unittest
import sys
import os

# Add the parent directory to the path so we can import the fingerprinter
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all test modules
from test_node_implementation import TestNodeImplementationDetection
from test_client_version_parsing import TestClientVersionParsing
from test_fingerprint_result import TestFingerprintResult, TestFingerprintResultIntegration
from test_rpc_networking import TestNetworkingFunctionality, TestAsyncNetworkingFunctionality, TestMethodDetection, TestErrorHandling
from test_cve_database import TestVulnerabilityDataClass, TestCVEDatabase, TestCVEIntegration, TestConvenienceFunction


def create_test_suite():
    """Create a comprehensive test suite."""
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        # Node implementation detection tests
        TestNodeImplementationDetection,
        
        # Client version parsing tests
        TestClientVersionParsing,
        
        # FingerprintResult tests
        TestFingerprintResult,
        TestFingerprintResultIntegration,
        
        # RPC and networking tests
        TestMethodDetection,
        TestNetworkingFunctionality,
        TestAsyncNetworkingFunctionality,
        TestErrorHandling,
        
        # CVE database and vulnerability tests
        TestVulnerabilityDataClass,
        TestCVEDatabase,
        TestCVEIntegration,
        TestConvenienceFunction,
    ]
    
    # Load all test methods from each class
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_tests(verbosity=2):
    """Run all tests with specified verbosity level."""
    print("🧪 Running Ethereum RPC Fingerprinter Unit Tests")
    print("=" * 60)
    
    # Create and run the test suite
    suite = create_test_suite()
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\n❌ Failures ({len(result.failures)}):")
        for test, traceback in result.failures:
            print(f"  • {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0] if 'AssertionError:' in traceback else 'See details above'}")
    
    if result.errors:
        print(f"\n💥 Errors ({len(result.errors)}):")
        for test, traceback in result.errors:
            print(f"  • {test}: {traceback.split('\\n')[-2] if len(traceback.split('\\n')) > 1 else 'Unknown error'}")
    
    # Overall result
    if result.wasSuccessful():
        print("\\n✅ All tests passed successfully!")
        return 0
    else:
        print("\\n❌ Some tests failed. Please review the output above.")
        return 1


def run_specific_test_module(module_name):
    """Run tests from a specific module."""
    print(f"🧪 Running tests from: {module_name}")
    print("=" * 60)
    
    # Import and run specific module
    try:
        module = __import__(module_name)
        suite = unittest.TestLoader().loadTestsFromModule(module)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    except ImportError as e:
        print(f"❌ Could not import test module '{module_name}': {e}")
        return 1


def list_available_tests():
    """List all available test methods."""
    print("📋 Available Test Categories:")
    print("=" * 60)
    
    test_categories = [
        ("Node Implementation Detection", "test_node_implementation"),
        ("Client Version Parsing", "test_client_version_parsing"), 
        ("FingerprintResult Data Structure", "test_fingerprint_result"),
        ("RPC Method Detection & Networking", "test_rpc_networking"),
    ]
    
    for category, module in test_categories:
        print(f"• {category:.<45} {module}")
    
    print("\\nTo run a specific category:")
    print("  python test_runner.py --module <module_name>")
    print("\\nTo run all tests:")
    print("  python test_runner.py")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ethereum RPC Fingerprinter Test Runner")
    parser.add_argument('--module', '-m', help='Run tests from specific module')
    parser.add_argument('--list', '-l', action='store_true', help='List available test modules')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.list:
        list_available_tests()
        sys.exit(0)
    
    verbosity = 2 if args.verbose else 1
    
    if args.module:
        exit_code = run_specific_test_module(args.module)
    else:
        exit_code = run_tests(verbosity)
    
    sys.exit(exit_code)
