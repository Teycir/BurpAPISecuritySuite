#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run all tests"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_tests():
    print("=" * 80)
    print("RUNNING ALL TESTS")
    print("=" * 80)
    print("")
    
    tests = [
        'test_fuzzer_logic',
        'test_real_data',
        'test_feature_contracts'
    ]
    
    passed = 0
    failed = 0
    
    for test_name in tests:
        try:
            print("\n{}".format("=" * 80))
            print("Running: {}".format(test_name))
            print('=' * 80)
            module = __import__(test_name)
            
            # Run all test functions
            for attr in dir(module):
                if attr.startswith('test_'):
                    func = getattr(module, attr)
                    if callable(func):
                        result = func()
                        if result is False:
                            raise AssertionError("{}.{} returned False".format(test_name, attr))
            
            passed += 1
        except Exception as e:
            print("  [FAIL] {}".format(e))
            failed += 1
    
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print("Passed: {}/{}".format(passed, len(tests)))
    print("Failed: {}/{}".format(failed, len(tests)))
    
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
