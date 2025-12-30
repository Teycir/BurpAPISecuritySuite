#!/usr/bin/env python3
"""Run all tests"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_tests():
    print("=" * 80)
    print("RUNNING ALL TESTS")
    print("=" * 80)
    print()
    
    tests = [
        'test_fuzzer_logic',
        'test_real_data'
    ]
    
    passed = 0
    failed = 0
    
    for test_name in tests:
        try:
            print(f"\n{'=' * 80}")
            print(f"Running: {test_name}")
            print('=' * 80)
            module = __import__(test_name)
            
            # Run all test functions
            for attr in dir(module):
                if attr.startswith('test_'):
                    func = getattr(module, attr)
                    if callable(func):
                        func()
            
            passed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
    
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
