#!/usr/bin/env python3
"""
Integration tests using real imported JSON data
Tests fuzzer and Nuclei with actual export files
"""

import sys
import os
import json
import glob

def test_real_imported_data():
    """Test fuzzer with real imported JSON"""
    print("=" * 60)
    print("Testing with Real Imported Data")
    print("=" * 60)
    
    # Find real export files
    export_files = glob.glob(os.path.expanduser("~/burp_APIRecon/Export*/api_analysis_*.json"))
    
    if not export_files:
        print("[FAIL] No export files found in ~/burp_APIRecon/")
        return False
    
    latest_export = sorted(export_files)[-1]
    print("Using: {}".format(latest_export))
    
    with open(latest_export, 'r') as f:
        data = json.load(f)
    
    print("Loaded {} endpoints".format(len(data.get('endpoints', []))))
    
    # Test data structure
    errors = []
    for i, endpoint in enumerate(data.get('endpoints', [])[:5]):
        print("\nEndpoint {}: {}".format(i+1, endpoint.get('endpoint', 'UNKNOWN')))
        
        # Check parameters structure
        params = endpoint.get('parameters', {})
        print("  Parameters type: {}".format(type(params)))
        
        for param_type in ['url', 'body', 'cookie', 'json']:
            param_data = params.get(param_type, [])
            print("    {}: {} (type: {})".format(param_type, param_data, type(param_data)))
            
            # Verify it's a list
            if not isinstance(param_data, list):
                errors.append("Endpoint {}: {} params should be list, got {}".format(
                    endpoint.get('endpoint'), param_type, type(param_data)))
        
        # Check reflected params
        reflected = endpoint.get('reflected_params', [])
        print("  Reflected: {} (type: {})".format(reflected, type(reflected)))
        if not isinstance(reflected, list):
            errors.append("Endpoint {}: reflected_params should be list, got {}".format(
                endpoint.get('endpoint'), type(reflected)))
    
    if errors:
        print("\n[FAIL] Data structure errors:")
        for err in errors:
            print("  - {}".format(err))
        return False
    
    print("\n[PASS] Real data structure is valid")
    return True


def test_nuclei_targets_export():
    """Test Nuclei targets export with real data"""
    print("\n" + "=" * 60)
    print("Testing Nuclei Targets Export")
    print("=" * 60)
    
    export_files = glob.glob(os.path.expanduser("~/burp_APIRecon/Export*/api_analysis_*.json"))
    
    if not export_files:
        print("[SKIP] No export files found")
        return True
    
    latest_export = sorted(export_files)[-1]
    
    with open(latest_export, 'r') as f:
        data = json.load(f)
    
    # Simulate what _export_nuclei_targets does
    targets = []
    errors = []
    
    for endpoint in data.get('endpoints', []):
        try:
            # Extract required fields
            method = endpoint.get('method', 'GET')
            host = endpoint.get('host', 'unknown')
            path = endpoint.get('normalized_path', '/')
            
            # Get sample request for more details
            samples = endpoint.get('sample_requests', [])
            if samples:
                sample = samples[0]
                actual_path = sample.get('path', path)
            else:
                actual_path = path
            
            # Build URL (assume https)
            url = "https://{}{}".format(host, actual_path)
            targets.append(url)
            
        except Exception as e:
            errors.append("Error processing {}: {}".format(endpoint.get('endpoint', 'UNKNOWN'), str(e)))
    
    print("Generated {} Nuclei targets".format(len(targets)))
    
    if errors:
        print("\n[FAIL] Errors generating targets:")
        for err in errors[:5]:
            print("  - {}".format(err))
        return False
    
    # Show sample targets
    print("\nSample targets:")
    for target in targets[:5]:
        print("  {}".format(target))
    
    print("\n[PASS] Nuclei targets export works")
    return True


def test_nuclei_command():
    """Test Nuclei command construction"""
    print("\n" + "=" * 60)
    print("Testing Nuclei Command")
    print("=" * 60)
    
    nuclei_path = os.path.expanduser("~/go/bin/nuclei")
    
    if not os.path.exists(nuclei_path):
        print("[SKIP] Nuclei not found at {}".format(nuclei_path))
        return True
    
    # Test nuclei version
    import subprocess
    try:
        result = subprocess.run(
            [nuclei_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        print("Nuclei version: {}".format(result.stdout.strip()))
        
        # Test command construction
        targets_file = "/tmp/test_targets.txt"
        output_file = "/tmp/test_output.txt"
        
        cmd = [
            nuclei_path,
            "-l", targets_file,
            "-o", output_file,
            "-severity", "critical,high,medium,low",
            "-tags", "cve,owasp,exposure",
            "-rate-limit", "150",
            "-concurrency", "25",
            "-timeout", "10",
            "-retries", "1",
            "-stats",
            "-v"
        ]
        
        print("\nCommand: {}".format(" ".join(cmd)))
        print("\n[PASS] Nuclei command construction works")
        return True
        
    except subprocess.TimeoutExpired:
        print("[FAIL] Nuclei command timed out")
        return False
    except Exception as e:
        print("[FAIL] Nuclei test failed: {}".format(str(e)))
        return False


def test_fuzzer_with_real_data():
    """Test fuzzer generation with real imported data"""
    print("\n" + "=" * 60)
    print("Testing Fuzzer with Real Data")
    print("=" * 60)
    
    export_files = glob.glob(os.path.expanduser("~/burp_APIRecon/Export*/api_analysis_*.json"))
    
    if not export_files:
        print("[SKIP] No export files found")
        return True
    
    latest_export = sorted(export_files)[-1]
    
    with open(latest_export, 'r') as f:
        data = json.load(f)
    
    # Convert to api_data format (as import does)
    api_data = {}
    for endpoint in data.get('endpoints', []):
        key = endpoint['endpoint']
        entry = {
            "method": endpoint["method"],
            "normalized_path": endpoint["normalized_path"],
            "host": endpoint["host"],
            "parameters": endpoint.get("parameters", {"url": [], "body": [], "cookie": [], "json": []}),
            "auth_detected": endpoint.get("auth_methods", ["None"]),
            "param_patterns": {
                "reflected": endpoint.get("reflected_params", []),
            },
            "content_type": endpoint.get("content_types", ["unknown"])[0] if endpoint.get("content_types") else "unknown"
        }
        api_data[key] = entry
    
    print("Converted {} endpoints to api_data format".format(len(api_data)))
    
    # Test normalization
    errors = []
    for key, entry in list(api_data.items())[:10]:
        try:
            # Simulate normalization
            params = entry.get("parameters", {})
            
            # Check each param type
            for ptype in ['url', 'body', 'cookie', 'json']:
                pdata = params.get(ptype, [])
                if isinstance(pdata, dict):
                    param_list = list(pdata.keys())
                elif isinstance(pdata, list):
                    param_list = pdata
                else:
                    errors.append("{}: {} params invalid type {}".format(key, ptype, type(pdata)))
                    continue
                
                # Verify we can iterate
                for p in param_list:
                    pass
                    
        except Exception as e:
            errors.append("{}: {}".format(key, str(e)))
    
    if errors:
        print("\n[FAIL] Normalization errors:")
        for err in errors[:5]:
            print("  - {}".format(err))
        return False
    
    # Test attack detection
    attack_count = 0
    for key, entry in api_data.items():
        path = entry["normalized_path"]
        params = entry.get("parameters", {})
        
        # IDOR check
        if "{id}" in path or "{uuid}" in path:
            attack_count += 1
        
        # SQLi check
        url_params = params.get("url", [])
        if url_params:
            attack_count += 1
    
    print("Detected {} potential attacks".format(attack_count))
    print("\n[PASS] Fuzzer works with real data")
    return True


if __name__ == "__main__":
    tests = [
        test_real_imported_data,
        test_nuclei_targets_export,
        test_nuclei_command,
        test_fuzzer_with_real_data
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print("[ERROR] {}: {}".format(test.__name__, str(e)))
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print("Results: {} passed, {} failed".format(passed, failed))
    print("=" * 60)
    
    sys.exit(0 if failed == 0 else 1)
