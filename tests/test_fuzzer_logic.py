#!/usr/bin/env python3
"""
Unit tests for BurpAPIRecon fuzzer logic
Tests the core fuzzing functions in isolation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MockCallbacks:
    """Mock Burp callbacks for testing"""
    def printError(self, msg):
        print("ERROR:", msg)
    
    def printOutput(self, msg):
        print("OUTPUT:", msg)


class FuzzerLogic:
    """Isolated fuzzer logic for testing"""
    def __init__(self):
        self._callbacks = MockCallbacks()
    
    def _normalize_param_list(self, param_data):
        """Convert params to list format (handles dict or list)"""
        if isinstance(param_data, dict):
            return list(param_data.keys())
        elif isinstance(param_data, list):
            return param_data
        return []
    
    def _normalize_endpoint_data(self, entry):
        """Normalize endpoint data to consistent format"""
        params = entry.get("parameters", {})
        param_patterns = entry.get("param_patterns", {})
        
        return {
            "path": entry["normalized_path"],
            "method": entry["method"],
            "auth": entry.get("auth_detected", []),
            "params": {
                "url": self._normalize_param_list(params.get("url", [])),
                "body": self._normalize_param_list(params.get("body", [])),
                "json": self._normalize_param_list(params.get("json", [])),
                "cookie": self._normalize_param_list(params.get("cookie", []))
            },
            "reflected": param_patterns.get("reflected", []) if isinstance(param_patterns, dict) else [],
            "content_type": entry.get("content_type", "")
        }
    
    def _check_idor(self, normalized, attack_type):
        """Check if endpoint is vulnerable to IDOR"""
        if attack_type not in ["IDOR", "All"]:
            return None
        path = normalized["path"]
        if "{id}" not in path and "{uuid}" not in path:
            return None
        return {
            "type": "IDOR/BOLA",
            "test": "Sequential enumeration",
            "risk": "Access other users' resources"
        }
    
    def _check_sqli(self, normalized, attack_type):
        """Check if endpoint has SQLi potential"""
        if attack_type not in ["SQLi", "All"]:
            return None
        params = normalized["params"]
        if not params["url"] and not params["body"]:
            return None
        return {
            "type": "SQL Injection",
            "params": params["url"][:5] if params["url"] else [],
            "risk": "Database compromise"
        }
    
    def _check_xss(self, normalized, attack_type):
        """Check if endpoint has XSS potential"""
        if attack_type not in ["XSS", "All"]:
            return None
        if not normalized["reflected"]:
            return None
        return {
            "type": "XSS",
            "reflected": normalized["reflected"],
            "risk": "Client-side code execution"
        }
    
    def _generate_fuzzing_attacks(self, endpoints, attack_type):
        """Core fuzzing logic - pure function for testing"""
        attacks = []
        for key, entry in endpoints.items():
            try:
                normalized = self._normalize_endpoint_data(entry)
                checks = [
                    self._check_idor(normalized, attack_type),
                    self._check_sqli(normalized, attack_type),
                    self._check_xss(normalized, attack_type)
                ]
                for attack in checks:
                    if attack:
                        attacks.append((key, attack))
            except Exception as e:
                self._callbacks.printError("Error processing {}: {}".format(key, str(e)))
        return attacks


def test_normalize_param_list():
    """Test parameter normalization"""
    fuzzer = FuzzerLogic()
    
    # Test dict format (live capture)
    assert fuzzer._normalize_param_list({"id": "123", "name": "test"}) == ["id", "name"]
    
    # Test list format (imported)
    assert fuzzer._normalize_param_list(["id", "name"]) == ["id", "name"]
    
    # Test empty
    assert fuzzer._normalize_param_list([]) == []
    assert fuzzer._normalize_param_list({}) == []
    
    # Test invalid
    assert fuzzer._normalize_param_list(None) == []
    assert fuzzer._normalize_param_list("invalid") == []
    
    print("[PASS] test_normalize_param_list")


def test_normalize_endpoint_data_imported():
    """Test endpoint normalization with imported JSON format"""
    fuzzer = FuzzerLogic()
    
    # Imported format (lists)
    entry = {
        "normalized_path": "/api/users/{id}",
        "method": "GET",
        "auth_detected": ["Bearer Token"],
        "parameters": {
            "url": ["id", "filter"],
            "body": [],
            "json": [],
            "cookie": ["session"]
        },
        "param_patterns": {
            "reflected": ["filter"]
        },
        "content_type": "application/json"
    }
    
    normalized = fuzzer._normalize_endpoint_data(entry)
    
    assert normalized["path"] == "/api/users/{id}"
    assert normalized["method"] == "GET"
    assert normalized["auth"] == ["Bearer Token"]
    assert normalized["params"]["url"] == ["id", "filter"]
    assert normalized["params"]["cookie"] == ["session"]
    assert normalized["reflected"] == ["filter"]
    assert normalized["content_type"] == "application/json"
    
    print("[PASS] test_normalize_endpoint_data_imported")


def test_normalize_endpoint_data_live():
    """Test endpoint normalization with live capture format"""
    fuzzer = FuzzerLogic()
    
    # Live capture format (dicts)
    entry = {
        "normalized_path": "/api/users/{id}",
        "method": "GET",
        "auth_detected": ["Bearer Token"],
        "parameters": {
            "url": {"id": "123", "filter": "active"},
            "body": {},
            "json": {},
            "cookie": {"session": "abc123"}
        },
        "param_patterns": {
            "reflected": ["filter"]
        },
        "content_type": "application/json"
    }
    
    normalized = fuzzer._normalize_endpoint_data(entry)
    
    assert normalized["path"] == "/api/users/{id}"
    assert set(normalized["params"]["url"]) == {"id", "filter"}
    assert set(normalized["params"]["cookie"]) == {"session"}
    
    print("[PASS] test_normalize_endpoint_data_live")


def test_check_idor():
    """Test IDOR detection"""
    fuzzer = FuzzerLogic()
    
    # Positive case
    normalized = {
        "path": "/api/users/{id}",
        "method": "GET",
        "auth": ["Bearer Token"],
        "params": {"url": ["id"], "body": [], "json": [], "cookie": []},
        "reflected": [],
        "content_type": ""
    }
    
    result = fuzzer._check_idor(normalized, "All")
    assert result is not None
    assert result["type"] == "IDOR/BOLA"
    
    result = fuzzer._check_idor(normalized, "IDOR")
    assert result is not None
    
    # Negative case - no ID in path
    normalized["path"] = "/api/users"
    result = fuzzer._check_idor(normalized, "All")
    assert result is None
    
    # Negative case - wrong attack type
    normalized["path"] = "/api/users/{id}"
    result = fuzzer._check_idor(normalized, "SQLi")
    assert result is None
    
    print("[PASS] test_check_idor")


def test_check_sqli():
    """Test SQLi detection"""
    fuzzer = FuzzerLogic()
    
    # Positive case - URL params
    normalized = {
        "path": "/api/search",
        "method": "GET",
        "auth": [],
        "params": {"url": ["q", "filter"], "body": [], "json": [], "cookie": []},
        "reflected": [],
        "content_type": ""
    }
    
    result = fuzzer._check_sqli(normalized, "All")
    assert result is not None
    assert result["type"] == "SQL Injection"
    assert "q" in result["params"]
    
    # Positive case - body params
    normalized["params"]["url"] = []
    normalized["params"]["body"] = ["username", "password"]
    result = fuzzer._check_sqli(normalized, "SQLi")
    assert result is not None
    
    # Negative case - no params
    normalized["params"]["body"] = []
    result = fuzzer._check_sqli(normalized, "All")
    assert result is None
    
    print("[PASS] test_check_sqli")


def test_check_xss():
    """Test XSS detection"""
    fuzzer = FuzzerLogic()
    
    # Positive case
    normalized = {
        "path": "/search",
        "method": "GET",
        "auth": [],
        "params": {"url": ["q"], "body": [], "json": [], "cookie": []},
        "reflected": ["q"],
        "content_type": "text/html"
    }
    
    result = fuzzer._check_xss(normalized, "All")
    assert result is not None
    assert result["type"] == "XSS"
    assert "q" in result["reflected"]
    
    # Negative case - no reflected params
    normalized["reflected"] = []
    result = fuzzer._check_xss(normalized, "All")
    assert result is None
    
    print("[PASS] test_check_xss")


def test_generate_fuzzing_attacks():
    """Test full attack generation"""
    fuzzer = FuzzerLogic()
    
    endpoints = {
        "GET:/api/users/{id}": {
            "normalized_path": "/api/users/{id}",
            "method": "GET",
            "auth_detected": ["Bearer Token"],
            "parameters": {"url": ["id"], "body": [], "json": [], "cookie": []},
            "param_patterns": {"reflected": []},
            "content_type": "application/json"
        },
        "GET:/search": {
            "normalized_path": "/search",
            "method": "GET",
            "auth_detected": ["None"],
            "parameters": {"url": ["q", "page"], "body": [], "json": [], "cookie": []},
            "param_patterns": {"reflected": ["q"]},
            "content_type": "text/html"
        }
    }
    
    attacks = fuzzer._generate_fuzzing_attacks(endpoints, "All")
    
    # Should find IDOR, SQLi, and XSS
    assert len(attacks) >= 3
    
    attack_types = [a[1]["type"] for a in attacks]
    assert "IDOR/BOLA" in attack_types
    assert "SQL Injection" in attack_types
    assert "XSS" in attack_types
    
    print("[PASS] test_generate_fuzzing_attacks")


def test_mixed_data_formats():
    """Test handling of mixed imported and live data"""
    fuzzer = FuzzerLogic()
    
    endpoints = {
        # Imported format (lists)
        "GET:/api/v1/users": {
            "normalized_path": "/api/v1/users",
            "method": "GET",
            "auth_detected": ["None"],
            "parameters": {
                "url": ["page", "limit"],
                "body": [],
                "json": [],
                "cookie": []
            },
            "param_patterns": {"reflected": []},
            "content_type": "application/json"
        },
        # Live format (dicts)
        "POST:/api/v1/login": {
            "normalized_path": "/api/v1/login",
            "method": "POST",
            "auth_detected": ["None"],
            "parameters": {
                "url": {},
                "body": {"username": "admin", "password": "pass"},
                "json": {},
                "cookie": {}
            },
            "param_patterns": {"reflected": []},
            "content_type": "application/json"
        }
    }
    
    attacks = fuzzer._generate_fuzzing_attacks(endpoints, "All")
    
    # Should handle both formats without errors
    assert len(attacks) >= 2
    
    print("[PASS] test_mixed_data_formats")


def test_real_imported_json():
    """Test with real imported JSON data from actual export"""
    import json
    import glob
    
    fuzzer = FuzzerLogic()
    
    # Find real export files
    export_files = glob.glob(os.path.expanduser("~/burp_APIRecon/Export*/api_analysis_*.json"))
    
    if not export_files:
        print("[SKIP] test_real_imported_json - No export files found")
        return
    
    # Use most recent export
    latest_export = sorted(export_files)[-1]
    print("  Testing with: {}".format(os.path.basename(latest_export)))
    
    with open(latest_export, 'r') as f:
        data = json.load(f)
    
    # Convert to api_data format (as import does)
    endpoints = {}
    for endpoint in data.get('endpoints', []):
        key = endpoint['endpoint']
        # Simulate import structure
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
        endpoints[key] = entry
    
    print("  Loaded {} endpoints from real export".format(len(endpoints)))
    
    # Test normalization on all real endpoints
    errors = 0
    for key, entry in endpoints.items():
        try:
            normalized = fuzzer._normalize_endpoint_data(entry)
            # Verify structure
            assert "path" in normalized
            assert "method" in normalized
            assert "params" in normalized
            assert isinstance(normalized["params"]["url"], list)
            assert isinstance(normalized["params"]["body"], list)
            assert isinstance(normalized["params"]["cookie"], list)
        except Exception as e:
            print("  ERROR on {}: {}".format(key, str(e)))
            errors += 1
    
    assert errors == 0, "Failed to normalize {} endpoints".format(errors)
    
    # Test attack generation on real data
    attacks = fuzzer._generate_fuzzing_attacks(endpoints, "All")
    print("  Generated {} attacks from real data".format(len(attacks)))
    
    # Verify attacks have correct structure
    for key, attack in attacks:
        assert "type" in attack
        assert "risk" in attack
    
    print("[PASS] test_real_imported_json - {} endpoints, {} attacks".format(len(endpoints), len(attacks)))


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Running Fuzzer Logic Tests")
    print("=" * 60)
    
    tests = [
        test_normalize_param_list,
        test_normalize_endpoint_data_imported,
        test_normalize_endpoint_data_live,
        test_check_idor,
        test_check_sqli,
        test_check_xss,
        test_generate_fuzzing_attacks,
        test_mixed_data_formats
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print("[FAIL] {}: {}".format(test.__name__, str(e)))
            failed += 1
        except Exception as e:
            print("[ERROR] {}: {}".format(test.__name__, str(e)))
            failed += 1
    
    print("=" * 60)
    print("Results: {} passed, {} failed".format(passed, failed))
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
