# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Capture normalization, export pipelines, and external-tool control helpers."""
import json
import os
import re
import shlex
import threading
import time
import ai_prep_layer
import behavior_analysis
import heavy_runners
import jython_size_helpers
import recon_param_intel

from java.awt import BorderLayout, Color, Dimension, FlowLayout, Font, GridLayout
from java.awt.event import MouseAdapter
from java.io import File, FileWriter
from java.net import URL
from java.text import SimpleDateFormat
from java.util import ArrayList, Date
from javax.swing import (
    BorderFactory,
    Box,
    BoxLayout,
    DefaultListModel,
    JButton,
    JCheckBox,
    JColorChooser,
    JComboBox,
    JFileChooser,
    JLabel,
    JList,
    JMenuItem,
    JOptionPane,
    JPanel,
    JPopupMenu,
    JScrollPane,
    JSplitPane,
    JTabbedPane,
    JTextArea,
    JTextField,
    ListCellRenderer,
    SwingUtilities,
    ToolTipManager,
)
from javax.swing.event import DocumentListener, ListSelectionListener

def _extract_body(self, message, offset):
    try:
        if not message or offset < 0:
            return ""
        body_bytes = message[offset : offset + self.max_body_size]
        body = self._helpers.bytesToString(body_bytes)
        if len(body) > self.max_body_size:
            body = body[: self.max_body_size] + "... [truncated]"
        return body
    except Exception as e:
        self._callbacks.printError("Body extraction error: " + str(e))
        return ""

def _truncate_body_text_by_max_size(self, body_text):
    """Clamp plain-text body content to the configured capture size."""
    text = self._ascii_safe(body_text or "")
    try:
        cap = int(getattr(self, "max_body_size", 15000) or 15000)
    except (TypeError, ValueError):
        cap = 15000
    if cap < 5000:
        cap = 5000
    if cap > 15000:
        cap = 15000
    if len(text) > cap:
        return text[:cap] + "... [truncated]"
    return text

def _get_content_type(self, resp_info):
    for header in resp_info.getHeaders()[:30]:
        if header.lower().startswith("content-type:"):
            return header.split(":", 1)[1].strip()
    return "unknown"

def _detect_auth(self, req_info):
    auth_types = []
    for header in req_info.getHeaders()[1:30]:
        lower = header.lower()
        if "authorization:" in lower:
            if "bearer" in lower:
                auth_types.append("Bearer Token")
            elif "basic" in lower:
                auth_types.append("Basic Auth")
            else:
                auth_types.append("Custom Auth")
        elif "x-api-key:" in lower:
            auth_types.append("API Key")
        elif "cookie:" in lower:
            auth_types.append("Session Cookie")
    return auth_types if auth_types else ["None"]

def _extract_jwt(self, req_info):
    """Extract and decode JWT tokens from Authorization header, cookies, params, and body"""
    import base64
    import binascii

    def decode_jwt(token):
        try:
            parts = token.strip().split(".")
            if len(parts) != 3:
                return None
            header_data = base64.urlsafe_b64decode(parts[0] + "===")
            payload_data = base64.urlsafe_b64decode(parts[1] + "===")
            return {
                "raw": token,
                "header": json.loads(header_data),
                "payload": json.loads(payload_data),
                "signature": parts[2],
                "location": ""
            }
        except (ValueError, TypeError, binascii.Error):
            return None
        except Exception as e:
            self._callbacks.printError(
                "JWT decode unexpected error: {}".format(str(e))
            )
            return None

    # Check Authorization header
    for header in req_info.getHeaders()[1:30]:
        if "authorization:" in header.lower():
            if "bearer" in header.lower():
                token = header.split(" ")[-1]
                jwt = decode_jwt(token)
                if jwt:
                    jwt["location"] = "Authorization: Bearer"
                    return jwt

    # Check cookies
    for param in req_info.getParameters():
        if param.getType() == self.PARAM_COOKIE:
            token = param.getValue() or ""
            if token.count(".") == 2:
                jwt = decode_jwt(token)
                if jwt:
                    jwt["location"] = "Cookie: {}".format(param.getName())
                    return jwt

    # Check URL params
    for param in req_info.getParameters():
        if param.getType() == self.PARAM_URL:
            name = (param.getName() or "").lower()
            if "token" in name or "jwt" in name or "auth" in name:
                token = param.getValue() or ""
                jwt = decode_jwt(token)
                if jwt:
                    jwt["location"] = "URL param: {}".format(param.getName())
                    return jwt

    return None

def _detect_encryption(self, req_body, resp_body, headers):
    indicators = {"likely_encrypted": False, "types": [], "evidence": []}
    req_body = req_body or ""
    resp_body = resp_body or ""
    combined = req_body + resp_body
    if self.BASE64_PATTERN.search(combined):
        indicators["types"].append("Base64")
    if self.HEX_PATTERN.search(combined):
        indicators["types"].append("Hex")
    for key in headers:
        if any(
            x in key.lower() for x in ["encryption", "cipher", "signature", "hash"]
        ):
            indicators["types"].append("Custom Header")
            break
    if any(x in combined.lower() for x in ["encrypted", "cipher", "hmac"]):
        indicators["types"].append("Keyword")
    indicators["likely_encrypted"] = len(indicators["types"]) > 0
    return indicators

def _analyze_param_patterns(self, req_info, req_body, resp_body):
    patterns = {"param_types": {}, "reflected": []}
    resp_body = resp_body or ""
    for param in req_info.getParameters()[:50]:
        name = param.getName() or ""
        value = param.getValue() or ""
        if value and re.match(r"^\d+$", value):
            patterns["param_types"][name] = "numeric"
        elif value and re.match(r"^[0-9a-f-]{36}$", value):
            patterns["param_types"][name] = "uuid"
        elif value and re.match(r"^[A-Za-z0-9+/=]{20,}$", value):
            patterns["param_types"][name] = "base64"
        elif value and re.match(r"^[0-9a-f]{32,}$", value):
            patterns["param_types"][name] = "hash"
        if value and len(value) > 3 and value in resp_body:
            patterns["reflected"].append(name)
    return patterns

def _detect_api_patterns(self, path, content_type, response_body):
    patterns = []
    response_body = response_body or ""
    content_type = content_type or ""

    # REST patterns
    if any(x in path.lower() for x in ["/api/", "/v1/", "/v2/", "/rest/"]):
        patterns.append("REST API")

    # GraphQL
    if "/graphql" in path.lower():
        patterns.append("GraphQL")

    # SOAP
    if "<soap:" in response_body.lower() or "<wsdl:" in response_body.lower():
        patterns.append("SOAP")

    # JSON API
    if "json" in content_type.lower():
        patterns.append("JSON API")

    # XML API
    if "xml" in content_type.lower():
        patterns.append("XML API")

    return patterns if patterns else ["Unknown"]

def export_api_data(self):
    if not self.api_data:
        self.log_to_ui("[!] No API data to export")
        return

    timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
    self.log_to_ui("[*] Starting export at {}...".format(timestamp))

    with self.lock:
        data_snapshot = dict(self.api_data)

    # Generate comprehensive analysis
    analysis = {
        "metadata": {
            "timestamp": timestamp,
            "total_endpoints": len(data_snapshot),
            "total_requests": sum(len(v) for v in data_snapshot.values()),
        },
        "endpoints": [],
        "api_structure": self._analyze_structure_for(data_snapshot),
        "security_observations": self._analyze_security(data_snapshot),
        "llm_prompt": self._generate_llm_prompt(),
    }

    for endpoint_key, entries in data_snapshot.items():
        entry = self._get_entry(entries)
        entries_list = entries if isinstance(entries, list) else [entries]
        endpoint_summary = {
            "endpoint": endpoint_key,
            "method": entry["method"],
            "normalized_path": entry["normalized_path"],
            "host": entry["host"],
            "sample_count": len(entries_list),
            "parameters": self._merge_params(entries_list),
            "auth_methods": list(
                set([a for e in entries_list for a in e["auth_detected"]])
            ),
            "response_codes": list(
                set([e["response_status"] for e in entries_list])
            ),
            "content_types": list(set([e["content_type"] for e in entries_list])),
            "api_patterns": list(
                set([p for e in entries_list for p in e["api_patterns"]])
            ),
            "avg_response_length": sum(e["response_length"] for e in entries_list)
            / len(entries_list),
            "jwt_claims": entry.get("jwt_detected"),
            "encryption_detected": any(
                e.get("encryption_indicators", {}).get("likely_encrypted")
                for e in entries_list
            ),
            "encryption_types": list(
                set(
                    [
                        t
                        for e in entries_list
                        for t in e.get("encryption_indicators", {}).get("types", [])
                    ]
                )
            ),
            "reflected_params": list(
                set(
                    [
                        p
                        for e in entries_list
                        for p in e.get("param_patterns", {}).get("reflected", [])
                    ]
                )
            ),
            "param_type_summary": self._summarize_param_types(entries_list),
            "sample_requests": [self._format_sample(e) for e in entries_list[:3]],
        }
        analysis["endpoints"].append(endpoint_summary)

    # Export to file
    import os

    export_dir = self._get_export_dir("FullExport")
    if not export_dir:
        self.log_to_ui("[!] Cannot create export directory")
        return

    self.log_to_ui("[*] Analyzing {} endpoints...".format(len(data_snapshot)))

    # Count severities
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for key, entries in data_snapshot.items():
        sev = self._get_severity(key, entries)
        severity_counts[sev] += 1

    filename = os.path.join(export_dir, "api_analysis.json")
    writer = None
    try:
        writer = FileWriter(filename)
        writer.write(json.dumps(analysis, indent=2))
        self.log_to_ui(
            "[+] Export complete: {} endpoints, {} requests".format(
                analysis["metadata"]["total_endpoints"],
                analysis["metadata"]["total_requests"],
            )
        )
        self.log_to_ui(
            "[+] Severity: Critical={}, High={}, Medium={}, Info={}".format(
                severity_counts["critical"],
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["info"],
            )
        )
        self.log_to_ui(
            "[+] Security observations: {}".format(
                len(analysis["security_observations"])
            )
        )
        self.log_to_ui("[+] Folder: {}".format(export_dir))
        self.log_to_ui("[+] File: {}".format(filename))
    except (IOError, TypeError) as e:
        self.log_to_ui("[!] Export failed: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError("Error closing file: " + str(e))

def _merge_params(self, entries):
    merged = {"url": set(), "body": set(), "cookie": set(), "json": set()}
    for entry in entries:
        for ptype, params in entry.get("parameters", {}).items():
            if isinstance(params, dict):
                merged[ptype].update(params.keys())
            elif isinstance(params, list):
                merged[ptype].update(params)
    return {k: list(v) for k, v in merged.items()}

def _format_sample(self, entry):
    return {
        "method": entry.get("method", ""),
        "path": entry.get("path", ""),
        "query": entry.get("query_string", ""),
        "headers": entry.get("headers", {}),
        "request_body": (entry.get("request_body") or "")[:500],
        "response_status": entry.get("response_status", 200),
        "response_body": (entry.get("response_body") or "")[:500],
    }

def _summarize_param_types(self, entries):
    summary = {}
    for entry in entries:
        for pname, ptype in (
            entry.get("param_patterns", {}).get("param_types", {}).items()
        ):
            if pname not in summary:
                summary[pname] = set()
            summary[pname].add(ptype)
    return {k: list(v)[0] if len(v) == 1 else list(v) for k, v in summary.items()}

def _analyze_structure(self):
    structure = {
        "api_types": set(),
        "http_methods": set(),
        "auth_methods": set(),
        "base_paths": set(),
    }
    for entries in self.api_data.values():
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            structure["http_methods"].add(entry.get("method", ""))
            structure["auth_methods"].update(entry.get("auth_detected", []))
            structure["api_types"].update(entry.get("api_patterns", []))
            path = entry.get("normalized_path", "")
            if path.startswith("/api/"):
                structure["base_paths"].add("/api/")
            elif path.startswith("/v1/"):
                structure["base_paths"].add("/v1/")
    return {k: list(v) for k, v in structure.items()}

def _check_endpoints(self, check_func):
    """Helper to check endpoints and return matches"""
    matches = []
    for endpoint_key, entries in self.api_data.items():
        if check_func(endpoint_key, entries):
            matches.append(endpoint_key)
    return matches

def _add_observation(
    self, observations, matches, obs_type, severity, recommendation=None
):
    """Helper to add observation if matches found"""
    if matches:
        obs = {
            "type": obs_type,
            "severity": severity,
            "count": len(matches),
            "examples": matches[:5],
        }
        if recommendation:
            obs["recommendation"] = recommendation
        observations.append(obs)

def _analyze_security(self, data_snapshot=None):
    observations = []

    if data_snapshot is None:
        with self.lock:
            data_snapshot = dict(self.api_data)
    else:
        data_snapshot = dict(data_snapshot)

    normalized_snapshot = {}
    for key, entries in data_snapshot.items():
        if isinstance(entries, list):
            entries_list = [x for x in entries if isinstance(x, dict)]
        elif isinstance(entries, dict):
            entries_list = [entries]
        else:
            entries_list = []
        if entries_list:
            normalized_snapshot[key] = entries_list

    # Process snapshot without holding lock
    def check_snapshot(check_func):
        matches = []
        for key, entries in normalized_snapshot.items():
            if check_func(key, entries):
                matches.append(key)
        return matches

    # Unprotected endpoints
    self._add_observation(
        observations,
        check_snapshot(lambda k, e: any("None" in x["auth_detected"] for x in e)),
        "Unauthenticated Endpoints",
        "High",
    )

    # IDOR/BOLA
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: len(e) > 0
            and re.search(r"/{id}|/{uuid}|/\d+", e[0]["normalized_path"])
        ),
        "Potential IDOR/BOLA",
        "Critical",
        "Implement object-level authorization checks",
    )

    # Sensitive data
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                any(
                    p
                    in (
                        (x.get("request_body") or "")
                        + (x.get("response_body") or "")
                    ).lower()
                    for p in [
                        "password",
                        "token",
                        "secret",
                        "key",
                        "credit",
                        "ssn",
                        "email",
                        "phone",
                    ]
                )
                for x in e
            )
        ),
        "Sensitive Data Detected",
        "High",
        "Encrypt sensitive data and use proper masking",
    )

    # PII in URLs
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                re.search(
                    r"email=|phone=|ssn=|credit",
                    (x.get("query_string") or "").lower(),
                )
                for x in e
            )
        ),
        "PII in URL Parameters",
        "High",
        "Move PII to request body with POST method",
    )

    # Verbose errors
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                any(
                    x in (entry.get("response_body") or "").lower()
                    for x in [
                        "stack trace",
                        "exception",
                        "sql",
                        "debug",
                        "traceback",
                    ]
                )
                for entry in e
            )
        ),
        "Verbose Error Messages",
        "Medium",
        "Implement generic error messages for production",
    )

    # Error responses
    error_endpoints = [
        (
            k,
            list(
                set(
                    [
                        x.get("response_status", 200)
                        for x in e
                        if x.get("response_status", 200) >= 400
                    ]
                )
            ),
        )
        for k, e in normalized_snapshot.items()
        if any(x.get("response_status", 200) >= 400 for x in e)
    ]
    if error_endpoints:
        observations.append(
            {
                "type": "Error Responses Detected",
                "severity": "Info",
                "count": len(error_endpoints),
                "examples": error_endpoints[:5],
            }
        )

    # Weak encryption
    weak_enc = [
        {
            "endpoint": k,
            "types": list(
                set(
                    [
                        t
                        for x in e
                        for t in x.get("encryption_indicators", {}).get("types", [])
                    ]
                )
            ),
        }
        for k, e in normalized_snapshot.items()
        if any(
            x.get("encryption_indicators", {}).get("likely_encrypted")
            and "Base64" in x.get("encryption_indicators", {}).get("types", [])
            for x in e
        )
    ]
    if weak_enc:
        observations.append(
            {
                "type": "Weak Encryption (Base64)",
                "severity": "High",
                "count": len(weak_enc),
                "examples": weak_enc[:5],
                "recommendation": "Use proper encryption (AES-256, TLS 1.3)",
            }
        )

    # Rate limiting
    self._add_observation(
        observations,
        check_snapshot(lambda k, e: len(e) >= 3),
        "Potential Missing Rate Limiting",
        "Medium",
        "Implement rate limiting and throttling",
    )

    # CORS
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                (
                    x.get("response_headers", {}).get(
                        "Access-Control-Allow-Origin", ""
                    )
                    == "*"
                    or "null"
                    in x.get("response_headers", {})
                    .get("Access-Control-Allow-Origin", "")
                    .lower()
                )
                for x in e
            )
        ),
        "CORS Misconfiguration",
        "High",
        "Restrict CORS to specific origins, avoid wildcards",
    )

    # Security headers
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                not any(
                    h in x.get("response_headers", {})
                    for h in [
                        "X-Content-Type-Options",
                        "X-Frame-Options",
                        "Content-Security-Policy",
                    ]
                )
                for x in e
            )
        ),
        "Missing Security Headers",
        "Medium",
        "Add X-Content-Type-Options, X-Frame-Options, CSP headers",
    )

    # HTTP method misuse
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                x.get("method") == "GET" and x.get("request_body") for x in e
            )
        ),
        "HTTP Method Misuse",
        "Medium",
        "Use POST/PUT for requests with body data",
    )

    # Mass assignment
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                any(
                    p in (x.get("request_body") or "").lower()
                    for p in [
                        '"role"',
                        '"admin"',
                        '"isadmin"',
                        '"permissions"',
                        '"privileges"',
                    ]
                )
                for x in e
            )
        ),
        "Mass Assignment Risk",
        "High",
        "Whitelist allowed fields, reject unexpected parameters",
    )

    # Debug endpoints
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: len(e) > 0
            and any(
                p in e[0]["normalized_path"].lower()
                for p in [
                    "/debug",
                    "/test",
                    "/admin",
                    "/swagger",
                    "/api-docs",
                    "/.env",
                    "/config",
                ]
            )
        ),
        "Debug/Admin Endpoints Exposed",
        "Critical",
        "Remove or properly secure debug/admin endpoints",
    )

    # Injection patterns
    self._add_observation(
        observations,
        check_snapshot(
            lambda k, e: any(
                re.search(
                    r"(select|union|insert|delete|drop|exec|script|<|>|\.\.)",
                    str(x.get("parameters", {})),
                    re.IGNORECASE,
                )
                for x in e
            )
        ),
        "Injection Pattern Detected",
        "Critical",
        "Implement input validation and parameterized queries",
    )

    return observations

def _generate_llm_prompt(self):
    return """# API Red Team Extension Generation

## Context
This JSON contains comprehensive API traffic analysis from a Burp Suite scan/capture session.

## Your Task
Analyze this API data and generate a custom Burp Suite extension in Jython that:

### 1. IDOR/BOLA Testing
- For endpoints with {id}, {uuid} patterns, test:
  * Sequential ID enumeration (1,2,3...)
  * UUID manipulation
  * Negative IDs and boundary values
  * Other user's resource access

### 2. Authentication/Authorization
- Test missing/invalid tokens
- Session fixation attacks
- JWT manipulation (alg:none, weak secrets)
- Privilege escalation attempts
- Cookie tampering

### 3. Parameter Manipulation
- Mass assignment (add admin=true, role=admin)
- Type confusion (string->int, array->object)
- SQL injection in all parameters
- NoSQL injection for JSON APIs
- Command injection in file paths
- XXE for XML endpoints

### 4. Business Logic
- Negative quantities/prices
- Race conditions on state changes
- Workflow bypass (skip payment steps)
- Rate limiting bypass

### 5. Encryption/Encoding
- Base64 decode/encode attacks
- Padding oracle attacks
- Replay attacks on encrypted data
- Weak crypto detection

### 6. Information Disclosure
- Verbose error messages
- Stack traces
- Debug endpoints
- API version disclosure

### 7. Injection Attacks
- Test reflected_params for XSS
- SSTI in template parameters
- LDAP injection
- XML injection

## Output Format
Generate a complete Burp extension that:
- Extends IBurpExtender, IScannerCheck
- Implements doPassiveScan (info gathering) and doActiveScan (exploitation)
- Returns IScanIssue objects with:
  * Severity: Critical/High/Medium/Low/Info
  * Confidence: Certain/Firm/Tentative
  * Detailed description with proof
  * Remediation advice
- Handles all detected patterns from security_observations
- Includes attack payloads specific to this API
- Provides clear documentation and usage instructions

## API Data Analysis Below
"""

def _get_export_dir(self, export_type="Export"):
    import os

    timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
    path = os.path.join(
        os.path.expanduser("~"),
        "burp_APIRecon",
        "{}_{}".format(export_type, timestamp),
    )
    try:
        f = File(path)
        if f.mkdirs() or f.exists():
            return path
    except Exception as e:
        self._callbacks.printError(
            "Failed to create directory {}: {}".format(path, str(e))
        )
    return None

def clear_data(self):
    with self.lock:
        count = len(self.api_data)
        self.api_data.clear()
        self.endpoint_tags.clear()
        self.endpoint_times.clear()
        self.recon_hidden_param_results = []
        self.recon_param_intel_snapshot = None
    logger_cleared = int(self._clear_logger_logs(emit_log=False) or 0)
    with self.sequence_invariant_lock:
        self.sequence_invariant_findings = []
        self.sequence_invariant_ledger = {}
        self.sequence_invariant_meta = {}
    with self.golden_ticket_lock:
        self.golden_ticket_findings = []
        self.golden_ticket_ledger = {}
        self.golden_ticket_meta = {}
    with self.state_transition_lock:
        self.state_transition_findings = []
        self.state_transition_ledger = {}
        self.state_transition_meta = {}
    with self.token_lineage_lock:
        self.token_lineage_findings = []
        self.token_lineage_ledger = {}
        self.token_lineage_meta = {}
    with self.parity_drift_lock:
        self.parity_drift_findings = []
        self.parity_drift_ledger = {}
        self.parity_drift_meta = {}
    with self.counterfactual_lock:
        self.counterfactual_findings = []
        self.counterfactual_summary = {}
        self.counterfactual_meta = {}
    with self.advanced_logic_lock:
        self.advanced_logic_packages = {}
    self.list_model.clear()
    if hasattr(self, "_recon_set_detail_redirect_text"):
        self._recon_set_detail_redirect_text(None)
    else:
        self.details_area.setText("")
    self._callbacks.setExtensionName("API Recon")
    self.log_to_ui(
        "[+] Cleared {} endpoints and {} logger events".format(count, logger_cleared)
    )
    SwingUtilities.invokeLater(
        lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
    )
    SwingUtilities.invokeLater(lambda: self._update_host_filter())
    SwingUtilities.invokeLater(lambda: self._update_stats())
    SwingUtilities.invokeLater(lambda: self.refresh_view())
    SwingUtilities.invokeLater(lambda: self._refresh_recon_invariant_status_label())

def _auto_tag(self, entry):
    tags = set()
    path = self._ascii_safe(
        entry.get("normalized_path") or entry.get("path") or "/", lower=True
    )
    method = self._ascii_safe(entry.get("method") or "GET").upper()
    request_body = self._ascii_safe(entry.get("request_body") or "", lower=True)
    response_body = self._ascii_safe(entry.get("response_body") or "", lower=True)
    headers = entry.get("headers", {}) or {}
    header_keys = [self._ascii_safe(k, lower=True) for k in headers.keys()]
    header_values = [self._ascii_safe(v, lower=True) for v in headers.values()]
    content_type = self._ascii_safe(entry.get("content_type") or "", lower=True)
    auth_detected = [self._ascii_safe(x, lower=True) for x in entry.get("auth_detected", [])]

    has_api_hint = (
        "/api/" in path
        or path.startswith("/v1/")
        or path.startswith("/v2/")
        or "/graphql" in path
        or "json" in content_type
    )
    if has_api_hint:
        tags.add("api_endpoint")
    if any(marker in path for marker in ["/auth", "/login", "/token"]) or (
        "authorization" in header_keys
    ):
        tags.add("auth")
    if (
        "{id}" in path
        or "{uuid}" in path
        or "{objectid}" in path
        or re.search(r"/[0-9]+(?:/|$)", path)
    ):
        tags.add("idor_risk")
    if any(token in response_body for token in ["password", "token", "secret", "api_key", "credit"]):
        tags.add("sensitive")
    if method in ["POST", "PUT", "PATCH", "DELETE"]:
        tags.add("write_ops")
    if entry.get("jwt_detected") or any("bearer" in value for value in header_values):
        tags.add("jwt")
    if any(marker in path for marker in ["/admin", "/debug", "/test", "/.env", "/swagger"]):
        tags.add("admin_debug")
    if has_api_hint and ("none" in auth_detected or not auth_detected):
        tags.add("no_auth")

    if entry.get("encryption_indicators", {}).get("likely_encrypted"):
        tags.add("encrypted")
    if "none" not in auth_detected:
        tags.add("authenticated")
    else:
        tags.add("public")
    if entry.get("response_status", 200) >= 400:
        tags.add("error")
    if entry.get("param_patterns", {}).get("reflected"):
        tags.add("reflected")
    return sorted(tags)

def _get_severity(self, key, entries):
    """Determine severity level for endpoint highlighting"""
    entry = self._get_entry(entries)
    path = entry["normalized_path"]

    # Critical
    if any(
        p in path.lower() for p in ["/debug", "/test", "/admin", "/.env", "/config"]
    ):
        return "critical"
    if re.search(r"/{id}|/{uuid}", path) and "None" in entry["auth_detected"]:
        return "critical"

    # High
    if re.search(r"/{id}|/{uuid}", path):
        return "high"
    if "None" in entry["auth_detected"]:
        return "high"
    if any(
        p
        in (entry.get("request_body", "") + entry.get("response_body", "")).lower()
        for p in ["password", "token", "secret"]
    ):
        return "high"
    if entry.get("encryption_indicators", {}).get(
        "likely_encrypted"
    ) and "Base64" in entry.get("encryption_indicators", {}).get("types", []):
        return "high"

    # Medium
    if entry.get("response_status", 200) >= 400:
        return "medium"
    if entry.get("param_patterns", {}).get("reflected"):
        return "medium"

    return "info"

def _get_recon_entry_tool(self, entry):
    """Get normalized source tool label for one captured entry."""
    tool_name = self._ascii_safe((entry or {}).get("source_tool") or "").strip()
    return tool_name if tool_name else "Unknown"

def _entry_matches_recon_regex(self, entry, regex_obj, scope_label):
    """Check whether one capture sample matches Recon regex scope."""
    scope = self._ascii_safe(scope_label or "Any", lower=True).strip()
    if scope not in ["any", "request", "response", "req+resp"]:
        scope = "any"

    targets = []
    if scope in ["any", "request", "req+resp"]:
        req_parts = []
        req_parts.append(
            "{} {}".format(
                self._ascii_safe(entry.get("method") or "").upper(),
                self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/"),
            )
        )
        req_parts.append(self._ascii_safe(entry.get("query_string") or ""))
        req_parts.append(self._ascii_safe(entry.get("request_body") or "")[:8000])
        req_parts.append(
            json.dumps(entry.get("headers", {}) or {}, sort_keys=True)
        )
        targets.append("\n".join(req_parts))

    if scope in ["any", "response", "req+resp"]:
        resp_parts = []
        resp_parts.append("status={}".format(int(entry.get("response_status", 0) or 0)))
        resp_parts.append(self._ascii_safe(entry.get("response_body") or "")[:8000])
        resp_parts.append(
            json.dumps(entry.get("response_headers", {}) or {}, sort_keys=True)
        )
        targets.append("\n".join(resp_parts))

    for text in targets:
        if regex_obj.search(text):
            return True
    return False

def _endpoint_matches_recon_regex(self, entries, regex_obj, scope_label):
    """Check regex against all stored samples for an endpoint."""
    entries_list = entries if isinstance(entries, list) else [entries]
    for sample in entries_list:
        if self._entry_matches_recon_regex(sample, regex_obj, scope_label):
            return True
    return False

def _sync_noise_filter_checkboxes(self, source="recon"):
    """Keep Recon and Logger noise toggles aligned in both directions."""
    if getattr(self, "_syncing_noise_filter_controls", False):
        return False

    recon_box = getattr(self, "recon_noise_filter_checkbox", None)
    logger_box = getattr(self, "logger_noise_filter_checkbox", None)
    if (recon_box is None) and (logger_box is None):
        return False

    source_key = self._ascii_safe(source or "recon", lower=True).strip()
    selected = bool(getattr(self, "recon_noise_filter_enabled", True))
    if source_key == "logger":
        if logger_box is not None:
            selected = bool(logger_box.isSelected())
        elif recon_box is not None:
            selected = bool(recon_box.isSelected())
    else:
        if recon_box is not None:
            selected = bool(recon_box.isSelected())
        elif logger_box is not None:
            selected = bool(logger_box.isSelected())

    changed = False
    self._syncing_noise_filter_controls = True
    try:
        if (recon_box is not None) and (recon_box.isSelected() != selected):
            recon_box.setSelected(selected)
            changed = True
        if (logger_box is not None) and (logger_box.isSelected() != selected):
            logger_box.setSelected(selected)
            changed = True
    finally:
        self._syncing_noise_filter_controls = False

    recon_before = bool(getattr(self, "recon_noise_filter_enabled", True))
    logger_before = bool(getattr(self, "logger_noise_filter_enabled", True))
    self.recon_noise_filter_enabled = selected
    self.logger_noise_filter_enabled = selected
    if (recon_before != selected) or (logger_before != selected):
        changed = True
    return changed

def _has_high_signal_tags(self, tags):
    """Return True when tags include high-signal security findings."""
    keep_tags = set(["admin_debug", "jwt"])
    for raw in list(tags or []):
        safe_tag = self._ascii_safe(raw, lower=True).strip()
        if safe_tag and safe_tag in keep_tags:
            return True
    return False

def _recon_entry_is_noise(self, entry, endpoint_tags=None):
    """Heuristic noise detector for Recon/Logger filtering."""
    if not isinstance(entry, dict):
        return False

    tag_values = list(endpoint_tags or [])
    if self._has_high_signal_tags(tag_values):
        return False

    method = self._ascii_safe(entry.get("method") or "GET").upper().strip()
    host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
    path = self._ascii_safe(
        entry.get("path") or entry.get("normalized_path") or "/", lower=True
    ).strip()
    content_type = self._ascii_safe(entry.get("content_type") or "", lower=True).strip()

    first_part = ""
    parts = [p for p in path.strip("/").split("/") if p]
    if parts:
        first_part = parts[0]

    host_noise = False
    if hasattr(self, "_ffuf_is_noise_host"):
        host_noise = bool(self._ffuf_is_noise_host(host))
    if hasattr(self, "_is_wayback_noise_host"):
        host_noise = bool(host_noise or self._is_wayback_noise_host(host))
    extra_noise_host_markers = (
        "googletagmanager.com",
        "googleadservices.com",
        "googlesyndication.com",
        "doubleclick.net",
        "ad4m.at",
        "batch.com",
        "ampproject.org",
        "acuityplatform.com",
        "33across.com",
        "indexww.com",
        "liadm.com",
        "deepintent.com",
        "onetag-sys.com",
    )
    if any(marker in host for marker in extra_noise_host_markers):
        host_noise = True

    path_noise = False
    if hasattr(self, "_path_contains_noise_marker"):
        path_noise = bool(
            self._path_contains_noise_marker(path, self.FUZZER_STRICT_NOISE_PATH_MARKERS)
            or self._path_contains_noise_marker(path, self.PARAM_MINER_NOISE_PATH_MARKERS)
        )
    if path.endswith(self.PASSIVE_STATIC_EXTENSIONS):
        path_noise = True
    if first_part and hasattr(self, "_ffuf_is_noise_path_segment"):
        if self._ffuf_is_noise_path_segment(first_part):
            path_noise = True
    if first_part and first_part in getattr(self, "FUZZER_STATIC_PATH_PARTS", ()):
        path_noise = True

    type_noise = bool(
        ("javascript" in content_type)
        or ("ecmascript" in content_type)
        or ("text/css" in content_type)
        or content_type.startswith("image/")
        or content_type.startswith("font/")
        or content_type.startswith("video/")
        or content_type.startswith("audio/")
    )

    api_signal = bool(
        ("/api/" in path)
        or ("/graphql" in path)
        or ("/rest/" in path)
        or ("/openapi" in path)
        or ("/swagger" in path)
        or re.match(r"^/v\d+(?:\.\d+)?(?:/|$)", path)
    )

    if not (host_noise or path_noise or type_noise):
        return False
    if api_signal and (not host_noise):
        return False
    if api_signal and method in ["POST", "PUT", "PATCH", "DELETE"] and (not host_noise):
        return False
    return True

def _endpoint_is_recon_noise(self, endpoint_key, entries, endpoint_tags_snapshot=None):
    """Return True when all samples for one endpoint are noisy."""
    entries_list = entries if isinstance(entries, list) else [entries]
    if endpoint_tags_snapshot is None:
        endpoint_tags_snapshot = getattr(
            self, "_recon_filter_endpoint_tags_snapshot", None
        )
    if isinstance(endpoint_tags_snapshot, dict):
        endpoint_tags = list(endpoint_tags_snapshot.get(endpoint_key, []) or [])
    else:
        endpoint_tags = list(self.endpoint_tags.get(endpoint_key, []) or [])
    if self._has_high_signal_tags(endpoint_tags):
        return False
    has_sample = False
    for sample in entries_list:
        if not isinstance(sample, dict):
            continue
        has_sample = True
        if not self._recon_entry_is_noise(sample, endpoint_tags):
            return False
    return has_sample

def _logger_extract_tag_tokens(self, raw_text):
    """Parse logger tags safely from plain CSV or legacy HTML-tagged strings."""
    text = self._ascii_safe(raw_text or "", lower=True).strip()
    if not text:
        return []
    text = (
        text.replace("\r", " ")
        .replace("\n", " ")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
    )
    if "<" in text or ">" in text:
        text = re.sub(r"<[^>]*>", " ", text)
    text = re.sub(r"(?i)\b(tags|primary)\s*:\s*", " ", text)
    text = re.sub(r"[^a-z0-9_-]+", " ", text)
    stop_tokens = set(
        [
            "html",
            "span",
            "style",
            "color",
            "background",
            "background-color",
            "padding",
            "border",
            "radius",
            "nbsp",
            "tags",
            "primary",
            "none",
        ]
    )
    tokens = []
    seen = set()
    for raw_piece in text.split():
        token = self._ascii_safe(raw_piece or "", lower=True).strip(" \t\r\n'\"()[]{}")
        if not token:
            continue
        if token in stop_tokens:
            continue
        if re.match(r"^[0-9a-f]{3,8}$", token):
            continue
        if token.isdigit():
            continue
        if token not in seen:
            seen.add(token)
            tokens.append(token)
        if len(tokens) >= 30:
            break
    return tokens

def _logger_event_is_noise(self, event):
    """Logger-event wrapper for shared Recon noise heuristics."""
    if not isinstance(event, dict):
        return False
    tags = self._logger_extract_tag_tokens(event.get("tags") or event.get("base_tags") or "")
    pseudo_entry = {
        "method": self._ascii_safe(event.get("method") or "GET").upper().strip(),
        "host": self._ascii_safe(event.get("host") or "", lower=True).strip(),
        "path": self._ascii_safe(event.get("path") or "/", lower=True),
        "content_type": self._ascii_safe(event.get("inferred_type") or "", lower=True),
    }
    return self._recon_entry_is_noise(pseudo_entry, endpoint_tags=tags)

def _filter_endpoints(self):
    search = self._ascii_safe(self.search_field.getText() or "", lower=True)
    method = str(self.method_filter.getSelectedItem())
    host = str(self.host_filter.getSelectedItem())
    severity = str(self.severity_filter.getSelectedItem())
    tag = str(self.tag_filter.getSelectedItem())
    tool = str(self.tool_filter.getSelectedItem())
    host_lower = self._ascii_safe(host, lower=True)
    tag_lower = self._ascii_safe(tag, lower=True)
    noise_filter_enabled = bool(getattr(self, "recon_noise_filter_enabled", True))
    noise_box = getattr(self, "recon_noise_filter_checkbox", None)
    if noise_box is not None:
        noise_filter_enabled = bool(noise_box.isSelected())
    self.recon_noise_filter_enabled = noise_filter_enabled
    regex_text = self._ascii_safe(self.recon_regex_field.getText() or "").strip()
    regex_scope = str(self.recon_regex_scope_combo.getSelectedItem())
    regex_obj = None
    if regex_text:
        try:
            regex_obj = re.compile(regex_text, re.IGNORECASE | re.MULTILINE)
            self._recon_last_regex_error = ""
        except re.error as regex_err:
            err_msg = self._ascii_safe(regex_err)
            if err_msg != self._recon_last_regex_error:
                self._recon_last_regex_error = err_msg
                self.log_to_ui("[!] Recon regex invalid: {}".format(err_msg))
            regex_obj = None
    filtered = {}
    with self.lock:
        data_snapshot = list(self.api_data.items())
        endpoint_tags_snapshot = dict(self.endpoint_tags)
    setattr(self, "_recon_filter_endpoint_tags_snapshot", endpoint_tags_snapshot)
    try:
        for key, entries in data_snapshot:
            entry = self._get_entry(entries)
            entry_host = self._ascii_safe(entry.get("host") or "", lower=True)
            if (
                search
                and search not in key.lower()
                and search not in entry_host
            ):
                continue
            if method != "All" and not key.startswith(method + ":"):
                continue
            if host != "All" and entry_host != host_lower:
                continue
            if (
                severity != "All"
                and self._get_severity(key, entries) != severity.lower()
            ):
                continue
            if noise_filter_enabled and self._endpoint_is_recon_noise(key, entries):
                continue
            if tag != "All":
                tags = endpoint_tags_snapshot.get(key, []) or []
                if not any(self._ascii_safe(t, lower=True) == tag_lower for t in tags):
                    continue
            entries_list = entries if isinstance(entries, list) else [entries]
            if tool != "All":
                if not any(self._get_recon_entry_tool(item) == tool for item in entries_list):
                    continue
            if regex_obj is not None:
                if not self._endpoint_matches_recon_regex(entries_list, regex_obj, regex_scope):
                    continue
            filtered[key] = entries
    finally:
        setattr(self, "_recon_filter_endpoint_tags_snapshot", None)
    return filtered

def _on_filter_change(self):
    if getattr(self, "_syncing_noise_filter_controls", False):
        return
    noise_toggle_changed = self._sync_noise_filter_checkboxes(source="recon")
    self.refresh_view()
    if noise_toggle_changed:
        self._refresh_logger_view()

def _persist_recon_filter_library(self):
    """Persist saved Recon filter profiles."""
    with self.lock:
        library_snapshot = list(getattr(self, "recon_filter_library", []) or [])
    serializable = []
    for item in library_snapshot:
        if not isinstance(item, dict):
            continue
        alias = self._ascii_safe(item.get("alias") or "").strip()
        string_filter = self._ascii_safe(item.get("string_filter") or "").strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        regex_scope = self._ascii_safe(item.get("regex_scope") or "Any").strip()
        if (not alias) or ((not string_filter) and (not regex_text)):
            continue
        if regex_scope not in ["Any", "Request", "Response", "Req+Resp"]:
            regex_scope = "Any"
        serializable.append(
            {
                "alias": alias[:80],
                "string_filter": string_filter[:120],
                "regex": regex_text[:400],
                "regex_scope": regex_scope,
            }
        )
        if len(serializable) >= 200:
            break
    try:
        payload = json.dumps(serializable)
    except (TypeError, ValueError) as json_err:
        self._callbacks.printError(
            "Recon filter-library persistence encode failed: {}".format(str(json_err))
        )
        return
    self._save_text_setting("recon_filter_library_json", payload)

def _restore_recon_filter_library(self):
    """Restore saved Recon filter profiles from extension settings."""
    raw_payload = self._load_text_setting("recon_filter_library_json", "").strip()
    if not raw_payload:
        with self.lock:
            self.recon_filter_library = []
        self._recon_filter_library_signature = ()
        self._refresh_recon_filter_library_combo()
        return
    try:
        parsed = json.loads(raw_payload)
    except (TypeError, ValueError) as json_err:
        self._callbacks.printError(
            "Recon filter-library persistence decode failed: {}".format(str(json_err))
        )
        return
    if not isinstance(parsed, list):
        return
    cleaned = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        alias = self._ascii_safe(item.get("alias") or "").strip()
        string_filter = self._ascii_safe(item.get("string_filter") or "").strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        regex_scope = self._ascii_safe(item.get("regex_scope") or "Any").strip()
        if regex_scope not in ["Any", "Request", "Response", "Req+Resp"]:
            regex_scope = "Any"
        if (not alias) or ((not string_filter) and (not regex_text)):
            continue
        if regex_text:
            try:
                re.compile(regex_text, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
        cleaned.append(
            {
                "alias": alias[:80],
                "string_filter": string_filter[:120],
                "regex": regex_text[:400],
                "regex_scope": regex_scope,
            }
        )
        if len(cleaned) >= 200:
            break
    with self.lock:
        self.recon_filter_library = cleaned
    self._recon_filter_library_signature = ()
    self._refresh_recon_filter_library_combo()
    combo = getattr(self, "recon_filter_library_combo", None)
    if combo is not None:
        desired = self._load_text_setting("combo.recon_filter_library_combo", "").strip()
        if desired and self._combo_contains_item(combo, desired):
            self._syncing_recon_controls = True
            try:
                combo.setSelectedItem(desired)
            finally:
                self._syncing_recon_controls = False

def _refresh_recon_filter_library_combo(self):
    """Refresh Recon saved-filter dropdown from persisted library."""
    combo = getattr(self, "recon_filter_library_combo", None)
    if combo is None:
        return
    with self.lock:
        entries = list(getattr(self, "recon_filter_library", []) or [])
    aliases = []
    for item in entries:
        alias = self._ascii_safe(item.get("alias") or "").strip()
        if alias:
            aliases.append(alias)
    aliases_signature = tuple(aliases)
    cached_signature = tuple(getattr(self, "_recon_filter_library_signature", ()) or ())
    selected = self._ascii_safe(
        str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else ""
    )
    if cached_signature == aliases_signature:
        if (not aliases) and selected != "(No Saved Filters)":
            self._syncing_recon_controls = True
            try:
                combo.setSelectedItem("(No Saved Filters)")
            finally:
                self._syncing_recon_controls = False
        elif aliases and selected and selected not in aliases:
            self._syncing_recon_controls = True
            try:
                combo.setSelectedItem(aliases[0])
            finally:
                self._syncing_recon_controls = False
        return
    self._syncing_recon_controls = True
    try:
        combo.removeAllItems()
        if not aliases:
            combo.addItem("(No Saved Filters)")
        else:
            for alias in aliases:
                combo.addItem(alias)
        if selected:
            combo.setSelectedItem(selected)
        self._recon_filter_library_signature = aliases_signature
    finally:
        self._syncing_recon_controls = False

def _save_recon_filter(self):
    """Save current Recon filter profile as named entry."""
    string_filter = ""
    if getattr(self, "search_field", None) is not None:
        string_filter = self._ascii_safe(self.search_field.getText() or "")
    string_filter = string_filter.strip()
    regex_text = ""
    if getattr(self, "recon_regex_field", None) is not None:
        regex_text = self._ascii_safe(self.recon_regex_field.getText() or "")
    regex_text = regex_text.strip()
    regex_scope = "Any"
    if getattr(self, "recon_regex_scope_combo", None) is not None:
        regex_scope = self._ascii_safe(
            str(self.recon_regex_scope_combo.getSelectedItem()) or "Any"
        ).strip()
    if regex_scope not in ["Any", "Request", "Response", "Req+Resp"]:
        regex_scope = "Any"
    if (not string_filter) and (not regex_text):
        self.log_to_ui("[!] Recon: set String Filter and/or Regex Filter before saving")
        return
    if regex_text:
        try:
            re.compile(regex_text, re.IGNORECASE | re.MULTILINE)
        except re.error as regex_err:
            self.log_to_ui("[!] Recon invalid regex: {}".format(str(regex_err)))
            return
    alias = JOptionPane.showInputDialog(
        self._panel, "Filter name:", "Save Recon Filter", JOptionPane.PLAIN_MESSAGE
    )
    alias = self._ascii_safe(alias or "").strip()
    if not alias:
        return
    with self.lock:
        library = list(getattr(self, "recon_filter_library", []) or [])
        library = [
            item
            for item in library
            if self._ascii_safe(item.get("alias") or "", lower=True)
            != self._ascii_safe(alias, lower=True)
        ]
        library.append(
            {
                "alias": alias,
                "string_filter": string_filter,
                "regex": regex_text,
                "regex_scope": regex_scope,
            }
        )
        library = sorted(
            library,
            key=lambda item: self._ascii_safe(item.get("alias") or "", lower=True),
        )[:200]
        self.recon_filter_library = library
    self._persist_recon_filter_library()
    self._refresh_recon_filter_library_combo()
    combo = getattr(self, "recon_filter_library_combo", None)
    if combo is not None:
        combo.setSelectedItem(alias)
    self.log_to_ui("[+] Recon saved filter '{}'".format(alias))

def _apply_recon_filter(self):
    """Apply selected saved Recon filter profile."""
    combo = getattr(self, "recon_filter_library_combo", None)
    if combo is None:
        return
    alias = self._ascii_safe(
        str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else ""
    ).strip()
    if (not alias) or alias == "(No Saved Filters)":
        return
    string_filter = ""
    regex_text = ""
    regex_scope = "Any"
    with self.lock:
        for item in list(getattr(self, "recon_filter_library", []) or []):
            if (
                self._ascii_safe(item.get("alias") or "", lower=True)
                == self._ascii_safe(alias, lower=True)
            ):
                string_filter = self._ascii_safe(item.get("string_filter") or "")
                regex_text = self._ascii_safe(item.get("regex") or "")
                regex_scope = self._ascii_safe(item.get("regex_scope") or "Any").strip()
                break
    if (not string_filter) and (not regex_text):
        self.log_to_ui("[!] Recon: selected filter is empty")
        return
    if getattr(self, "search_field", None) is not None:
        self.search_field.setText(string_filter)
    if getattr(self, "recon_regex_field", None) is not None:
        self.recon_regex_field.setText(regex_text)
    if getattr(self, "recon_regex_scope_combo", None) is not None:
        if regex_scope not in ["Any", "Request", "Response", "Req+Resp"]:
            regex_scope = "Any"
        self.recon_regex_scope_combo.setSelectedItem(regex_scope)
    self._on_filter_change()

def _remove_recon_filter(self):
    """Remove selected saved Recon filter profile."""
    combo = getattr(self, "recon_filter_library_combo", None)
    if combo is None:
        return
    alias = self._ascii_safe(
        str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else ""
    ).strip()
    if (not alias) or alias == "(No Saved Filters)":
        return
    with self.lock:
        library = list(getattr(self, "recon_filter_library", []) or [])
        original = len(library)
        library = [
            item
            for item in library
            if self._ascii_safe(item.get("alias") or "", lower=True)
            != self._ascii_safe(alias, lower=True)
        ]
        self.recon_filter_library = library
    self._persist_recon_filter_library()
    self._refresh_recon_filter_library_combo()
    if len(library) < original:
        self.log_to_ui("[*] Recon removed filter '{}'".format(alias))

def _clear_recon_filters(self):
    """Clear active Recon filter inputs (does not remove saved filters)."""
    if getattr(self, "search_field", None) is not None:
        self.search_field.setText("")
    if getattr(self, "recon_regex_field", None) is not None:
        self.recon_regex_field.setText("")
    if getattr(self, "recon_regex_scope_combo", None) is not None:
        self.recon_regex_scope_combo.setSelectedItem("Any")
    combo = getattr(self, "recon_filter_library_combo", None)
    if combo is not None and self._combo_contains_item(combo, "(No Saved Filters)"):
        self._syncing_recon_controls = True
        try:
            combo.setSelectedItem("(No Saved Filters)")
        finally:
            self._syncing_recon_controls = False
    self._on_filter_change()
    self.log_to_ui("[*] Recon filters cleared")

def _on_group_change(self):
    group = str(self.group_by.getSelectedItem())
    self.log_to_ui("[*] Grouping changed: {}".format(group))
    self.refresh_view()

def _on_refresh(self):
    self.refresh_view()
    self.log_to_ui("[*] View refreshed")

def _prev_page(self):
    if self.current_page > 0:
        self.current_page -= 1
        self.refresh_view()

def _next_page(self):
    if self.current_page < self.total_pages - 1:
        self.current_page += 1
        self.refresh_view()

def _change_page_size(self):
    self.page_size = int(str(self.page_size_combo.getSelectedItem()))
    self.current_page = 0
    self.refresh_view()

def refresh_view(self):
    try:
        filtered = self._filter_endpoints()
        with self.lock:
            tags_snapshot = dict(self.endpoint_tags)

        # Calculate pagination
        total_items = len(filtered)
        self.total_pages = max(1, (total_items + self.page_size - 1) // self.page_size)
        if self.current_page >= self.total_pages:
            self.current_page = max(0, self.total_pages - 1)

        start_idx = self.current_page * self.page_size
        end_idx = min(start_idx + self.page_size, total_items)

        # Update pagination controls
        self.page_label.setText("{}/{}".format(self.current_page + 1, self.total_pages))
        self.prev_page_btn.setEnabled(self.current_page > 0)
        self.next_page_btn.setEnabled(self.current_page < self.total_pages - 1)

        # Batch UI updates - build all rows first, then update UI once
        rows_to_add = []
        group_by = str(self.group_by.getSelectedItem())

        if group_by == "None":
            sorted_keys = sorted(filtered.keys())
            page_keys = sorted_keys[start_idx:end_idx]
            for key in page_keys:
                tags = tags_snapshot.get(key, [])
                tag_str = " [{}]".format(",".join(tags)) if tags else ""
                entries = filtered[key]
                entry = self._get_entry(entries)
                count = len(entries) if isinstance(entries, list) else 1
                rows_to_add.append(
                    (
                        "[{}x] {} @ {}{}".format(count, key, entry["host"], tag_str),
                        key,
                    )
                )
        else:
            groups = self._group_endpoints(filtered, group_by)
            item_count = 0
            for group_name in sorted(groups.keys()):
                if item_count >= end_idx:
                    break
                if item_count >= start_idx:
                    rows_to_add.append(("=== {} ===".format(group_name), None))
                item_count += 1
                for key in sorted(groups[group_name]):
                    if item_count >= end_idx:
                        break
                    if item_count >= start_idx:
                        tags = tags_snapshot.get(key, [])
                        tag_str = " [{}]".format(",".join(tags)) if tags else ""
                        entries = filtered[key]
                        entry = self._get_entry(entries)
                        count = len(entries) if isinstance(entries, list) else 1
                        rows_to_add.append(
                            (
                                "  [{}x] {} @ {}{}".format(
                                    count, key, entry["host"], tag_str
                                ),
                                key,
                            )
                        )
                    item_count += 1

        # Single UI update
        self.list_model.clear()
        view_keys = []
        for item_text, endpoint_key in rows_to_add:
            self.list_model.addElement(item_text)
            view_keys.append(endpoint_key)
        with self.lock:
            self.recon_view_keys = list(view_keys)

        if int(self.list_model.getSize() or 0) <= 0:
            endpoint_list = getattr(self, "endpoint_list", None)
            if endpoint_list is not None:
                endpoint_list.clearSelection()

    except Exception as e:
        self._callbacks.printError("Refresh view error: " + str(e))

def _group_endpoints(self, endpoints, group_by):
    groups = {}
    for key, entries in endpoints.items():
        entry = self._get_entry(entries)
        if group_by == "Host":
            group_name = entry["host"]
        elif group_by == "Method":
            group_name = entry["method"]
        elif group_by == "Auth":
            auth = entry["auth_detected"]
            group_name = auth[0] if auth else "None"
        elif group_by == "Encryption":
            enc = entry.get("encryption_indicators", {}).get("likely_encrypted")
            group_name = "Encrypted" if enc else "Plain"
        else:
            group_name = "Other"

        if group_name not in groups:
            groups[group_name] = []
        groups[group_name].append(key)
    return groups

def _update_tab_title(self):
    """Update tab title with count"""
    count = len(self.api_data)
    self._callbacks.setExtensionName(
        "API Security Suite"
        if count == 0
        else "API Security Suite ({})".format(count)
    )

def _update_stats(self):
    """Update statistics panel"""
    with self.lock:
        total = len(self.api_data)
        hosts = len(set(self._get_entry(e)["host"] for e in self.api_data.values()))
        severity_counts = {"critical": 0, "high": 0, "medium": 0}
        for key, entries in self.api_data.items():
            sev = self._get_severity(key, entries)
            if sev in severity_counts:
                severity_counts[sev] += 1

    self.stats_label.setText(
        "Endpoints: {} | Critical: {} | High: {} | Medium: {} | Hosts: {}".format(
            total,
            severity_counts["critical"],
            severity_counts["high"],
            severity_counts["medium"],
            hosts,
        )
    )

def _update_host_filter(self):
    """Update host filter dropdown"""
    with self.lock:
        hosts = sorted(
            set(self._get_entry(e)["host"] for e in self.api_data.values())
        )
    current = str(self.host_filter.getSelectedItem())
    self.host_filter.removeAllItems()
    self.host_filter.addItem("All")
    for host in hosts:
        self.host_filter.addItem(host)
    if current in hosts or current == "All":
        self.host_filter.setSelectedItem(current)
    self._update_tool_filter()
    self._update_tag_filter()

def _update_tool_filter(self):
    """Update source tool filter dropdown from captured entries."""
    tool_combo = getattr(self, "tool_filter", None)
    if tool_combo is None:
        return

    with self.lock:
        tool_names = set()
        for entries in self.api_data.values():
            entries_list = entries if isinstance(entries, list) else [entries]
            for entry in entries_list:
                tool_names.add(self._get_recon_entry_tool(entry))
    sorted_tools = sorted(tool_names)

    current = str(tool_combo.getSelectedItem())
    tool_combo.removeAllItems()
    tool_combo.addItem("All")
    for tool_name in sorted_tools:
        tool_combo.addItem(tool_name)
    if current in sorted_tools or current == "All":
        tool_combo.setSelectedItem(current)

def _update_tag_filter(self):
    """Update tag filter dropdown from endpoint tags."""
    tag_combo = getattr(self, "tag_filter", None)
    if tag_combo is None:
        return

    with self.lock:
        tags = set()
        for values in self.endpoint_tags.values():
            for tag in values or []:
                safe_tag = self._ascii_safe(tag, lower=True).strip()
                if safe_tag:
                    tags.add(safe_tag)
    sorted_tags = sorted(tags)

    current = str(tag_combo.getSelectedItem())
    tag_combo.removeAllItems()
    tag_combo.addItem("All")
    for tag in sorted_tags:
        tag_combo.addItem(tag)
    if current in sorted_tags or current == "All":
        tag_combo.setSelectedItem(current)

def _schedule_capture_ui_refresh(self, force=False):
    """Debounce expensive Recon UI refresh work during bursty captures."""
    timer = None
    with self.lock:
        if force and self._capture_ui_refresh_timer is not None:
            try:
                self._capture_ui_refresh_timer.cancel()
            except Exception as cancel_err:
                self._callbacks.printError(
                    "Capture UI refresh cancel error: {}".format(str(cancel_err))
                )
            self._capture_ui_refresh_timer = None

        if self._capture_ui_refresh_timer is not None:
            return

        now = time.time()
        elapsed_ms = int((now - self._capture_ui_refresh_last_ts) * 1000)
        delay_ms = 0
        if not force:
            delay_ms = max(
                0, int(self._capture_ui_refresh_min_interval_ms - elapsed_ms)
            )

        def _queue_refresh():
            with self.lock:
                self._capture_ui_refresh_timer = None
                self._capture_ui_refresh_last_ts = time.time()
            SwingUtilities.invokeLater(lambda: self._run_capture_ui_refresh())

        timer = threading.Timer(delay_ms / 1000.0, _queue_refresh)
        timer.daemon = True
        self._capture_ui_refresh_timer = timer

    if timer is not None:
        timer.start()

def _run_capture_ui_refresh(self):
    """Apply a full Recon list/stats refresh on the EDT."""
    try:
        renderer = self.endpoint_list.getCellRenderer()
        if renderer:
            renderer.invalidate_cache()
        self._update_host_filter()
        self._update_stats()
        self.refresh_view()
    except Exception as e:
        self._callbacks.printError("Capture UI refresh error: {}".format(str(e)))

def _logger_apply_runtime_settings(self, schedule_refresh=True):
    """Apply logger runtime settings from UI controls."""
    max_rows = int(getattr(self, "logger_max_rows", 20000) or 20000)
    max_rows_combo = getattr(self, "logger_max_rows_combo", None)
    if max_rows_combo is not None:
        try:
            max_rows = int(str(max_rows_combo.getSelectedItem()))
        except (TypeError, ValueError):
            max_rows = int(getattr(self, "logger_max_rows", 20000) or 20000)
    if max_rows < 200:
        max_rows = 200
    if max_rows > 50000:
        max_rows = 50000

    auto_prune = bool(getattr(self, "logger_auto_prune_enabled", True))
    auto_prune_box = getattr(self, "logger_auto_prune_checkbox", None)
    if auto_prune_box is not None:
        auto_prune = bool(auto_prune_box.isSelected())

    capture_enabled = bool(getattr(self, "logger_capture_enabled", True))
    logging_off_box = getattr(self, "logger_logging_off_checkbox", None)
    logging_off_requested = bool(logging_off_box.isSelected()) if logging_off_box is not None else (not capture_enabled)
    capture_enabled = not logging_off_requested
    if logging_off_box is not None and logging_off_box.isSelected() != logging_off_requested:
        logging_off_box.setSelected(logging_off_requested)
    import_on_open = bool(getattr(self, "logger_import_on_open", True))
    import_box = getattr(self, "logger_import_on_open_checkbox", None)
    if import_box is not None:
        import_on_open = bool(import_box.isSelected())
    noise_filter_enabled = bool(getattr(self, "logger_noise_filter_enabled", True))
    noise_box = getattr(self, "logger_noise_filter_checkbox", None)
    if noise_box is None:
        noise_box = getattr(self, "recon_noise_filter_checkbox", None)
    if noise_box is not None:
        noise_filter_enabled = bool(noise_box.isSelected())

    with self.logger_lock:
        self.logger_max_rows = max_rows
        self.logger_trim_batch = max(100, int(max_rows * 0.1))
        self.logger_auto_prune_enabled = auto_prune
        self.logger_capture_enabled = capture_enabled
        self.logger_import_on_open = import_on_open
        self.logger_noise_filter_enabled = noise_filter_enabled
    self._logger_trim_if_needed(force=True)
    if schedule_refresh:
        self._schedule_logger_ui_refresh(force=True)

def _show_logger_help_popup(self):
    """Show quick help for Logger controls and workflows."""
    help_lines = [
        "Logger Quick Help",
        "",
        "- Logging Off: pause capture while keeping current rows visible.",
        "- Filter Noise is controlled from Recon and applies to Logger too.",
        "- Clear Data lives in Recon and clears shared Recon+Logger capture state.",
        "- Len >= / Len <=: filter visible rows by response length.",
        "- Grep Values...: regex search popup with request/response scope.",
        "- Tag Rules...: create custom regex tags (tag|scope|regex).",
        "- Show Last + Max Rows + Auto Prune: keep long sessions responsive.",
        "- Max Rows is configured from Recon top controls and applies to Logger runtime.",
        "- Auto Prune and Import on Open are configured from Recon top controls.",
        "- Use the '?' next to Recon Max Rows for detailed capacity guidance.",
        "",
        "Tip: right-click the table for bulk actions (select all, copy, send to repeater).",
    ]
    JOptionPane.showMessageDialog(
        self._panel,
        "\n".join(help_lines),
        "Logger Help",
        JOptionPane.INFORMATION_MESSAGE,
    )

def _show_logger_capacity_help_popup(self):
    """Explain the difference between Show Last and Max Rows controls."""
    lines = [
        "Logger Capacity Help",
        "=" * 56,
        "",
        "Show Last:",
        "  - View limit only (how many newest rows are rendered in table).",
        "  - Does not change capture retention.",
        "",
        "Max Rows:",
        "  - Memory retention limit (total rows Logger keeps).",
        "  - When reached, Logger prunes oldest duplicate rows first when possible.",
        "  - This keeps at least one anchor row per endpoint before deeper pruning.",
        "",
        "How they work together:",
        "  - Keep: up to Max Rows.",
        "  - Display: up to Show Last from that kept set.",
        "  - Effective visible rows are also reduced by active filters.",
        "",
        "Tuning tips:",
        "  - Lower Show Last if UI feels heavy while keeping history.",
        "  - Lower Max Rows if memory usage grows during long sessions.",
    ]
    JOptionPane.showMessageDialog(
        self._panel,
        "\n".join(lines),
        "Logger Capacity Help",
        JOptionPane.INFORMATION_MESSAGE,
    )

def _logger_trim_if_needed(self, force=False):
    """Trim logger events to keep memory bounded while preserving endpoint coverage."""
    with self.logger_lock:
        max_rows = int(getattr(self, "logger_max_rows", 20000) or 20000)
        auto_prune = bool(getattr(self, "logger_auto_prune_enabled", True))
        if (not force) and (not auto_prune):
            return 0
        total_rows = int(len(self.logger_events) or 0)
        overflow = total_rows - max_rows
        if overflow <= 0:
            return 0
        trim_batch = int(getattr(self, "logger_trim_batch", 500) or 500)
        drop_count = overflow if force else max(overflow, trim_batch)
        if drop_count > total_rows:
            drop_count = total_rows
        if drop_count <= 0:
            return 0

        events_snapshot = list(self.logger_events)
        endpoint_counts = {}
        endpoint_keys = []
        for event in events_snapshot:
            endpoint_key = self._ascii_safe(event.get("endpoint_key") or "").strip()
            if not endpoint_key:
                endpoint_key = "__no_endpoint__"
            endpoint_keys.append(endpoint_key)
            endpoint_counts[endpoint_key] = int(endpoint_counts.get(endpoint_key, 0) or 0) + 1

        # Pass 1: drop oldest duplicate rows first (keep at least one anchor row per endpoint).
        drop_indexes = set()
        for index, endpoint_key in enumerate(endpoint_keys):
            if len(drop_indexes) >= drop_count:
                break
            if endpoint_counts.get(endpoint_key, 0) > 1:
                drop_indexes.add(index)
                endpoint_counts[endpoint_key] = int(endpoint_counts.get(endpoint_key, 0) or 0) - 1

        # Pass 2: if still overflowing, drop oldest remaining rows.
        if len(drop_indexes) < drop_count:
            for index in range(len(events_snapshot)):
                if len(drop_indexes) >= drop_count:
                    break
                if index in drop_indexes:
                    continue
                drop_indexes.add(index)

        kept_events = [
            event for index, event in enumerate(events_snapshot) if index not in drop_indexes
        ]
        dropped = total_rows - len(kept_events)
        if dropped < 0:
            dropped = 0
        if dropped:
            if hasattr(self.logger_events, "popleft"):
                try:
                    self.logger_events = self.logger_events.__class__(kept_events)
                except (TypeError, ValueError):
                    self.logger_events = list(kept_events)
            else:
                self.logger_events = list(kept_events)
        drop_count = dropped
        self.logger_dropped_count = int(getattr(self, "logger_dropped_count", 0) or 0) + drop_count
        self.logger_last_prune_ts = time.strftime("%H:%M:%S")
    return drop_count

def _logger_effective_preview_caps(self):
    """Return adaptive request/response preview caps for current logger memory mode."""
    req_cap = int(getattr(self, "logger_request_preview_max", 1200) or 1200)
    resp_cap = int(getattr(self, "logger_response_preview_max", 2400) or 2400)
    max_rows = int(getattr(self, "logger_max_rows", 20000) or 20000)
    if max_rows >= 20000:
        req_cap = min(req_cap, 500)
        resp_cap = min(resp_cap, 900)
    elif max_rows >= 10000:
        req_cap = min(req_cap, 700)
        resp_cap = min(resp_cap, 1400)
    elif max_rows >= 5000:
        req_cap = min(req_cap, 1000)
        resp_cap = min(resp_cap, 2000)
    try:
        body_cap = int(getattr(self, "max_body_size", 15000) or 15000)
    except (TypeError, ValueError):
        body_cap = 15000
    if body_cap < 5000:
        body_cap = 5000
    if body_cap > 15000:
        body_cap = 15000
    # Keep logger request/response previews aligned with Recon max-body setting.
    req_cap = max(req_cap, body_cap)
    resp_cap = max(resp_cap, body_cap)
    req_cap = max(300, req_cap)
    resp_cap = max(500, resp_cap)
    return req_cap, resp_cap

def _logger_effective_header_preview_limit(self, side="request"):
    """Return adaptive per-event header preview count."""
    side_key = self._ascii_safe(side or "request", lower=True).strip()
    max_rows = int(getattr(self, "logger_max_rows", 20000) or 20000)
    if max_rows >= 20000:
        return 4 if side_key == "request" else 5
    if max_rows >= 10000:
        return 6
    return 8 if side_key == "request" else 10

def _sync_recon_entry_from_logger(self, endpoint_key, entry, tags=None):
    """Ensure logger-originated rows exist in Recon cache (deduped + bounded)."""
    if not endpoint_key or (not isinstance(entry, dict)):
        return False
    method = self._ascii_safe(entry.get("method") or "GET").upper().strip() or "GET"
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    normalized_path = self._ascii_safe(entry.get("normalized_path") or "").strip()
    if not normalized_path:
        normalized_path = self._normalize_path(path)
    query = self._ascii_safe(entry.get("query_string") or "")
    try:
        response_status = int(entry.get("response_status", 0) or 0)
    except (TypeError, ValueError):
        response_status = 0
    try:
        response_length = int(entry.get("response_length", 0) or 0)
    except (TypeError, ValueError):
        response_length = 0
    try:
        response_time_ms = int(entry.get("response_time_ms", 0) or 0)
    except (TypeError, ValueError):
        response_time_ms = 0
    if response_time_ms < 0:
        response_time_ms = 0

    entry_copy = dict(entry)
    entry_copy["method"] = method
    entry_copy["path"] = path
    entry_copy["normalized_path"] = normalized_path
    entry_copy["query_string"] = query
    entry_copy["response_status"] = response_status
    entry_copy["response_length"] = response_length
    entry_copy["response_time_ms"] = response_time_ms
    entry_copy["source_tool"] = self._ascii_safe(entry.get("source_tool") or "Logger")
    entry_copy["headers"] = dict(entry.get("headers") or {})
    entry_copy["response_headers"] = dict(entry.get("response_headers") or {})
    entry_copy["request_body"] = self._truncate_body_text_by_max_size(
        entry.get("request_body") or ""
    )
    entry_copy["response_body"] = self._truncate_body_text_by_max_size(
        entry.get("response_body") or ""
    )
    entry_copy["host"] = self._ascii_safe(entry.get("host") or "", lower=True).strip()
    entry_copy["protocol"] = self._ascii_safe(
        entry.get("protocol") or "https", lower=True
    ).strip() or "https"
    try:
        entry_copy["port"] = int(entry.get("port", 0) or 0)
    except (TypeError, ValueError):
        entry_copy["port"] = 0
    entry_copy["content_type"] = self._ascii_safe(
        entry.get("content_type") or entry.get("inferred_type") or ""
    )

    tag_values = []
    seen_tag_values = set()
    for raw_tag in list(tags or []):
        for clean_tag in self._logger_extract_tag_tokens(raw_tag):
            if clean_tag and (clean_tag not in seen_tag_values):
                seen_tag_values.add(clean_tag)
                tag_values.append(clean_tag)
    sample_limit = 3
    sample_combo = getattr(self, "sample_limit", None)
    if sample_combo is not None:
        try:
            sample_limit = int(str(sample_combo.getSelectedItem()))
        except (TypeError, ValueError):
            sample_limit = 3
    if sample_limit < 1:
        sample_limit = 1

    added = False
    with self.lock:
        if endpoint_key not in self.api_data:
            max_endpoints = int(getattr(self, "max_endpoints", 800) or 800)
            if len(self.api_data) >= max_endpoints:
                # Safety: avoid expensive rotation work from logger hot path/backfill.
                return False
            self.api_data[endpoint_key] = []
            self.endpoint_times[endpoint_key] = []
            self.endpoint_tags[endpoint_key] = []

        existing = self.api_data.get(endpoint_key, [])
        signature = (
            method,
            normalized_path,
            query,
            response_status,
            response_length,
        )
        has_same = False
        for row in existing:
            row_sig = (
                self._ascii_safe(row.get("method") or "GET").upper().strip(),
                self._ascii_safe(
                    row.get("normalized_path") or self._normalize_path(self._ascii_safe(row.get("path") or "/"))
                ),
                self._ascii_safe(row.get("query_string") or ""),
                int(row.get("response_status", 0) or 0),
                int(row.get("response_length", 0) or 0),
            )
            if row_sig == signature:
                has_same = True
                break
        if (not has_same) and len(existing) < sample_limit:
            self.api_data[endpoint_key].append(entry_copy)
            self.endpoint_times[endpoint_key].append(response_time_ms)
            added = True

        merged_tags = set()
        for raw_tag in list(self.endpoint_tags.get(endpoint_key, []) or []):
            for clean_tag in self._logger_extract_tag_tokens(raw_tag):
                if clean_tag:
                    merged_tags.add(clean_tag)
        for auto_tag in list(self._auto_tag(entry_copy) or []):
            for clean_tag in self._logger_extract_tag_tokens(auto_tag):
                if clean_tag:
                    merged_tags.add(clean_tag)
        merged_tags.update(tag_values)
        self.endpoint_tags[endpoint_key] = sorted(merged_tags)
    return added

def _logger_capture_event(
    self, endpoint_key, entry, tags=None, bypass_capture=False, sync_recon=True
):
    """Capture lightweight Logger++ event from one processed request/response."""
    if (not bypass_capture) and (not getattr(self, "logger_capture_enabled", True)):
        return
    if not isinstance(entry, dict):
        return

    method = self._ascii_safe(entry.get("method") or "GET").upper()
    host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/")
    query = self._ascii_safe(entry.get("query_string") or "")
    tool = self._ascii_safe(entry.get("source_tool") or "Unknown")
    content_type = self._ascii_safe(entry.get("content_type") or "unknown", lower=True)
    inferred_type = content_type.split(";", 1)[0].strip() if content_type else "none"
    if not inferred_type:
        inferred_type = "none"
    inferred_type = inferred_type[:28].upper()

    try:
        status = int(entry.get("response_status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        response_len = int(entry.get("response_length", 0) or 0)
    except (TypeError, ValueError):
        response_len = 0

    tag_values = []
    seen_tag_values = set()
    for raw_tag in list(tags or []):
        for clean_tag in self._logger_extract_tag_tokens(raw_tag):
            if clean_tag and (clean_tag not in seen_tag_values):
                seen_tag_values.add(clean_tag)
                tag_values.append(clean_tag)
    if sync_recon:
        self._sync_recon_entry_from_logger(endpoint_key, entry, tags=tag_values)
    tag_text = ",".join(tag_values[:8])
    req_cap, resp_cap = self._logger_effective_preview_caps()
    req_header_limit = self._logger_effective_header_preview_limit("request")
    resp_header_limit = self._logger_effective_header_preview_limit("response")

    query_suffix = "?{}".format(query) if query else ""
    request_line = "{} {}{} HTTP/1.1".format(method, path, query_suffix)
    req_preview_lines = [request_line]
    req_preview_lines.append("Host: {}".format(host))
    req_headers = entry.get("headers", {}) or {}
    header_count = 0
    for key, value in req_headers.items():
        if header_count >= req_header_limit:
            break
        header_count += 1
        key_text = self._ascii_safe(key)
        key_lower = self._ascii_safe(key, lower=True)
        value_text = self._ascii_safe(value)
        if any(marker in key_lower for marker in ["authorization", "cookie", "token", "api-key", "apikey"]):
            value_text = "<redacted>"
        req_preview_lines.append("{}: {}".format(key_text, value_text))
    request_body = self._truncate_body_text_by_max_size(entry.get("request_body") or "")
    if request_body:
        req_preview_lines.append("")
        req_preview_lines.append(request_body)
    request_preview = "\n".join(req_preview_lines)
    if len(request_preview) > req_cap:
        request_preview = request_preview[:req_cap] + "\n... [truncated]"

    resp_preview_lines = ["HTTP {}".format(status)]
    response_headers = entry.get("response_headers", {}) or {}
    resp_header_count = 0
    for key, value in response_headers.items():
        if resp_header_count >= resp_header_limit:
            break
        resp_header_count += 1
        resp_preview_lines.append("{}: {}".format(self._ascii_safe(key), self._ascii_safe(value)))
    response_body = self._truncate_body_text_by_max_size(entry.get("response_body") or "")
    if response_body:
        resp_preview_lines.append("")
        resp_preview_lines.append(response_body)
    response_preview = "\n".join(resp_preview_lines)
    if len(response_preview) > resp_cap:
        response_preview = response_preview[:resp_cap] + "\n... [truncated]"

    with self.logger_lock:
        self.logger_event_seq = int(getattr(self, "logger_event_seq", 0) or 0) + 1
        event = {
            "seq": self.logger_event_seq,
            "time": time.strftime("%H:%M:%S"),
            "tool": tool,
            "method": method,
            "host": host,
            "protocol": self._ascii_safe(entry.get("protocol") or "https", lower=True),
            "port": int(entry.get("port", 0) or 0),
            "path": path,
            "query": query,
            "status": status,
            "response_length": response_len,
            "inferred_type": inferred_type,
            "base_tags": tag_text,
            "tags": tag_text,
            "endpoint_key": self._ascii_safe(endpoint_key),
            "request_preview": request_preview,
            "response_preview": response_preview,
        }
        self.logger_events.append(event)
    self._logger_trim_if_needed(force=False)
    self._schedule_logger_ui_refresh()

def _logger_count_default_request_markers(self, event):
    """Lightweight request-side metric for ReqM when regex is not active."""
    query_text = self._ascii_safe(event.get("query") or "").strip()
    preview = self._ascii_safe(event.get("request_preview") or "", lower=True)
    hits = 0
    if query_text:
        hits += len([part for part in query_text.split("&") if self._ascii_safe(part).strip()])
    markers = [
        "authorization:",
        "cookie:",
        "token",
        "apikey",
        "x-api-key",
        "bearer ",
        "password",
        "jwt",
        "csrf",
    ]
    for marker in markers:
        if marker in preview:
            hits += 1
    return min(99, max(0, int(hits)))

def _logger_count_default_response_markers(self, event):
    """Lightweight response-side metric for RespM when regex is not active."""
    preview = self._ascii_safe(event.get("response_preview") or "", lower=True)
    hits = 0
    try:
        status = int(event.get("status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status >= 400:
        hits += 1
    markers = [
        "set-cookie",
        "token",
        "jwt",
        "error",
        "exception",
        "stack",
        "trace",
        "access-control-allow-origin",
        "x-powered-by",
    ]
    for marker in markers:
        if marker in preview:
            hits += 1
    return min(99, max(0, int(hits)))

def _schedule_logger_ui_refresh(self, force=False):
    """Debounce Logger++ table refresh to keep long sessions responsive."""
    timer = None
    with self.logger_lock:
        if force and self._logger_refresh_timer is not None:
            try:
                self._logger_refresh_timer.cancel()
            except Exception as cancel_err:
                self._callbacks.printError("Logger UI refresh cancel error: {}".format(str(cancel_err)))
            self._logger_refresh_timer = None
        if self._logger_refresh_timer is not None:
            return

        now = time.time()
        elapsed_ms = int((now - self._logger_refresh_last_ts) * 1000)
        delay_ms = 0
        if not force:
            delay_ms = max(0, int(self._logger_refresh_min_interval_ms - elapsed_ms))

        def _queue_refresh():
            with self.logger_lock:
                self._logger_refresh_timer = None
                self._logger_refresh_last_ts = time.time()
            SwingUtilities.invokeLater(lambda: self._run_logger_ui_refresh())

        timer = threading.Timer(delay_ms / 1000.0, _queue_refresh)
        timer.daemon = True
        self._logger_refresh_timer = timer
    if timer is not None:
        timer.start()

def _run_logger_ui_refresh(self):
    """Refresh Logger++ view on the Swing UI thread."""
    try:
        self._refresh_logger_view()
    except Exception as e:
        self._callbacks.printError("Logger++ refresh error: {}".format(str(e)))

def _refresh_logger_tool_filter(self):
    """Refresh logger tool filter from captured logger events."""
    combo = getattr(self, "logger_tool_combo", None)
    if combo is None:
        return
    with self.logger_lock:
        tool_names = set()
        for item in self.logger_events:
            tool_name = self._ascii_safe(item.get("tool") or "").strip()
            if tool_name:
                tool_names.add(tool_name)
        tools = sorted(tool_names)
    tools_signature = tuple(tools)
    cached_signature = tuple(getattr(self, "_logger_tool_combo_signature", ()) or ())
    selected = self._ascii_safe(str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else "All")
    if cached_signature == tools_signature:
        if selected and selected not in tools and selected != "All":
            self._syncing_logger_controls = True
            try:
                combo.setSelectedItem("All")
            finally:
                self._syncing_logger_controls = False
        return
    self._syncing_logger_controls = True
    try:
        combo.removeAllItems()
        combo.addItem("All")
        for tool_name in tools:
            combo.addItem(tool_name)
        if selected in tools or selected == "All":
            combo.setSelectedItem(selected)
        else:
            combo.setSelectedItem("All")
        self._logger_tool_combo_signature = tools_signature
    finally:
        self._syncing_logger_controls = False

def _logger_event_in_scope(self, event):
    """Check whether logger event URL is inside Burp Target scope."""
    host = self._ascii_safe(event.get("host") or "", lower=True).strip()
    if not host:
        return False
    protocol = self._ascii_safe(event.get("protocol") or "https", lower=True).strip()
    if protocol not in ["http", "https"]:
        protocol = "https"
    path = self._ascii_safe(event.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    query = self._ascii_safe(event.get("query") or "")
    port = int(event.get("port", 0) or 0)
    if port <= 0:
        port = 443 if protocol == "https" else 80
    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
        base = "{}://{}{}".format(protocol, host, path)
    else:
        base = "{}://{}:{}{}".format(protocol, host, port, path)
    url_text = "{}?{}".format(base, query) if query else base
    try:
        return bool(self._callbacks.isInScope(URL(url_text)))
    except Exception as scope_err:
        self._callbacks.printError(
            "Logger++ scope check error: {}".format(str(scope_err))
        )
        return False

def _logger_count_regex_matches(self, text, compiled_regex):
    """Count regex matches in one text block safely."""
    if compiled_regex is None:
        return 0
    text_value = self._ascii_safe(text or "")
    if not text_value:
        return 0
    count = 0
    try:
        for _ in compiled_regex.finditer(text_value):
            count += 1
            if count >= 200:
                break
    except Exception as grep_err:
        self._callbacks.printError(
            "Logger++ regex count error: {}".format(str(grep_err))
        )
        return 0
    return count

def _run_logger_regex_search(self, log_feedback=True):
    """Apply grep-style regex search settings for logger view."""
    pattern = ""
    if getattr(self, "logger_regex_field", None) is not None:
        pattern = self._ascii_safe(self.logger_regex_field.getText() or "")
    pattern = pattern.strip()
    if not pattern:
        self._reset_logger_regex_search(clear_field=False, log_feedback=log_feedback)
        return
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as regex_err:
        if log_feedback:
            self.log_to_ui("[!] Logger++ invalid regex: {}".format(str(regex_err)))
        return

    search_req = True
    search_resp = True
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        search_req = bool(self.logger_search_req_checkbox.isSelected())
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        search_resp = bool(self.logger_search_resp_checkbox.isSelected())
    if (not search_req) and (not search_resp):
        search_req = True
        if getattr(self, "logger_search_req_checkbox", None) is not None:
            self.logger_search_req_checkbox.setSelected(True)

    scope_only = False
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        scope_only = bool(self.logger_in_scope_checkbox.isSelected())

    flags = []
    if search_req:
        flags.append("request")
    if search_resp:
        flags.append("response")
    with self.logger_lock:
        self.logger_active_regex = pattern
        self.logger_regex_flags = ",".join(flags)
        self.logger_regex_scope_only = scope_only
    self._schedule_logger_ui_refresh(force=True)
    if log_feedback:
        self.log_to_ui(
            "[*] Logger++ grep enabled: /{}/ on {}{}".format(
                pattern,
                "+".join(flags),
                " (in-scope only)" if scope_only else "",
            )
        )

def _logger_collect_grep_popup_matches(
    self, pattern, search_req=True, search_resp=True, scope_only=False, limit=120
):
    """Build compact grep preview lines for popup review."""
    regex_text = self._ascii_safe(pattern or "").strip()
    if not regex_text:
        return []
    try:
        compiled_regex = re.compile(regex_text, re.IGNORECASE)
    except re.error:
        return []

    with self.logger_lock:
        events = list(getattr(self, "logger_events", []) or [])

    lines = []
    for event in reversed(events):
        if scope_only and (not self._logger_event_in_scope(event)):
            continue
        req_hits = 0
        resp_hits = 0
        if search_req:
            req_hits = self._logger_count_regex_matches(
                event.get("request_preview") or "", compiled_regex
            )
        if search_resp:
            resp_hits = self._logger_count_regex_matches(
                event.get("response_preview") or "", compiled_regex
            )
        total_hits = req_hits + resp_hits
        if total_hits <= 0:
            continue
        method = self._ascii_safe(event.get("method") or "")
        host = self._ascii_safe(event.get("host") or "")
        path = self._ascii_safe(event.get("path") or "")
        query = self._ascii_safe(event.get("query") or "")
        status = self._ascii_safe(str(event.get("status") or ""))
        event_id = self._ascii_safe(str(event.get("id") or ""))
        url_path = "{}?{}".format(path, query) if query else path
        lines.append(
            "#{:>5}  {:<6} {:<40} {:<48} status={} hits(req={},resp={})".format(
                event_id[:5],
                method[:6],
                host[:40],
                url_path[:48],
                status[:4],
                req_hits,
                resp_hits,
            )
        )
        if len(lines) >= int(limit or 120):
            break
    return lines

def _open_logger_grep_popup(self):
    """Open Logger grep-values popup while preserving inline controls."""
    inline_pattern = ""
    if getattr(self, "logger_regex_field", None) is not None:
        inline_pattern = self._ascii_safe(self.logger_regex_field.getText() or "")
    inline_req = True
    inline_resp = True
    inline_scope = False
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        inline_req = bool(self.logger_search_req_checkbox.isSelected())
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        inline_resp = bool(self.logger_search_resp_checkbox.isSelected())
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        inline_scope = bool(self.logger_in_scope_checkbox.isSelected())

    popup_pattern = self._load_text_setting("logger_popup.grep_pattern", inline_pattern)
    popup_req = self._load_bool_setting("logger_popup.grep_req", inline_req)
    popup_resp = self._load_bool_setting("logger_popup.grep_resp", inline_resp)
    popup_scope = self._load_bool_setting("logger_popup.grep_scope", inline_scope)

    regex_field = JTextField(popup_pattern, 72)
    search_req_checkbox = JCheckBox("Search Requests", popup_req)
    search_resp_checkbox = JCheckBox("Search Responses", popup_resp)
    in_scope_checkbox = JCheckBox("In Scope Only", popup_scope)

    preview_area = JTextArea(14, 120)
    preview_area.setEditable(False)
    preview_area.setFont(Font("Monospaced", Font.PLAIN, 11))

    def _render_preview():
        pattern = self._ascii_safe(regex_field.getText() or "").strip()
        if not pattern:
            preview_area.setText("Enter a regex pattern to preview matches.")
            return
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as regex_err:
            preview_area.setText("Invalid regex: {}".format(str(regex_err)))
            return

        req_selected = bool(search_req_checkbox.isSelected())
        resp_selected = bool(search_resp_checkbox.isSelected())
        if (not req_selected) and (not resp_selected):
            req_selected = True
            search_req_checkbox.setSelected(True)
        scope_only = bool(in_scope_checkbox.isSelected())
        matches = self._logger_collect_grep_popup_matches(
            pattern,
            search_req=req_selected,
            search_resp=resp_selected,
            scope_only=scope_only,
            limit=140,
        )
        header = "Pattern: /{}/ | req={} resp={} scope_only={}".format(
            pattern, req_selected, resp_selected, scope_only
        )
        if matches:
            preview_area.setText("{}\n{}\n{}".format(header, "=" * 100, "\n".join(matches)))
        else:
            preview_area.setText("{}\nNo matches found in current logger cache.".format(header))

    preview_button = JButton("Preview Matches")
    preview_button.addActionListener(lambda e: _render_preview())
    clear_button = JButton("Reset")
    clear_button.addActionListener(
        lambda e: (
            regex_field.setText(""),
            search_req_checkbox.setSelected(True),
            search_resp_checkbox.setSelected(True),
            in_scope_checkbox.setSelected(False),
            preview_area.setText("Enter a regex pattern to preview matches."),
        )
    )

    top_row = JPanel(FlowLayout(FlowLayout.LEFT))
    top_row.add(JLabel("Regex:"))
    top_row.add(regex_field)
    top_row.add(search_req_checkbox)
    top_row.add(search_resp_checkbox)
    top_row.add(in_scope_checkbox)

    button_row = JPanel(FlowLayout(FlowLayout.LEFT))
    button_row.add(preview_button)
    button_row.add(clear_button)

    content = JPanel(BorderLayout(0, 6))
    content.add(button_row, BorderLayout.NORTH)
    content.add(JScrollPane(preview_area), BorderLayout.CENTER)

    panel = JPanel(BorderLayout(0, 6))
    panel.add(top_row, BorderLayout.NORTH)
    panel.add(content, BorderLayout.CENTER)

    _render_preview()
    decision = JOptionPane.showConfirmDialog(
        self._panel,
        panel,
        "Logger Grep Values",
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
    )
    if decision != JOptionPane.OK_OPTION:
        return

    if getattr(self, "logger_regex_field", None) is not None:
        self.logger_regex_field.setText(self._ascii_safe(regex_field.getText() or ""))
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        self.logger_search_req_checkbox.setSelected(bool(search_req_checkbox.isSelected()))
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        self.logger_search_resp_checkbox.setSelected(bool(search_resp_checkbox.isSelected()))
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        self.logger_in_scope_checkbox.setSelected(bool(in_scope_checkbox.isSelected()))
    self._save_text_setting(
        "logger_popup.grep_pattern", self._ascii_safe(regex_field.getText() or "")
    )
    self._save_bool_setting("logger_popup.grep_req", bool(search_req_checkbox.isSelected()))
    self._save_bool_setting("logger_popup.grep_resp", bool(search_resp_checkbox.isSelected()))
    self._save_bool_setting("logger_popup.grep_scope", bool(in_scope_checkbox.isSelected()))
    self._run_logger_regex_search()

def _reset_logger_regex_search(self, clear_field=True, log_feedback=True):
    """Disable active logger regex filter."""
    with self.logger_lock:
        self.logger_active_regex = ""
        self.logger_regex_flags = "request,response"
        self.logger_regex_scope_only = False
    if clear_field and getattr(self, "logger_regex_field", None) is not None:
        self.logger_regex_field.setText("")
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        self.logger_in_scope_checkbox.setSelected(False)
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        self.logger_search_req_checkbox.setSelected(True)
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        self.logger_search_resp_checkbox.setSelected(True)
    self._schedule_logger_ui_refresh(force=True)
    if log_feedback:
        self.log_to_ui("[*] Logger++ grep reset")

def _persist_logger_filter_library(self):
    """Persist named logger filter profiles across Burp sessions."""
    with self.logger_lock:
        library_snapshot = list(getattr(self, "logger_filter_library", []) or [])
    cleaned = []
    for item in library_snapshot:
        if not isinstance(item, dict):
            continue
        alias = self._ascii_safe(item.get("alias") or "").strip()
        string_filter = self._ascii_safe(item.get("string_filter") or "").strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        search_req = bool(item.get("search_req", True))
        search_resp = bool(item.get("search_resp", True))
        scope_only = bool(item.get("scope_only", False))
        if (not alias) or ((not string_filter) and (not regex_text)):
            continue
        cleaned.append(
            {
                "alias": alias[:80],
                "string_filter": string_filter[:120],
                "regex": regex_text[:400],
                "search_req": search_req,
                "search_resp": search_resp,
                "scope_only": scope_only,
            }
        )
        if len(cleaned) >= 200:
            break
    try:
        payload = json.dumps(cleaned, separators=(",", ":"))
    except (TypeError, ValueError) as json_err:
        self._callbacks.printError(
            "Logger filter library persistence encode failed: {}".format(str(json_err))
        )
        return
    self._save_text_setting("logger_filter_library_json", payload)

def _restore_logger_filter_library(self):
    """Restore named logger filter profiles from extension settings."""
    raw_payload = self._load_text_setting("logger_filter_library_json", "").strip()
    if not raw_payload:
        return
    try:
        parsed = json.loads(raw_payload)
    except (TypeError, ValueError) as json_err:
        self._callbacks.printError(
            "Logger filter library persistence decode failed: {}".format(str(json_err))
        )
        return
    if not isinstance(parsed, list):
        return
    cleaned = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        alias = self._ascii_safe(item.get("alias") or "").strip()
        string_filter = self._ascii_safe(item.get("string_filter") or "").strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        search_req = bool(item.get("search_req", True))
        search_resp = bool(item.get("search_resp", True))
        scope_only = bool(item.get("scope_only", False))
        if (not alias) or ((not string_filter) and (not regex_text)):
            continue
        if regex_text:
            try:
                re.compile(regex_text, re.IGNORECASE)
            except re.error:
                continue
        cleaned.append(
            {
                "alias": alias[:80],
                "string_filter": string_filter[:120],
                "regex": regex_text[:400],
                "search_req": search_req,
                "search_resp": search_resp,
                "scope_only": scope_only,
            }
        )
        if len(cleaned) >= 200:
            break
    with self.logger_lock:
        self.logger_filter_library = cleaned
    self._logger_filter_library_signature = ()
    self._refresh_logger_filter_library_combo()

def _persist_logger_tag_rules(self):
    """Persist logger tag rules across Burp sessions."""
    with self.logger_lock:
        rules_snapshot = list(getattr(self, "logger_tag_rules", []) or [])
    scope_map = {"any": "Any", "url": "URL", "request": "Request", "response": "Response"}
    cleaned = []
    for item in rules_snapshot:
        if not isinstance(item, dict):
            continue
        tag = self._ascii_safe(item.get("tag") or "", lower=True).strip().replace(" ", "_")
        scope_key = self._ascii_safe(item.get("scope") or "Any", lower=True).strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        fg_text = self._ascii_safe(item.get("fg") or "#000000", lower=True).strip()
        bg_text = self._ascii_safe(item.get("bg") or "#fff176", lower=True).strip()
        enabled = bool(item.get("enabled", True))
        scope_text = scope_map.get(scope_key)
        if (not tag) or (not scope_text) or (not regex_text):
            continue
        if not re.match(r"^#[0-9a-f]{6}$", fg_text):
            fg_text = "#000000"
        if not re.match(r"^#[0-9a-f]{6}$", bg_text):
            bg_text = "#fff176"
        cleaned.append(
            {
                "tag": tag[:48],
                "scope": scope_text,
                "regex": regex_text[:400],
                "fg": fg_text,
                "bg": bg_text,
                "enabled": enabled,
            }
        )
        if len(cleaned) >= 150:
            break
    try:
        payload = json.dumps(cleaned, separators=(",", ":"))
    except (TypeError, ValueError) as json_err:
        self._callbacks.printError(
            "Logger tag-rule persistence encode failed: {}".format(str(json_err))
        )
        return
    self._save_text_setting("logger_tag_rules_json", payload)

def _restore_logger_tag_rules(self):
    """Restore logger tag rules from extension settings."""
    raw_payload = self._load_text_setting("logger_tag_rules_json", "").strip()
    if not raw_payload:
        return
    try:
        parsed = json.loads(raw_payload)
    except (TypeError, ValueError) as json_err:
        self._callbacks.printError(
            "Logger tag-rule persistence decode failed: {}".format(str(json_err))
        )
        return
    if not isinstance(parsed, list):
        return
    scope_map = {"any": "Any", "url": "URL", "request": "Request", "response": "Response"}
    cleaned = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        tag = self._ascii_safe(item.get("tag") or "", lower=True).strip().replace(" ", "_")
        scope_key = self._ascii_safe(item.get("scope") or "Any", lower=True).strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        fg_text = self._ascii_safe(item.get("fg") or "#000000", lower=True).strip()
        bg_text = self._ascii_safe(item.get("bg") or "#fff176", lower=True).strip()
        enabled = bool(item.get("enabled", True))
        scope_text = scope_map.get(scope_key)
        if (not tag) or (not scope_text) or (not regex_text):
            continue
        if not re.match(r"^#[0-9a-f]{6}$", fg_text):
            fg_text = "#000000"
        if not re.match(r"^#[0-9a-f]{6}$", bg_text):
            bg_text = "#fff176"
        cleaned.append(
            {
                "tag": tag[:48],
                "scope": scope_text,
                "regex": regex_text[:400],
                "fg": fg_text,
                "bg": bg_text,
                "enabled": enabled,
            }
        )
        if len(cleaned) >= 150:
            break
    with self.logger_lock:
        self.logger_tag_rules = cleaned

def _restore_logger_popup_persistence(self):
    """Restore logger popup-related persisted state."""
    self._restore_logger_filter_library()
    self._restore_logger_tag_rules()

def _refresh_logger_filter_library_combo(self):
    """Refresh filter-library dropdown from saved logger regex snippets."""
    combo = getattr(self, "logger_filter_library_combo", None)
    if combo is None:
        return
    with self.logger_lock:
        entries = list(getattr(self, "logger_filter_library", []) or [])
    aliases = []
    for item in entries:
        alias = self._ascii_safe(item.get("alias") or "").strip()
        if alias:
            aliases.append(alias)
    aliases_signature = tuple(aliases)
    cached_signature = tuple(
        getattr(self, "_logger_filter_library_signature", ()) or ()
    )
    selected = self._ascii_safe(
        str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else ""
    )
    if cached_signature == aliases_signature:
        if (not aliases) and selected != "(No Saved Filters)":
            self._syncing_logger_controls = True
            try:
                combo.setSelectedItem("(No Saved Filters)")
            finally:
                self._syncing_logger_controls = False
        elif aliases and selected and selected not in aliases:
            self._syncing_logger_controls = True
            try:
                combo.setSelectedItem(aliases[0])
            finally:
                self._syncing_logger_controls = False
        return
    self._syncing_logger_controls = True
    try:
        combo.removeAllItems()
        if not aliases:
            combo.addItem("(No Saved Filters)")
        else:
            for alias in aliases:
                combo.addItem(alias)
        if selected:
            combo.setSelectedItem(selected)
        self._logger_filter_library_signature = aliases_signature
    finally:
        self._syncing_logger_controls = False

def _save_logger_filter(self):
    """Save current logger filter profile as named library entry."""
    string_filter = ""
    if getattr(self, "logger_filter_field", None) is not None:
        string_filter = self._ascii_safe(self.logger_filter_field.getText() or "")
    string_filter = string_filter.strip()
    regex_text = ""
    if getattr(self, "logger_regex_field", None) is not None:
        regex_text = self._ascii_safe(self.logger_regex_field.getText() or "")
    regex_text = regex_text.strip()
    search_req = True
    search_resp = True
    scope_only = False
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        search_req = bool(self.logger_search_req_checkbox.isSelected())
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        search_resp = bool(self.logger_search_resp_checkbox.isSelected())
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        scope_only = bool(self.logger_in_scope_checkbox.isSelected())
    if (not string_filter) and (not regex_text):
        self.log_to_ui("[!] Logger++: set String Filter and/or Regex Filter before saving")
        return
    if regex_text:
        try:
            re.compile(regex_text, re.IGNORECASE)
        except re.error as regex_err:
            self.log_to_ui("[!] Logger++ invalid regex: {}".format(str(regex_err)))
            return
    alias = JOptionPane.showInputDialog(
        self._panel, "Filter name:", "Save Logger Filter", JOptionPane.PLAIN_MESSAGE
    )
    alias = self._ascii_safe(alias or "").strip()
    if not alias:
        return
    with self.logger_lock:
        library = list(getattr(self, "logger_filter_library", []) or [])
        library = [
            item
            for item in library
            if self._ascii_safe(item.get("alias") or "", lower=True)
            != self._ascii_safe(alias, lower=True)
        ]
        library.append(
            {
                "alias": alias,
                "string_filter": string_filter,
                "regex": regex_text,
                "search_req": bool(search_req),
                "search_resp": bool(search_resp),
                "scope_only": bool(scope_only),
            }
        )
        library = sorted(
            library, key=lambda item: self._ascii_safe(item.get("alias") or "", lower=True)
        )[:200]
        self.logger_filter_library = library
    self._persist_logger_filter_library()
    self._refresh_logger_filter_library_combo()
    combo = getattr(self, "logger_filter_library_combo", None)
    if combo is not None:
        combo.setSelectedItem(alias)
    self.log_to_ui("[+] Logger++ saved filter '{}'".format(alias))

def _apply_logger_filter(self):
    """Apply selected named filter profile from logger filter library."""
    combo = getattr(self, "logger_filter_library_combo", None)
    if combo is None:
        return
    alias = self._ascii_safe(
        str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else ""
    ).strip()
    if (not alias) or alias == "(No Saved Filters)":
        return
    string_filter = ""
    regex_text = ""
    search_req = True
    search_resp = True
    scope_only = False
    with self.logger_lock:
        for item in list(getattr(self, "logger_filter_library", []) or []):
            if (
                self._ascii_safe(item.get("alias") or "", lower=True)
                == self._ascii_safe(alias, lower=True)
            ):
                string_filter = self._ascii_safe(item.get("string_filter") or "")
                regex_text = self._ascii_safe(item.get("regex") or "")
                search_req = bool(item.get("search_req", True))
                search_resp = bool(item.get("search_resp", True))
                scope_only = bool(item.get("scope_only", False))
                break
    if (not string_filter) and (not regex_text):
        self.log_to_ui("[!] Logger++: selected filter has no criteria")
        return
    if getattr(self, "logger_filter_field", None) is not None:
        self.logger_filter_field.setText(string_filter)
    if getattr(self, "logger_regex_field", None) is not None:
        self.logger_regex_field.setText(regex_text)
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        self.logger_search_req_checkbox.setSelected(bool(search_req))
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        self.logger_search_resp_checkbox.setSelected(bool(search_resp))
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        self.logger_in_scope_checkbox.setSelected(bool(scope_only))
    if regex_text:
        self._run_logger_regex_search(log_feedback=False)
    else:
        self._reset_logger_regex_search(clear_field=False, log_feedback=False)
        self._schedule_logger_ui_refresh(force=True)

def _remove_logger_filter(self):
    """Remove selected named filter from logger filter library."""
    combo = getattr(self, "logger_filter_library_combo", None)
    if combo is None:
        return
    alias = self._ascii_safe(
        str(combo.getSelectedItem()) if combo.getSelectedItem() is not None else ""
    ).strip()
    if (not alias) or alias == "(No Saved Filters)":
        return
    with self.logger_lock:
        library = list(getattr(self, "logger_filter_library", []) or [])
        original = len(library)
        library = [
            item
            for item in library
            if self._ascii_safe(item.get("alias") or "", lower=True)
            != self._ascii_safe(alias, lower=True)
        ]
        self.logger_filter_library = library
    self._persist_logger_filter_library()
    self._refresh_logger_filter_library_combo()
    if len(library) < original:
        self.log_to_ui("[*] Logger++ removed filter '{}'".format(alias))

def _clear_logger_filters(self, log_feedback=True):
    """Clear active logger string/regex filters (keeps saved library entries)."""
    if getattr(self, "logger_filter_field", None) is not None:
        self.logger_filter_field.setText("")
    self._reset_logger_regex_search(clear_field=True, log_feedback=False)
    if getattr(self, "logger_len_min_field", None) is not None:
        self.logger_len_min_field.setText("")
    if getattr(self, "logger_len_max_field", None) is not None:
        self.logger_len_max_field.setText("")
    if getattr(self, "logger_tool_combo", None) is not None:
        self.logger_tool_combo.setSelectedItem("All")
    if getattr(self, "logger_method_combo", None) is not None:
        self.logger_method_combo.setSelectedItem("All")
    if getattr(self, "logger_status_combo", None) is not None:
        self.logger_status_combo.setSelectedItem("All")
    combo = getattr(self, "logger_filter_library_combo", None)
    if combo is not None and self._combo_contains_item(combo, "(No Saved Filters)"):
        self._syncing_logger_controls = True
        try:
            combo.setSelectedItem("(No Saved Filters)")
        finally:
            self._syncing_logger_controls = False
    self._schedule_logger_ui_refresh(force=True)
    if log_feedback:
        self.log_to_ui("[*] Logger++ filters cleared")

def _logger_hex_to_color(self, hex_text, default_color=None):
    """Convert #RRGGBB text to java.awt.Color."""
    safe = self._ascii_safe(hex_text or "", lower=True).strip()
    if re.match(r"^#[0-9a-f]{6}$", safe):
        try:
            return Color(int(safe[1:3], 16), int(safe[3:5], 16), int(safe[5:7], 16))
        except Exception as color_err:
            self._callbacks.printError(
                "Logger color parse error: {}".format(str(color_err))
            )
            pass
    if default_color is not None:
        return default_color
    return Color(0, 0, 0)

def _logger_color_to_hex(self, color_obj, fallback="#000000"):
    """Convert java.awt.Color to #RRGGBB hex."""
    if color_obj is None:
        return self._ascii_safe(fallback or "#000000", lower=True).strip()
    try:
        return "#{:02x}{:02x}{:02x}".format(
            int(color_obj.getRed() or 0),
            int(color_obj.getGreen() or 0),
            int(color_obj.getBlue() or 0),
        )
    except Exception as color_err:
        self._callbacks.printError(
            "Logger color format error: {}".format(str(color_err))
        )
        return self._ascii_safe(fallback or "#000000", lower=True).strip()

def _logger_pick_color(self, title, current_hex, fallback_hex):
    """Open Swing color picker and return chosen #RRGGBB."""
    current_color = self._logger_hex_to_color(
        current_hex, default_color=self._logger_hex_to_color(fallback_hex)
    )
    chosen = JColorChooser.showDialog(self._panel, title, current_color)
    if chosen is None:
        safe = self._ascii_safe(current_hex or "", lower=True).strip()
        if re.match(r"^#[0-9a-f]{6}$", safe):
            return safe
        return self._ascii_safe(fallback_hex or "#000000", lower=True).strip()
    return self._logger_color_to_hex(chosen, fallback=fallback_hex)

def _logger_suggest_tag_palette(self, tag_text, regex_text):
    """Suggest readable FG/BG palette from tag intent."""
    tag_lower = self._ascii_safe(tag_text or "", lower=True).strip()
    regex_lower = self._ascii_safe(regex_text or "", lower=True).strip()
    combined = "{} {}".format(tag_lower, regex_lower)
    if any(x in combined for x in ["admin", "privilege", "root"]):
        return {"fg": "#ffffff", "bg": "#ff5252", "reason": "admin/privilege signal"}
    if "api_endpoint" in combined:
        return {"fg": "#000000", "bg": "#fff176", "reason": "API endpoint default style"}
    if re.search(r"\bauth\b", combined):
        return {"fg": "#000000", "bg": "#39ff14", "reason": "auth default style"}
    if "idor_risk" in combined:
        return {"fg": "#ffffff", "bg": "#ff5252", "reason": "idor default style"}
    if "write_ops" in combined:
        return {"fg": "#000000", "bg": "#c5cae9", "reason": "write-operation default style"}
    if re.search(r"\bjwt\b", combined):
        return {"fg": "#000000", "bg": "#9fa8da", "reason": "jwt default style"}
    if any(x in combined for x in ["sensitive", "secret", "token", "password", "jwt"]):
        return {"fg": "#ffffff", "bg": "#d32f2f", "reason": "secret/sensitive signal"}
    if any(x in combined for x in ["idor", "bola", "object", "account", "user_id"]):
        return {"fg": "#111111", "bg": "#ff8a65", "reason": "authorization/object signal"}
    if any(x in combined for x in ["write", "post", "put", "patch", "delete"]):
        return {"fg": "#111111", "bg": "#ffe082", "reason": "write-operation signal"}
    if any(x in combined for x in ["api", "endpoint", "graphql", "schema"]):
        return {"fg": "#111111", "bg": "#81d4fa", "reason": "API discovery signal"}
    return {"fg": "#111111", "bg": "#cfd8dc", "reason": "default neutral signal"}

def _logger_builtin_tag_rules(self):
    """Return built-in colored logger tag rules inspired by Logger++ defaults."""
    return [
        {
            "tag": "api_endpoint",
            "scope": "Any",
            "regex": r"(?i)(/api/|/v1/|/v2/|/graphql|application/json)",
            "fg": "#000000",
            "bg": "#fff176",
            "enabled": True,
        },
        {
            "tag": "auth",
            "scope": "Any",
            "regex": r"(?i)(/auth|/login|/token|authorization|bearer\s+)",
            "fg": "#000000",
            "bg": "#39ff14",
            "enabled": True,
        },
        {
            "tag": "sensitive",
            "scope": "Response",
            "regex": r"(?i)(password|secret|token|api[_-]?key|credit|ssn)",
            "fg": "#000000",
            "bg": "#ffcdd2",
            "enabled": True,
        },
        {
            "tag": "idor_risk",
            "scope": "URL",
            "regex": r"(?i)(/[0-9]{2,}$|/[0-9a-f]{8,}|(?:user|account|order|invoice)[_-]?id=\d+)",
            "fg": "#ffffff",
            "bg": "#ff5252",
            "enabled": True,
        },
        {
            "tag": "write_ops",
            "scope": "Request",
            "regex": r"(?im)^(POST|PUT|PATCH|DELETE)\s+",
            "fg": "#000000",
            "bg": "#c5cae9",
            "enabled": True,
        },
        {
            "tag": "jwt",
            "scope": "Request",
            "regex": r"(?i)(authorization:\s*bearer\s+[a-z0-9_\-=]+\.[a-z0-9_\-=]+\.[a-z0-9_\-=]+|\beyJ[a-z0-9_\-=]+\.[a-z0-9_\-=]+\.[a-z0-9_\-=]+)",
            "fg": "#000000",
            "bg": "#9fa8da",
            "enabled": True,
        },
    ]

def _ensure_logger_default_tag_rules(self, force=False):
    """Ensure baseline tag rules exist while preserving custom operator rules."""
    builtin_rules = [dict(rule) for rule in self._logger_builtin_tag_rules()]
    changed = False
    with self.logger_lock:
        existing = list(getattr(self, "logger_tag_rules", []) or [])
        if force:
            updated = list(builtin_rules)
            changed = True
        else:
            by_tag = {}
            updated = []
            for item in existing:
                tag = self._ascii_safe(item.get("tag") or "", lower=True).strip()
                if (not tag) or (tag in by_tag):
                    updated.append(dict(item))
                    continue
                by_tag[tag] = True
                updated.append(dict(item))
            for rule in builtin_rules:
                tag = self._ascii_safe(rule.get("tag") or "", lower=True).strip()
                if tag and (tag not in by_tag):
                    updated.append(rule)
                    by_tag[tag] = True
                    changed = True
            if (not existing) and updated:
                changed = True
        self.logger_tag_rules = updated
    return changed

def _logger_preview_rule_matches(self, scope, regex_text, limit=20):
    """Preview how one rule would match existing logger events."""
    scope_text = self._ascii_safe(scope or "Any").strip()
    pattern = self._ascii_safe(regex_text or "").strip()
    if not pattern:
        return 0, []
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return 0, []
    with self.logger_lock:
        snapshot = list(getattr(self, "logger_events", []) or [])
    matched = []
    total = 0
    for event in reversed(snapshot):
        haystack = self._logger_rule_scope_text(event, scope_text)
        try:
            if not compiled.search(haystack):
                continue
        except Exception as preview_err:
            self._callbacks.printError(
                "Logger rule preview match error: {}".format(str(preview_err))
            )
            continue
        total += 1
        if len(matched) >= int(limit or 20):
            continue
        method = self._ascii_safe(event.get("method") or "")
        host = self._ascii_safe(event.get("host") or "")
        path = self._ascii_safe(event.get("path") or "")
        query = self._ascii_safe(event.get("query") or "")
        status = self._ascii_safe(event.get("status") or "")
        length = self._ascii_safe(event.get("response_length") or "")
        url_path = "{}?{}".format(path, query) if query else path
        matched.append(
            "{} {:<6} {:<36} {:<44} st={} len={}".format(
                self._ascii_safe(event.get("time") or ""),
                method[:6],
                host[:36],
                url_path[:44],
                status,
                length,
            )
        )
    return total, matched

def _open_logger_tag_rules_popup(self):
    """Open popup editor for logger tag rules (tag|scope|regex|fg|bg|enabled)."""
    self._ensure_logger_default_tag_rules(force=False)
    with self.logger_lock:
        existing = list(getattr(self, "logger_tag_rules", []) or [])
    lines = []
    for item in existing:
        tag = self._ascii_safe(item.get("tag") or "", lower=True).strip()
        scope = self._ascii_safe(item.get("scope") or "Any").strip()
        regex = self._ascii_safe(item.get("regex") or "").strip()
        fg = self._ascii_safe(item.get("fg") or "#000000", lower=True).strip()
        bg = self._ascii_safe(item.get("bg") or "#fff176", lower=True).strip()
        enabled = bool(item.get("enabled", True))
        if tag and regex:
            lines.append(
                "{}|{}|{}|{}|{}|{}".format(
                    tag,
                    scope,
                    regex,
                    fg,
                    bg,
                    "true" if enabled else "false",
                )
            )
    if not lines:
        lines = [
            "api_endpoint|Any|(?i)(/api/|/v1/|/v2/|/graphql|application/json)|#000000|#fff176|true",
            "auth|Any|(?i)(/auth|/login|/token|authorization|bearer\\s+)|#000000|#39ff14|true",
            "sensitive|Response|(?i)(password|secret|token|api[_-]?key|credit|ssn)|#000000|#ffcdd2|true",
            "idor_risk|URL|(?i)(/[0-9]{2,}$|/[0-9a-f]{8,}|(?:user|account|order|invoice)[_-]?id=\\d+)|#ffffff|#ff5252|true",
            "write_ops|Request|(?im)^(POST|PUT|PATCH|DELETE)\\s+|#000000|#c5cae9|true",
            "jwt|Request|(?i)(authorization:\\s*bearer\\s+[a-z0-9_\\-=]+\\.[a-z0-9_\\-=]+\\.[a-z0-9_\\-=]+|\\beyJ[a-z0-9_\\-=]+\\.[a-z0-9_\\-=]+\\.[a-z0-9_\\-=]+)|#000000|#9fa8da|true",
        ]

    editor = JTextArea("\n".join(lines), 12, 110)
    editor.setLineWrap(False)
    editor.setWrapStyleWord(False)

    quick_tag_default = self._load_text_setting("logger_popup.tag.quick_tag", "")
    quick_scope_default = self._load_text_setting("logger_popup.tag.quick_scope", "Any")
    quick_regex_default = self._load_text_setting("logger_popup.tag.quick_regex", "")
    quick_fg_default = self._load_text_setting("logger_popup.tag.quick_fg", "#ffffff")
    quick_bg_default = self._load_text_setting("logger_popup.tag.quick_bg", "#ff5252")
    quick_enabled_default = self._load_bool_setting("logger_popup.tag.quick_enabled", True)

    quick_tag_field = JTextField(quick_tag_default, 14)
    quick_scope_combo = JComboBox(["Any", "URL", "Request", "Response"])
    if self._ascii_safe(quick_scope_default).strip() in ["Any", "URL", "Request", "Response"]:
        quick_scope_combo.setSelectedItem(self._ascii_safe(quick_scope_default).strip())
    else:
        quick_scope_combo.setSelectedItem("Any")
    quick_regex_field = JTextField(quick_regex_default, 36)
    quick_fg_combo = JComboBox(
        [
            "#000000",
            "#ffffff",
            "#1f2937",
            "#0f172a",
            "#7c3aed",
            "#be123c",
        ]
    )
    if re.match(r"^#[0-9a-f]{6}$", self._ascii_safe(quick_fg_default, lower=True).strip()):
        quick_fg_combo.setSelectedItem(self._ascii_safe(quick_fg_default, lower=True).strip())
    else:
        quick_fg_combo.setSelectedItem("#ffffff")
    quick_fg_combo.setEditable(True)
    quick_bg_combo = JComboBox(
        [
            "#fff176",
            "#ff5252",
            "#ef9a9a",
            "#81c784",
            "#64b5f6",
            "#b39ddb",
            "#cfd8dc",
        ]
    )
    if re.match(r"^#[0-9a-f]{6}$", self._ascii_safe(quick_bg_default, lower=True).strip()):
        quick_bg_combo.setSelectedItem(self._ascii_safe(quick_bg_default, lower=True).strip())
    else:
        quick_bg_combo.setSelectedItem("#ff5252")
    quick_bg_combo.setEditable(True)
    quick_enabled_checkbox = JCheckBox("Enabled", quick_enabled_default)
    lab_status_label = JLabel("Rule Lab: ready")
    lab_preview_area = JTextArea(8, 110)
    lab_preview_area.setEditable(False)
    lab_preview_area.setFont(Font("Monospaced", Font.PLAIN, 11))
    lab_preview_area.setText("Set scope+regex then click Preview Rule.")

    def _combo_selected_text(combo_obj, fallback_text):
        try:
            value = combo_obj.getEditor().getItem() if combo_obj.isEditable() else combo_obj.getSelectedItem()
        except Exception as combo_err:
            self._callbacks.printError(
                "Logger tag combo read error: {}".format(str(combo_err))
            )
            value = combo_obj.getSelectedItem()
        safe = self._ascii_safe(value or fallback_text, lower=True).strip()
        if not safe:
            safe = self._ascii_safe(fallback_text or "", lower=True).strip()
        return safe

    def _set_combo_hex(combo_obj, hex_text):
        safe_hex = self._ascii_safe(hex_text or "", lower=True).strip()
        if not re.match(r"^#[0-9a-f]{6}$", safe_hex):
            return
        combo_obj.setSelectedItem(safe_hex)
        try:
            combo_obj.getEditor().setItem(safe_hex)
        except Exception as combo_err:
            self._callbacks.printError(
                "Logger tag combo write error: {}".format(str(combo_err))
            )
            pass

    def _refresh_rule_lab():
        scope_text = self._ascii_safe(str(quick_scope_combo.getSelectedItem() or "Any")).strip()
        regex_text = self._ascii_safe(quick_regex_field.getText() or "").strip()
        if not regex_text:
            lab_status_label.setText("Rule Lab: enter regex to preview")
            lab_preview_area.setText("Set scope+regex then click Preview Rule.")
            return
        try:
            re.compile(regex_text, re.IGNORECASE)
        except re.error as regex_err:
            lab_status_label.setText("Rule Lab: invalid regex")
            lab_preview_area.setText("Invalid regex: {}".format(str(regex_err)))
            return
        total, sample_lines = self._logger_preview_rule_matches(scope_text, regex_text, limit=20)
        lab_status_label.setText("Rule Lab: {} matches for current regex".format(total))
        if sample_lines:
            lab_preview_area.setText("\n".join(sample_lines))
        else:
            lab_preview_area.setText("No matches for current rule on cached logger events.")

    def _apply_auto_style():
        suggestion = self._logger_suggest_tag_palette(
            quick_tag_field.getText(), quick_regex_field.getText()
        )
        _set_combo_hex(quick_fg_combo, suggestion.get("fg"))
        _set_combo_hex(quick_bg_combo, suggestion.get("bg"))
        lab_status_label.setText(
            "Rule Lab: auto style -> fg {} bg {} ({})".format(
                suggestion.get("fg"), suggestion.get("bg"), suggestion.get("reason")
            )
        )

    def _append_rule_line(tag_text, scope_text, regex_text, fg_text, bg_text, enabled):
        tag = self._ascii_safe(tag_text or "", lower=True).strip().replace(" ", "_")
        scope = self._ascii_safe(scope_text or "Any").strip()
        regex_value = self._ascii_safe(regex_text or "").strip()
        fg_value = self._ascii_safe(fg_text or "#000000", lower=True).strip()
        bg_value = self._ascii_safe(bg_text or "#fff176", lower=True).strip()
        if not re.match(r"^#[0-9a-f]{6}$", fg_value):
            fg_value = "#000000"
        if not re.match(r"^#[0-9a-f]{6}$", bg_value):
            bg_value = "#fff176"
        if (not tag) or (not regex_value):
            return
        existing_text = self._ascii_safe(editor.getText() or "").strip()
        new_line = "{}|{}|{}|{}|{}|{}".format(
            tag,
            scope,
            regex_value,
            fg_value,
            bg_value,
            "true" if enabled else "false",
        )
        if existing_text:
            editor.setText("{}\n{}".format(existing_text, new_line))
        else:
            editor.setText(new_line)

    add_rule_button = JButton("Add Rule")
    add_rule_button.addActionListener(
        lambda e: _append_rule_line(
            quick_tag_field.getText(),
            str(quick_scope_combo.getSelectedItem() or "Any"),
            quick_regex_field.getText(),
            _combo_selected_text(quick_fg_combo, "#000000"),
            _combo_selected_text(quick_bg_combo, "#fff176"),
            bool(quick_enabled_checkbox.isSelected()),
        )
    )
    add_admin_button = JButton("Add Admin Preset")
    add_admin_button.addActionListener(
        lambda e: _append_rule_line(
            "admin_risk",
            "Any",
            "(?i)(\\badmin\\b|role\\s*=\\s*admin|is[_-]?admin)",
            "#ffffff",
            "#ff5252",
            True,
        )
    )
    pick_fg_button = JButton("Pick FG")
    pick_fg_button.addActionListener(
        lambda e: _set_combo_hex(
            quick_fg_combo,
            self._logger_pick_color(
                "Pick Tag Foreground",
                _combo_selected_text(quick_fg_combo, "#000000"),
                "#000000",
            ),
        )
    )
    pick_bg_button = JButton("Pick BG")
    pick_bg_button.addActionListener(
        lambda e: _set_combo_hex(
            quick_bg_combo,
            self._logger_pick_color(
                "Pick Tag Background",
                _combo_selected_text(quick_bg_combo, "#fff176"),
                "#fff176",
            ),
        )
    )
    auto_style_button = JButton("Auto Style")
    auto_style_button.addActionListener(lambda e: _apply_auto_style())
    preview_button = JButton("Preview Rule")
    preview_button.addActionListener(lambda e: _refresh_rule_lab())

    panel = JPanel(BorderLayout(0, 6))
    header = JPanel(BorderLayout())
    header.add(
        JLabel("One rule per line: tag|scope|regex|fg|bg|enabled   (scope: Any, URL, Request, Response)"),
        BorderLayout.NORTH,
    )
    quick_row = JPanel(FlowLayout(FlowLayout.LEFT))
    quick_row.add(JLabel("Tag:"))
    quick_row.add(quick_tag_field)
    quick_row.add(JLabel("Scope:"))
    quick_row.add(quick_scope_combo)
    quick_row.add(JLabel("Regex:"))
    quick_row.add(quick_regex_field)
    quick_row.add(JLabel("FG:"))
    quick_row.add(quick_fg_combo)
    quick_row.add(pick_fg_button)
    quick_row.add(JLabel("BG:"))
    quick_row.add(quick_bg_combo)
    quick_row.add(pick_bg_button)
    quick_row.add(quick_enabled_checkbox)
    quick_row.add(auto_style_button)
    quick_row.add(preview_button)
    quick_row.add(add_rule_button)
    quick_row.add(add_admin_button)
    header.add(quick_row, BorderLayout.SOUTH)
    panel.add(header, BorderLayout.NORTH)
    center = JPanel(BorderLayout(0, 6))
    center.add(JScrollPane(editor), BorderLayout.CENTER)
    lab_panel = JPanel(BorderLayout(0, 4))
    lab_panel.setBorder(BorderFactory.createTitledBorder("Rule Lab"))
    lab_panel.add(lab_status_label, BorderLayout.NORTH)
    lab_panel.add(JScrollPane(lab_preview_area), BorderLayout.CENTER)
    center.add(lab_panel, BorderLayout.SOUTH)
    panel.add(center, BorderLayout.CENTER)
    if (not self._ascii_safe(quick_tag_default).strip()) and (
        not self._ascii_safe(quick_regex_default).strip()
    ):
        _apply_auto_style()
    _refresh_rule_lab()

    decision = JOptionPane.showConfirmDialog(
        self._panel,
        panel,
        "Logger Tag Rules",
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
    )
    if decision != JOptionPane.OK_OPTION:
        return

    scope_map = {
        "any": "Any",
        "url": "URL",
        "request": "Request",
        "response": "Response",
    }
    self._save_text_setting(
        "logger_popup.tag.quick_tag", self._ascii_safe(quick_tag_field.getText() or "")
    )
    self._save_text_setting(
        "logger_popup.tag.quick_scope",
        self._ascii_safe(str(quick_scope_combo.getSelectedItem() or "Any")),
    )
    self._save_text_setting(
        "logger_popup.tag.quick_regex", self._ascii_safe(quick_regex_field.getText() or "")
    )
    self._save_text_setting(
        "logger_popup.tag.quick_fg", _combo_selected_text(quick_fg_combo, "#ffffff")
    )
    self._save_text_setting(
        "logger_popup.tag.quick_bg", _combo_selected_text(quick_bg_combo, "#ff5252")
    )
    self._save_bool_setting(
        "logger_popup.tag.quick_enabled", bool(quick_enabled_checkbox.isSelected())
    )

    parsed = []
    errors = []
    raw_text = self._ascii_safe(editor.getText() or "")
    for idx, raw_line in enumerate(raw_text.splitlines(), 1):
        line = self._ascii_safe(raw_line).strip()
        if (not line) or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 3:
            errors.append("line {} missing fields".format(idx))
            continue
        tag = self._ascii_safe(parts[0] or "", lower=True).strip().replace(" ", "_")
        scope_key = self._ascii_safe(parts[1] or "", lower=True).strip()
        regex_text = self._ascii_safe(parts[2] or "").strip()
        fg_text = "#000000"
        bg_text = "#fff176"
        enabled = True
        if len(parts) >= 5:
            fg_text = self._ascii_safe(parts[3] or "#000000", lower=True).strip()
            bg_text = self._ascii_safe(parts[4] or "#fff176", lower=True).strip()
        if len(parts) >= 6:
            enabled_text = self._ascii_safe(parts[5] or "true", lower=True).strip()
            enabled = enabled_text not in ["0", "false", "off", "no", "disabled"]
        scope = scope_map.get(scope_key)
        if not tag:
            errors.append("line {} empty tag".format(idx))
            continue
        if not scope:
            errors.append("line {} invalid scope '{}'".format(idx, scope_key))
            continue
        if not regex_text:
            errors.append("line {} empty regex".format(idx))
            continue
        if not re.match(r"^#[0-9a-f]{6}$", fg_text):
            errors.append("line {} invalid fg color '{}'".format(idx, fg_text))
            continue
        if not re.match(r"^#[0-9a-f]{6}$", bg_text):
            errors.append("line {} invalid bg color '{}'".format(idx, bg_text))
            continue
        try:
            re.compile(regex_text, re.IGNORECASE)
        except re.error as regex_err:
            errors.append("line {} regex error: {}".format(idx, str(regex_err)))
            continue
        parsed.append(
            {
                "tag": tag[:48],
                "scope": scope,
                "regex": regex_text[:400],
                "fg": fg_text,
                "bg": bg_text,
                "enabled": enabled,
            }
        )
        if len(parsed) >= 150:
            break

    if errors:
        self.log_to_ui("[!] Logger Tag Rules validation failed: {}".format("; ".join(errors[:4])))
        JOptionPane.showMessageDialog(
            self._panel,
            "Invalid tag rules:\n- {}".format("\n- ".join(errors[:6])),
            "Logger Tag Rules",
            JOptionPane.WARNING_MESSAGE,
        )
        return

    with self.logger_lock:
        self.logger_tag_rules = list(parsed)
    self._persist_logger_tag_rules()
    self._schedule_logger_ui_refresh(force=True)
    self.log_to_ui("[+] Logger tag rules updated: {} rules".format(len(parsed)))

def _compile_logger_tag_rules(self, rules):
    """Compile logger tag rules once per refresh cycle."""
    compiled = []
    for item in list(rules or []):
        tag = self._ascii_safe(item.get("tag") or "", lower=True).strip()
        scope = self._ascii_safe(item.get("scope") or "Any").strip()
        regex_text = self._ascii_safe(item.get("regex") or "").strip()
        fg_text = self._ascii_safe(item.get("fg") or "#000000", lower=True).strip()
        bg_text = self._ascii_safe(item.get("bg") or "#fff176", lower=True).strip()
        enabled = bool(item.get("enabled", True))
        if (not tag) or (not regex_text) or (not enabled):
            continue
        if not re.match(r"^#[0-9a-f]{6}$", fg_text):
            fg_text = "#000000"
        if not re.match(r"^#[0-9a-f]{6}$", bg_text):
            bg_text = "#fff176"
        try:
            compiled_regex = re.compile(regex_text, re.IGNORECASE)
        except re.error:
            continue
        compiled.append(
            {
                "tag": tag,
                "scope": scope,
                "regex": compiled_regex,
                "fg": fg_text,
                "bg": bg_text,
            }
        )
    return compiled

def _logger_rule_scope_text(self, event, scope):
    """Build searchable scope text for logger tag-rule matching."""
    scope_key = self._ascii_safe(scope or "Any", lower=True).strip()
    request_preview = self._ascii_safe(event.get("request_preview") or "")
    response_preview = self._ascii_safe(event.get("response_preview") or "")
    url_text = "{} {}{}?{}".format(
        self._ascii_safe(event.get("method") or ""),
        self._ascii_safe(event.get("host") or ""),
        self._ascii_safe(event.get("path") or ""),
        self._ascii_safe(event.get("query") or ""),
    )
    if scope_key == "url":
        return self._ascii_safe(url_text, lower=True)
    if scope_key == "request":
        return self._ascii_safe(request_preview, lower=True)
    if scope_key == "response":
        return self._ascii_safe(response_preview, lower=True)
    return self._ascii_safe(
        "{}\n{}\n{}".format(url_text, request_preview, response_preview), lower=True
    )

def _logger_apply_tag_rules(self, event, compiled_rules):
    """Apply compiled tag rules and merge with baseline event tags."""
    merged = []
    seen = set()
    style_map = {}
    base_tokens = self._logger_extract_tag_tokens(
        event.get("base_tags") or event.get("tags") or ""
    )
    for tag in base_tokens:
        if tag and tag not in seen:
            seen.add(tag)
            merged.append(tag)

    for rule in list(compiled_rules or []):
        tag = self._ascii_safe(rule.get("tag") or "", lower=True).strip()
        regex_obj = rule.get("regex")
        scope = self._ascii_safe(rule.get("scope") or "Any")
        fg_text = self._ascii_safe(rule.get("fg") or "#000000", lower=True).strip()
        bg_text = self._ascii_safe(rule.get("bg") or "#fff176", lower=True).strip()
        if (not tag) or (tag in seen) or regex_obj is None:
            continue
        haystack = self._logger_rule_scope_text(event, scope)
        try:
            if regex_obj.search(haystack):
                seen.add(tag)
                merged.append(tag)
                style_map[tag] = {"fg": fg_text, "bg": bg_text}
        except Exception as tag_rule_err:
            self._callbacks.printError(
                "Logger tag-rule match error: {}".format(str(tag_rule_err))
            )
            continue
    if style_map:
        event["_tag_style_map"] = style_map
    return ",".join(merged[:8])

def _logger_event_matches_filters(
    self,
    event,
    filter_text,
    selected_tool,
    selected_method,
    selected_status,
    compiled_regex=None,
    search_request=True,
    search_response=True,
    scope_only=False,
    noise_filter_enabled=False,
    min_len=None,
    max_len=None,
):
    """Check whether one logger event matches current tab filters."""
    method = self._ascii_safe(event.get("method") or "").upper()
    tool = self._ascii_safe(event.get("tool") or "")
    try:
        status = int(event.get("status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        response_length = int(event.get("response_length", 0) or 0)
    except (TypeError, ValueError):
        response_length = 0

    if selected_tool and selected_tool != "All" and tool != selected_tool:
        return False
    if selected_method and selected_method != "ALL" and method != selected_method:
        return False
    if selected_status and selected_status != "All":
        if selected_status == "2xx" and not (200 <= status < 300):
            return False
        if selected_status == "3xx" and not (300 <= status < 400):
            return False
        if selected_status == "4xx" and not (400 <= status < 500):
            return False
        if selected_status == "5xx" and not (500 <= status < 600):
            return False
        if selected_status == "Errors" and status < 400:
            return False
    if (min_len is not None) and response_length < int(min_len):
        return False
    if (max_len is not None) and response_length > int(max_len):
        return False

    if scope_only and (not self._logger_event_in_scope(event)):
        return False
    if noise_filter_enabled and self._logger_event_is_noise(event):
        return False

    cached_tokens = event.get("_tag_tokens")
    if isinstance(cached_tokens, list):
        tags_for_search = ", ".join(cached_tokens[:8])
    else:
        parsed_tokens = self._logger_extract_tag_tokens(event.get("tags") or "")
        event["_tag_tokens"] = list(parsed_tokens)
        tags_for_search = ", ".join(parsed_tokens[:8])
    search = self._ascii_safe(filter_text, lower=True).strip()
    haystack = " ".join(
        [
            self._ascii_safe(event.get("method") or "", lower=True),
            self._ascii_safe(event.get("tool") or "", lower=True),
            self._ascii_safe(event.get("host") or "", lower=True),
            self._ascii_safe(event.get("path") or "", lower=True),
            self._ascii_safe(event.get("query") or "", lower=True),
            self._ascii_safe(tags_for_search, lower=True),
            self._ascii_safe(event.get("inferred_type") or "", lower=True),
            self._ascii_safe(event.get("status") or "", lower=True),
        ]
    )
    if search and (search not in haystack):
        return False

    if compiled_regex is None:
        event["_grep_req"] = self._logger_count_default_request_markers(event)
        event["_grep_resp"] = self._logger_count_default_response_markers(event)
        return True
    req_hits = (
        self._logger_count_regex_matches(event.get("request_preview"), compiled_regex)
        if search_request
        else 0
    )
    resp_hits = (
        self._logger_count_regex_matches(event.get("response_preview"), compiled_regex)
        if search_response
        else 0
    )
    event["_grep_req"] = req_hits
    event["_grep_resp"] = resp_hits
    return (req_hits + resp_hits) > 0

def _refresh_logger_view(self):
    """Rebuild Logger++ table from snapshot with active filters."""
    if getattr(self, "_syncing_logger_controls", False):
        return
    if getattr(self, "_syncing_noise_filter_controls", False):
        return

    noise_toggle_changed = self._sync_noise_filter_checkboxes(source="logger")

    self._logger_apply_runtime_settings(schedule_refresh=False)
    self._refresh_logger_tool_filter()
    self._refresh_logger_filter_library_combo()

    filter_text = ""
    if getattr(self, "logger_filter_field", None) is not None:
        filter_text = self._ascii_safe(self.logger_filter_field.getText() or "")
    selected_tool = "All"
    if getattr(self, "logger_tool_combo", None) is not None:
        selected_tool = self._ascii_safe(str(self.logger_tool_combo.getSelectedItem()) or "All")
    selected_method = "ALL"
    if getattr(self, "logger_method_combo", None) is not None:
        selected_method = self._ascii_safe(
            str(self.logger_method_combo.getSelectedItem()) or "All"
        ).upper()
    selected_status = "All"
    if getattr(self, "logger_status_combo", None) is not None:
        selected_status = self._ascii_safe(str(self.logger_status_combo.getSelectedItem()) or "All")
    min_len = None
    max_len = None
    min_len_text = ""
    max_len_text = ""
    if getattr(self, "logger_len_min_field", None) is not None:
        min_len_text = self._ascii_safe(self.logger_len_min_field.getText() or "").strip()
        if min_len_text:
            try:
                min_len = max(0, int(min_len_text))
            except (TypeError, ValueError):
                min_len = None
    if getattr(self, "logger_len_max_field", None) is not None:
        max_len_text = self._ascii_safe(self.logger_len_max_field.getText() or "").strip()
        if max_len_text:
            try:
                max_len = max(0, int(max_len_text))
            except (TypeError, ValueError):
                max_len = None
    if (min_len is not None) and (max_len is not None) and min_len > max_len:
        min_len, max_len = max_len, min_len

    inline_regex_pattern = ""
    if getattr(self, "logger_regex_field", None) is not None:
        inline_regex_pattern = self._ascii_safe(self.logger_regex_field.getText() or "").strip()
    inline_search_request = True
    inline_search_response = True
    if getattr(self, "logger_search_req_checkbox", None) is not None:
        inline_search_request = bool(self.logger_search_req_checkbox.isSelected())
    if getattr(self, "logger_search_resp_checkbox", None) is not None:
        inline_search_response = bool(self.logger_search_resp_checkbox.isSelected())
    if (not inline_search_request) and (not inline_search_response):
        inline_search_request = True
        if getattr(self, "logger_search_req_checkbox", None) is not None:
            self.logger_search_req_checkbox.setSelected(True)
    inline_scope_only = False
    if getattr(self, "logger_in_scope_checkbox", None) is not None:
        inline_scope_only = bool(self.logger_in_scope_checkbox.isSelected())

    with self.logger_lock:
        desired_pattern = inline_regex_pattern
        desired_flags = "request,response"
        desired_scope_only = False
        if desired_pattern:
            desired_flags = ",".join(
                [x for x in ["request" if inline_search_request else "", "response" if inline_search_response else ""] if x]
            )
            if not desired_flags:
                desired_flags = "request"
            desired_scope_only = inline_scope_only
        state_changed = (
            self._ascii_safe(getattr(self, "logger_active_regex", "") or "") != desired_pattern
            or self._ascii_safe(
                getattr(self, "logger_regex_flags", "request,response") or "request,response",
                lower=True,
            )
            != self._ascii_safe(desired_flags, lower=True)
            or bool(getattr(self, "logger_regex_scope_only", False)) != bool(desired_scope_only)
        )
        if state_changed:
            self.logger_active_regex = desired_pattern
            self.logger_regex_flags = desired_flags
            self.logger_regex_scope_only = bool(desired_scope_only)
        regex_pattern = self._ascii_safe(getattr(self, "logger_active_regex", "") or "")
        regex_flags_text = self._ascii_safe(
            getattr(self, "logger_regex_flags", "request,response") or "request,response",
            lower=True,
        )
    scope_only = bool(getattr(self, "logger_regex_scope_only", False))
    noise_filter_enabled = bool(getattr(self, "logger_noise_filter_enabled", True))
    noise_box = getattr(self, "logger_noise_filter_checkbox", None)
    if noise_box is None:
        noise_box = getattr(self, "recon_noise_filter_checkbox", None)
    if noise_box is not None:
        noise_filter_enabled = bool(noise_box.isSelected())
    self.logger_noise_filter_enabled = noise_filter_enabled
    compiled_regex = None
    regex_error_text = ""
    if regex_pattern.strip():
        try:
            compiled_regex = re.compile(regex_pattern.strip(), re.IGNORECASE)
        except re.error as regex_err:
            regex_error_text = self._ascii_safe(str(regex_err))
            compiled_regex = None
    search_request = "request" in regex_flags_text
    search_response = "response" in regex_flags_text

    show_last = 1000
    if getattr(self, "logger_show_last_combo", None) is not None:
        try:
            show_last = int(str(self.logger_show_last_combo.getSelectedItem()))
        except (TypeError, ValueError):
            show_last = 1000
    if show_last < 100:
        show_last = 100
    if show_last > 50000:
        show_last = 50000

    with self.logger_lock:
        snapshot = list(self.logger_events)
        dropped = int(getattr(self, "logger_dropped_count", 0) or 0)
        last_prune = self._ascii_safe(getattr(self, "logger_last_prune_ts", "") or "")
        tag_rules_snapshot = list(getattr(self, "logger_tag_rules", []) or [])
    compiled_tag_rules = self._compile_logger_tag_rules(tag_rules_snapshot)

    matched = []
    grep_total_hits = 0
    endpoint_tag_map = {}
    for event in snapshot:
        event_view = event
        event_view["tags"] = self._logger_apply_tag_rules(event_view, compiled_tag_rules)
        if not self._ascii_safe(event_view.get("base_tags") or "").strip():
            event_view["base_tags"] = event_view["tags"]
        endpoint_key = self._ascii_safe(event_view.get("endpoint_key") or "").strip()
        tag_tokens = self._logger_extract_tag_tokens(event_view.get("tags") or "")
        event_view["_tag_tokens"] = list(tag_tokens)
        if endpoint_key and tag_tokens:
            collected = endpoint_tag_map.get(endpoint_key)
            if collected is None:
                collected = set()
                endpoint_tag_map[endpoint_key] = collected
            for safe_token in tag_tokens:
                collected.add(safe_token)
        if self._logger_event_matches_filters(
            event_view,
            filter_text,
            selected_tool,
            selected_method,
            selected_status,
            compiled_regex=compiled_regex,
            search_request=search_request,
            search_response=search_response,
            scope_only=scope_only,
            noise_filter_enabled=noise_filter_enabled,
            min_len=min_len,
            max_len=max_len,
        ):
            grep_total_hits += int(event_view.get("_grep_req", 0) or 0) + int(
                event_view.get("_grep_resp", 0) or 0
            )
            matched.append(event_view)

    truncated = 0
    if len(matched) > show_last:
        truncated = len(matched) - show_last
        matched = matched[-show_last:]

    recon_tags_changed = False
    if endpoint_tag_map:
        with self.lock:
            for endpoint_key, derived_tags in endpoint_tag_map.items():
                merged = set(self.endpoint_tags.get(endpoint_key, []) or [])
                before = set(merged)
                merged.update(derived_tags)
                if merged != before:
                    self.endpoint_tags[endpoint_key] = sorted(merged)
                    recon_tags_changed = True

    with self.logger_lock:
        self.logger_view_events = list(matched)
    if recon_tags_changed:
        self._schedule_capture_ui_refresh()

    model = getattr(self, "logger_table_model", None)
    if model is not None:
        def _tag_cell_text(event_obj):
            tokens = event_obj.get("_tag_tokens")
            if not isinstance(tokens, list):
                tokens = self._logger_extract_tag_tokens(event_obj.get("tags") or "")
            if not tokens:
                return ""
            return ", ".join(tokens[:8])

        model.setRowCount(0)
        for event in matched:
            model.addRow(
                [
                    str(event.get("seq", "")),
                    self._ascii_safe(event.get("time") or ""),
                    self._ascii_safe(event.get("tool") or ""),
                    self._ascii_safe(event.get("method") or ""),
                    self._ascii_safe(event.get("host") or ""),
                    self._ascii_safe(event.get("path") or ""),
                    self._ascii_safe(event.get("query") or "")[:70],
                    str(event.get("status", "")),
                    str(event.get("response_length", "")),
                    self._ascii_safe(event.get("inferred_type") or ""),
                    str(int(event.get("_grep_req", 0) or 0)),
                    str(int(event.get("_grep_resp", 0) or 0)),
                    _tag_cell_text(event),
                ]
            )

    stats_label = getattr(self, "logger_stats_label", None)
    if stats_label is not None:
        suffix = ""
        if truncated > 0:
            suffix = " | Hidden by Show Last: {}".format(truncated)
        prune_text = " | Last Prune: {}".format(last_prune) if last_prune else ""
        grep_text = ""
        if compiled_regex is not None:
            grep_text = " | Grep: /{}/ hits={}".format(regex_pattern.strip(), grep_total_hits)
        elif regex_error_text:
            grep_text = " | Grep error: {}".format(regex_error_text[:64])
        scope_text = " | Scope: in-scope only" if scope_only else ""
        len_text = ""
        if (min_len is not None) or (max_len is not None):
            len_text = " | Len: {}..{}".format(
                str(min_len) if min_len is not None else "0",
                str(max_len) if max_len is not None else "inf",
            )
        noise_text = " | Noise: on" if noise_filter_enabled else " | Noise: off"
        logging_text = (
            " | Logging: on" if bool(getattr(self, "logger_capture_enabled", True)) else " | Logging: off"
        )
        stats_label.setText(
            "Events: {} | Showing: {} | Dropped: {}{}{}{}{}{}{}{}".format(
                len(snapshot),
                len(matched),
                dropped,
                suffix,
                prune_text,
                grep_text,
                scope_text,
                len_text,
                noise_text,
                logging_text,
            )
        )
    if noise_toggle_changed:
        self.refresh_view()

def _logger_show_selected(self):
    """Render selected logger row request/response previews."""
    table = getattr(self, "logger_table", None)
    if table is None:
        return
    view_row = int(table.getSelectedRow())
    if view_row < 0:
        return
    try:
        row = int(table.convertRowIndexToModel(view_row))
    except (TypeError, ValueError):
        row = view_row
    with self.logger_lock:
        if row >= len(self.logger_view_events):
            return
        event = dict(self.logger_view_events[row])
    request_area = getattr(self, "logger_request_area", None)
    response_area = getattr(self, "logger_response_area", None)
    if request_area is not None:
        request_area.setText(self._ascii_safe(event.get("request_preview") or ""))
        request_area.setCaretPosition(0)
    if response_area is not None:
        response_area.setText(self._ascii_safe(event.get("response_preview") or ""))
        response_area.setCaretPosition(0)

def _logger_selected_indices(self):
    """Return selected row indices from logger table."""
    table = getattr(self, "logger_table", None)
    if table is None:
        return []
    rows = []
    try:
        selected_rows = table.getSelectedRows()
        for view_idx in list(selected_rows or []):
            view_idx_int = int(view_idx)
            if view_idx_int < 0:
                continue
            try:
                model_idx = int(table.convertRowIndexToModel(view_idx_int))
            except (TypeError, ValueError):
                model_idx = view_idx_int
            if model_idx >= 0:
                rows.append(model_idx)
    except Exception as e:
        self._callbacks.printError("Logger selection read error: {}".format(str(e)))
    if not rows:
        one_view = int(table.getSelectedRow())
        if one_view >= 0:
            try:
                one_model = int(table.convertRowIndexToModel(one_view))
            except (TypeError, ValueError):
                one_model = one_view
            rows = [one_model]
    dedup = []
    seen = set()
    for idx in rows:
        if idx not in seen:
            seen.add(idx)
            dedup.append(idx)
    return dedup

def _logger_select_all_rows(self):
    """Select all currently visible rows in logger table."""
    table = getattr(self, "logger_table", None)
    model = getattr(self, "logger_table_model", None)
    if table is None or model is None:
        return
    count = int(model.getRowCount() or 0)
    if count <= 0:
        return
    table.setRowSelectionInterval(0, count - 1)
    self.log_to_ui("[*] Logger: selected {} visible rows".format(count))

def _logger_event_full_url(self, event):
    """Build full URL string from one logger event."""
    protocol = self._ascii_safe(event.get("protocol") or "https", lower=True).strip()
    if protocol not in ["http", "https"]:
        protocol = "https"
    host = self._ascii_safe(event.get("host") or "", lower=True).strip()
    path = self._ascii_safe(event.get("path") or "/")
    query = self._ascii_safe(event.get("query") or "")
    port = int(event.get("port", 0) or 0)
    if not host:
        return path
    if not path.startswith("/"):
        path = "/" + path
    if port <= 0:
        port = 443 if protocol == "https" else 80
    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
        url_text = "{}://{}{}".format(protocol, host, path)
    else:
        url_text = "{}://{}:{}{}".format(protocol, host, port, path)
    if query:
        url_text += "?" + query
    return url_text

def _entry_full_url(self, entry):
    """Build full URL from one Recon entry."""
    protocol = self._ascii_safe(entry.get("protocol") or "https", lower=True).strip()
    if protocol not in ["http", "https"]:
        protocol = "https"
    host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/")
    query = self._ascii_safe(entry.get("query_string") or "")
    try:
        port = int(entry.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if not host:
        return path
    if not path.startswith("/"):
        path = "/" + path
    if port <= 0:
        port = 443 if protocol == "https" else 80
    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
        url_text = "{}://{}{}".format(protocol, host, path)
    else:
        url_text = "{}://{}:{}{}".format(protocol, host, port, path)
    if query:
        url_text += "?" + query
    return url_text

def _shell_single_quote(self, text):
    raw = self._ascii_safe(text or "")
    return "'" + raw.replace("'", "'\"'\"'") + "'"

def _build_entry_request_text(self, entry):
    """Reconstruct full raw HTTP request text from one Recon entry."""
    method = self._ascii_safe(entry.get("method") or "GET").upper().strip() or "GET"
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    query = self._ascii_safe(entry.get("query_string") or "")
    target = path + ("?" + query if query else "")

    headers = dict(entry.get("headers") or {})
    host = self._ascii_safe(entry.get("host") or "").strip()
    has_host = False
    has_content_length = False
    header_lines = []
    for name, value in headers.items():
        key = self._ascii_safe(name or "")
        data = self._ascii_safe(value or "")
        key_lower = self._ascii_safe(key, lower=True)
        if key_lower == "host":
            has_host = True
        if key_lower == "content-length":
            has_content_length = True
        if key and data:
            header_lines.append("{}: {}".format(key, data))
    if host and (not has_host):
        header_lines.insert(0, "Host: {}".format(host))

    body = self._ascii_safe(entry.get("request_body") or "")
    if body and (not has_content_length):
        header_lines.append("Content-Length: {}".format(len(body)))
    request_lines = ["{} {} HTTP/1.1".format(method, target)] + header_lines + ["", body]
    return "\r\n".join(request_lines)

def _build_entry_curl_command(self, entry):
    """Build a ready-to-run curl command from one Recon entry."""
    method = self._ascii_safe(entry.get("method") or "GET").upper().strip() or "GET"
    url_text = self._entry_full_url(entry)
    headers = dict(entry.get("headers") or {})
    body = self._ascii_safe(entry.get("request_body") or "")

    parts = [
        "curl -i -sS -k -X {}".format(method),
        self._shell_single_quote(url_text),
    ]
    for name, value in headers.items():
        key = self._ascii_safe(name or "")
        data = self._ascii_safe(value or "")
        if not key or (not data):
            continue
        if self._ascii_safe(key, lower=True) == "content-length":
            continue
        parts.append("-H {}".format(self._shell_single_quote("{}: {}".format(key, data))))
    if body:
        parts.append("--data-raw {}".format(self._shell_single_quote(body)))
    return " \\\n  ".join(parts)

def _build_ai_request_analysis_prompt(self, endpoint_key, entry, source_label):
    endpoint = self._ascii_safe(endpoint_key or "")
    source = self._ascii_safe(source_label or "Recon")
    method = self._ascii_safe(entry.get("method") or "GET").upper().strip() or "GET"
    url_text = self._entry_full_url(entry)
    lines = [
        "You are a senior API security tester.",
        "Analyze the supplied HTTP request and response context from Burp capture data.",
        "Focus on realistic exploitability and high-signal API weaknesses (BOLA/IDOR, authz/authn, mass assignment, injection, SSRF, business logic, race, data exposure).",
        "Use this target context:",
        "- Source: {}".format(source),
        "- Endpoint Key: {}".format(endpoint),
        "- Request: {} {}".format(method, url_text),
        "",
        "Return in this format:",
        "1) Top findings (severity + confidence + evidence)",
        "2) Exact reproduction steps",
        "3) Optional crafted payload variations",
        "4) Mitigations mapped to each finding",
        "5) Short follow-up test checklist",
    ]
    return "\n".join(lines)

def _build_ai_request_export(self, endpoint_key, entry, source_label):
    request_text = self._build_entry_request_text(entry)
    curl_text = self._build_entry_curl_command(entry)
    prompt_text = self._build_ai_request_analysis_prompt(endpoint_key, entry, source_label)

    status = int(entry.get("response_status", 0) or 0)
    response_headers = dict(entry.get("response_headers") or {})
    response_body = self._ascii_safe(entry.get("response_body") or "")
    response_lines = ["HTTP {}".format(status)]
    for name, value in response_headers.items():
        key = self._ascii_safe(name or "")
        data = self._ascii_safe(value or "")
        if key and data:
            response_lines.append("{}: {}".format(key, data))
    if response_body:
        response_lines.append("")
        if len(response_body) > 6000:
            response_lines.append(response_body[:6000] + "\n... [truncated]")
        else:
            response_lines.append(response_body)
    response_text = "\n".join(response_lines)

    output_lines = [
        "=== AI REQUEST ANALYSIS PACK ===",
        "Generated: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")),
        "Source: {}".format(self._ascii_safe(source_label or "Recon")),
        "Endpoint: {}".format(self._ascii_safe(endpoint_key or "")),
        "URL: {}".format(self._entry_full_url(entry)),
        "",
        "SMART PROMPT:",
        prompt_text,
        "",
        "READY CURL:",
        curl_text,
        "",
        "FULL HTTP REQUEST:",
        request_text,
        "",
        "SAMPLE HTTP RESPONSE:",
        response_text,
    ]
    return "\n".join(output_lines)

def _send_endpoint_to_ai(self, endpoint_key, source_label="Recon", entry_override=None):
    """Export one endpoint as an AI-ready request analysis package."""
    endpoint = self._ascii_safe(endpoint_key or "").strip()
    if not endpoint:
        self.log_to_ui("[!] AI export: missing endpoint key")
        return

    selected_entry = None
    if isinstance(entry_override, dict):
        selected_entry = dict(entry_override)
    if selected_entry is None:
        with self.lock:
            entries = self.api_data.get(endpoint, [])
        if isinstance(entries, list) and entries:
            selected_entry = dict(entries[-1])
        elif isinstance(entries, dict) and entries:
            selected_entry = dict(entries)
    if not isinstance(selected_entry, dict):
        self.log_to_ui("[!] AI export: endpoint not found ({})".format(endpoint))
        return

    package_text = self._build_ai_request_export(endpoint, selected_entry, source_label)
    if hasattr(self, "_show_ai_copy_exit_dialog"):
        self._show_ai_copy_exit_dialog(
            "AI Request Export - {}".format(endpoint),
            package_text,
            rows=30,
            cols=140,
        )
    else:
        self._show_text_dialog(
            "AI Request Export - {}".format(endpoint),
            package_text,
            rows=30,
            cols=140,
        )
    self.log_to_ui("[+] AI request export ready for {}".format(endpoint))

def _logger_send_selected_to_ai(self):
    """Export selected Logger row as AI-ready request analysis package."""
    indices = self._logger_selected_indices()
    if not indices:
        self.log_to_ui("[!] Logger: select a row first")
        return
    with self.logger_lock:
        view_snapshot = list(self.logger_view_events or [])
    first_idx = int(indices[0] if indices else -1)
    if first_idx < 0 or first_idx >= len(view_snapshot):
        self.log_to_ui("[!] Logger: selected row unavailable")
        return
    event = dict(view_snapshot[first_idx] or {})
    endpoint_key = self._ascii_safe(event.get("endpoint_key") or "").strip()
    if not endpoint_key:
        endpoint_key = "{}:{}".format(
            self._ascii_safe(event.get("method") or "GET").upper().strip() or "GET",
            self._normalize_path(self._ascii_safe(event.get("path") or "/")),
        )

    selected_entry = None
    with self.lock:
        entries = list(self.api_data.get(endpoint_key, []) or [])
    if entries:
        event_method = self._ascii_safe(event.get("method") or "GET").upper().strip()
        event_path = self._normalize_path(self._ascii_safe(event.get("path") or "/"))
        event_query = self._ascii_safe(event.get("query") or "")
        for candidate in reversed(entries):
            c_method = self._ascii_safe(candidate.get("method") or "GET").upper().strip()
            c_path = self._normalize_path(
                self._ascii_safe(candidate.get("path") or candidate.get("normalized_path") or "/")
            )
            c_query = self._ascii_safe(candidate.get("query_string") or "")
            if c_method == event_method and c_path == event_path and c_query == event_query:
                selected_entry = dict(candidate)
                break
        if selected_entry is None:
            selected_entry = dict(entries[-1])

    if selected_entry is None:
        selected_entry = {
            "method": self._ascii_safe(event.get("method") or "GET").upper().strip() or "GET",
            "path": self._ascii_safe(event.get("path") or "/"),
            "normalized_path": self._normalize_path(self._ascii_safe(event.get("path") or "/")),
            "host": self._ascii_safe(event.get("host") or "", lower=True).strip(),
            "protocol": self._ascii_safe(event.get("protocol") or "https", lower=True).strip(),
            "port": int(event.get("port", 0) or 0),
            "query_string": self._ascii_safe(event.get("query") or ""),
            "headers": {},
            "request_body": "",
            "response_status": int(event.get("status", 0) or 0),
            "response_headers": {},
            "response_body": self._ascii_safe(event.get("response_preview") or ""),
            "response_length": int(event.get("response_length", 0) or 0),
        }
    self._send_endpoint_to_ai(endpoint_key, source_label="Logger", entry_override=selected_entry)

def _logger_copy_selected_rows(self):
    """Copy selected logger rows to clipboard as TSV."""
    indices = self._logger_selected_indices()
    if not indices:
        self.log_to_ui("[!] Logger: no selected rows to copy")
        return
    with self.logger_lock:
        view_snapshot = list(self.logger_view_events or [])
    lines = ["seq\ttime\tmethod\turl\tstatus\tlen\ttags"]
    copied = 0
    for idx in indices:
        if idx < 0 or idx >= len(view_snapshot):
            continue
        event = view_snapshot[idx]
        line = "\t".join(
            [
                self._ascii_safe(event.get("seq") or ""),
                self._ascii_safe(event.get("time") or ""),
                self._ascii_safe(event.get("method") or ""),
                self._ascii_safe(self._logger_event_full_url(event)),
                self._ascii_safe(event.get("status") or ""),
                self._ascii_safe(event.get("response_length") or ""),
                ", ".join(self._logger_extract_tag_tokens(event.get("tags") or "")),
            ]
        )
        lines.append(line)
        copied += 1
    if copied <= 0:
        self.log_to_ui("[!] Logger: selected rows unavailable")
        return
    self._copy_to_clipboard("\n".join(lines) + "\n")
    self.log_to_ui("[+] Logger: copied {} selected rows".format(copied))

def _resolve_recon_endpoint_key(
    self, endpoint_key, method_hint=None, path_hint=None, host_hint=None
):
    """Resolve equivalent endpoint key variants to the canonical Recon cache key."""

    def _clean_key(raw_key):
        key_text = self._ascii_safe(raw_key or "").strip()
        if not key_text:
            return ""
        if " [" in key_text:
            key_text = key_text.split(" [", 1)[0].strip()
        if " @ " in key_text:
            key_text = key_text.split(" @ ", 1)[0].strip()
        return key_text

    def _split_key(raw_key):
        key_text = _clean_key(raw_key)
        if ":" not in key_text:
            return "", ""
        method_text, path_text = key_text.split(":", 1)
        method_text = self._ascii_safe(method_text or "", lower=False).upper().strip()
        path_text = self._ascii_safe(path_text or "").strip() or "/"
        if not path_text.startswith("/"):
            path_text = "/" + path_text
        return method_text, self._normalize_path(path_text)

    def _path_variants(raw_path):
        path_text = self._ascii_safe(raw_path or "").strip()
        if not path_text:
            return set()
        if not path_text.startswith("/"):
            path_text = "/" + path_text
        normalized = self._normalize_path(path_text)
        variants = set([normalized])
        if normalized != "/":
            if normalized.endswith("/"):
                variants.add(normalized[:-1] or "/")
            else:
                variants.add(normalized + "/")
        return variants

    cleaned_key = _clean_key(endpoint_key)
    key_method, key_path = _split_key(cleaned_key)
    hint_method = self._ascii_safe(method_hint or key_method or "", lower=False).upper().strip()
    hint_host = self._ascii_safe(host_hint or "", lower=True).strip()
    path_candidates = set()
    path_candidates.update(_path_variants(path_hint))
    path_candidates.update(_path_variants(key_path))
    if (not path_candidates) and key_path:
        path_candidates.add(key_path)

    if hint_method and path_candidates:
        for candidate_path in list(path_candidates):
            if candidate_path and (not candidate_path.startswith("/")):
                path_candidates.add("/" + candidate_path)

    with self.lock:
        if cleaned_key and cleaned_key in self.api_data:
            return cleaned_key
        if hint_method and path_candidates:
            preferred_path = self._normalize_path(
                self._ascii_safe(path_hint or key_path or "/")
            )
            preferred_key = "{}:{}".format(hint_method, preferred_path)
            if preferred_key in self.api_data:
                return preferred_key
            for candidate_path in list(path_candidates):
                candidate_key = "{}:{}".format(hint_method, candidate_path)
                if candidate_key in self.api_data:
                    return candidate_key

        if (not hint_method) and (not path_candidates):
            return cleaned_key

        best_match = ""
        best_score = 0
        for candidate_key in list(self.api_data.keys()):
            cand_method, cand_path = _split_key(candidate_key)
            if hint_method and cand_method and cand_method != hint_method:
                continue
            if path_candidates and cand_path not in path_candidates:
                continue
            score = 0
            if cleaned_key and candidate_key == cleaned_key:
                score += 100
            if path_candidates and cand_path in path_candidates:
                score += 50
            if hint_method and cand_method == hint_method:
                score += 20
            if hint_host:
                entries = self.api_data.get(candidate_key, [])
                sample = None
                if isinstance(entries, list) and entries:
                    sample = entries[-1]
                elif isinstance(entries, dict):
                    sample = entries
                sample_host = ""
                if isinstance(sample, dict):
                    sample_host = self._ascii_safe(sample.get("host") or "", lower=True).strip()
                if sample_host and sample_host == hint_host:
                    score += 10
            if score > best_score:
                best_score = score
                best_match = candidate_key
        if best_match and best_score > 0:
            return best_match
    return cleaned_key

def _show_recon_missing_detail_message(self, endpoint_key, reason=None):
    """Render explicit detail message when Recon cache has no data for selected endpoint."""
    key_text = self._ascii_safe(endpoint_key or "").strip() or "<unknown>"
    reason_text = self._ascii_safe(reason or "").strip()
    lines = []
    lines.append("=" * 80)
    lines.append("ENDPOINT DETAILS UNAVAILABLE")
    lines.append("=" * 80)
    lines.append("Endpoint: {}".format(key_text))
    lines.append("")
    lines.append("Recon does not currently have cached data for this endpoint.")
    if reason_text:
        lines.append("Reason: {}".format(reason_text))
    lines.append("")
    lines.append("Suggested recovery:")
    lines.append("1) Run Recon: Clear + Refill (or keep Autopopulate enabled).")
    lines.append("2) Run Logger: Backfill History.")
    lines.append("3) Retry: Endpoint Detail (button or double-click).")
    message = "\n".join(lines)

    details_area = getattr(self, "details_area", None)
    if details_area is not None:
        details_area.setText(message)
        details_area.setCaretPosition(0)
    request_area = getattr(self, "logger_request_area", None)
    if request_area is not None:
        request_area.setText(message)
        request_area.setCaretPosition(0)
    response_area = getattr(self, "logger_response_area", None)
    if response_area is not None:
        response_area.setText(message)
        response_area.setCaretPosition(0)

    def show_popup():
        try:
            JOptionPane.showMessageDialog(
                getattr(self, "_panel", None),
                message,
                "Recon Endpoint Details Unavailable",
                JOptionPane.WARNING_MESSAGE,
            )
        except Exception as popup_err:
            self._callbacks.printError(
                "Recon missing-detail popup error: {}".format(str(popup_err))
            )

    try:
        if SwingUtilities.isEventDispatchThread():
            show_popup()
        else:
            SwingUtilities.invokeLater(show_popup)
    except Exception as popup_schedule_err:
        self._callbacks.printError(
            "Recon missing-detail popup schedule error: {}".format(
                str(popup_schedule_err)
            )
        )
        show_popup()

    self.log_to_ui("[!] Recon has no data for endpoint: {}".format(key_text))

def _recon_show_selected_in_logger(self):
    """Open Logger tab and show request/response preview for selected Recon endpoint."""
    endpoint_key = self._ascii_safe(self._get_selected_endpoint_key() or "").strip()
    if not endpoint_key:
        if hasattr(self, "_recon_set_detail_redirect_text"):
            self._recon_set_detail_redirect_text(None)
        self.log_to_ui("[!] Recon: select an endpoint first")
        return

    self._recon_selected_endpoint_key = endpoint_key
    if hasattr(self, "_recon_set_detail_redirect_text"):
        self._recon_set_detail_redirect_text(endpoint_key)

    def _focus_logger_tab():
        tabbed = getattr(self, "tabbed_pane", None)
        if tabbed is None:
            return
        try:
            for idx in range(int(tabbed.getTabCount() or 0)):
                title = self._ascii_safe(tabbed.getTitleAt(idx) or "", lower=True)
                if title == "logger":
                    tabbed.setSelectedIndex(idx)
                    break
        except Exception as tab_err:
            self._callbacks.printError(
                "Recon->Logger tab focus error: {}".format(str(tab_err))
            )

    def _select_logger_row_for_endpoint(target_key):
        table = getattr(self, "logger_table", None)
        if table is None:
            return False
        with self.logger_lock:
            snapshot = list(self.logger_view_events or [])
        model_idx = -1
        for idx, event in enumerate(snapshot):
            candidate = self._ascii_safe(event.get("endpoint_key") or "").strip()
            if candidate == target_key:
                model_idx = idx
                break
        if model_idx < 0:
            return False
        try:
            view_idx = int(table.convertRowIndexToView(model_idx))
        except (TypeError, ValueError):
            view_idx = model_idx
        if view_idx < 0:
            return False
        try:
            table.setRowSelectionInterval(view_idx, view_idx)
            table.scrollRectToVisible(table.getCellRect(view_idx, 0, True))
        except Exception as select_err:
            self._callbacks.printError(
                "Recon->Logger row select error: {}".format(str(select_err))
            )
            return False
        self._logger_show_selected()
        return True

    try:
        self._refresh_logger_view()
    except Exception as refresh_err:
        self._callbacks.printError(
            "Recon->Logger refresh error: {}".format(str(refresh_err))
        )

    if _select_logger_row_for_endpoint(endpoint_key):
        _focus_logger_tab()
        self.log_to_ui("[+] Recon->Logger detail: {}".format(endpoint_key))
        return

    # If filtered/no matching logger row, seed one lightweight logger event from Recon.
    with self.lock:
        entries = list(self.api_data.get(endpoint_key) or [])
        tags = list(self.endpoint_tags.get(endpoint_key) or [])
    if entries:
        seed_entry = self._get_entry(entries)
        self._logger_capture_event(
            endpoint_key,
            seed_entry,
            tags=tags,
            bypass_capture=True,
            sync_recon=False,
        )
        self._refresh_logger_view()
        if _select_logger_row_for_endpoint(endpoint_key):
            _focus_logger_tab()
            self.log_to_ui("[*] Recon->Logger: seeded logger row for {}".format(endpoint_key))
            return

    _focus_logger_tab()
    message = (
        "No Logger row matched selected Recon endpoint.\n"
        "Try Logger 'Backfill History' or relax Logger filters."
    )
    request_area = getattr(self, "logger_request_area", None)
    response_area = getattr(self, "logger_response_area", None)
    if request_area is not None:
        request_area.setText(message)
        request_area.setCaretPosition(0)
    if response_area is not None:
        response_area.setText(message)
        response_area.setCaretPosition(0)
    self.log_to_ui("[!] Recon->Logger: no matching logger detail for {}".format(endpoint_key))

def _logger_show_endpoint_detail(self):
    """Open Recon endpoint detail view for selected logger row."""
    indices = self._logger_selected_indices()
    if not indices:
        self.log_to_ui("[!] Logger: select a row first")
        return

    with self.logger_lock:
        view_snapshot = list(self.logger_view_events or [])
    first_idx = int(indices[0] if indices else -1)
    if first_idx < 0 or first_idx >= len(view_snapshot):
        self.log_to_ui("[!] Logger: selected row unavailable")
        return

    event = dict(view_snapshot[first_idx] or {})
    endpoint_key = self._ascii_safe(event.get("endpoint_key") or "").strip()
    event_method = self._ascii_safe(event.get("method") or "GET").upper().strip() or "GET"
    event_path = self._ascii_safe(event.get("path") or "/").strip() or "/"
    event_host = self._ascii_safe(event.get("host") or "", lower=True).strip()
    if not endpoint_key:
        endpoint_key = "{}:{}".format(event_method, self._normalize_path(event_path))
    resolved_key = self._resolve_recon_endpoint_key(
        endpoint_key,
        method_hint=event_method,
        path_hint=event_path,
        host_hint=event_host,
    )
    if resolved_key:
        endpoint_key = resolved_key

    with self.lock:
        exists = endpoint_key in self.api_data
    if not exists:
        event_tags = self._logger_extract_tag_tokens(event.get("tags") or "")
        recovered_entry = {
            "method": self._ascii_safe(event.get("method") or "GET").upper().strip(),
            "path": self._ascii_safe(event.get("path") or "/"),
            "normalized_path": self._normalize_path(
                self._ascii_safe(event.get("path") or "/")
            ),
            "host": self._ascii_safe(event.get("host") or "", lower=True).strip(),
            "protocol": self._ascii_safe(event.get("protocol") or "https", lower=True),
            "port": int(event.get("port", 0) or 0),
            "query_string": self._ascii_safe(event.get("query") or ""),
            "headers": {},
            "request_body": self._ascii_safe(event.get("request_preview") or ""),
            "response_status": int(event.get("status", 0) or 0),
            "response_headers": {},
            "response_body": self._ascii_safe(event.get("response_preview") or ""),
            "response_length": int(event.get("response_length", 0) or 0),
            "response_time_ms": 0,
            "source_tool": self._ascii_safe(event.get("tool") or "Logger"),
            "content_type": self._ascii_safe(
                event.get("inferred_type") or "", lower=True
            ),
        }
        recovered = self._sync_recon_entry_from_logger(
            endpoint_key, recovered_entry, tags=event_tags
        )
        endpoint_key = self._resolve_recon_endpoint_key(
            endpoint_key,
            method_hint=event_method,
            path_hint=event_path,
            host_hint=event_host,
        )
        with self.lock:
            exists = endpoint_key in self.api_data
        if not exists:
            self._show_recon_missing_detail_message(
                endpoint_key,
                reason="Selected Logger row could not be synced into Recon cache.",
            )
            return
        if recovered:
            self.log_to_ui("[*] Logger: synced selected row into Recon cache")

    self.show_endpoint_details(endpoint_key)
    tabbed = getattr(self, "tabbed_pane", None)
    if tabbed is not None:
        try:
            for idx in range(int(tabbed.getTabCount() or 0)):
                if self._ascii_safe(tabbed.getTitleAt(idx) or "", lower=True) == "recon":
                    tabbed.setSelectedIndex(idx)
                    break
        except Exception as tab_err:
            self._callbacks.printError(
                "Logger endpoint detail tab switch error: {}".format(str(tab_err))
            )
    self.log_to_ui("[+] Logger: opened endpoint detail for {}".format(endpoint_key))

def _logger_send_selected_to_repeater(self):
    """Send selected logger row endpoint to Burp Repeater."""
    indices = self._logger_selected_indices()
    if not indices:
        self.log_to_ui("[!] Logger: select one or more rows first")
        return

    with self.logger_lock:
        view_snapshot = list(self.logger_view_events or [])
    endpoint_keys = []
    seen = set()
    for row in indices:
        if row < 0 or row >= len(view_snapshot):
            continue
        endpoint_key = self._ascii_safe(
            view_snapshot[row].get("endpoint_key") or ""
        ).strip()
        if endpoint_key and endpoint_key not in seen:
            seen.add(endpoint_key)
            endpoint_keys.append(endpoint_key)
    if not endpoint_keys:
        self.log_to_ui("[!] Logger: endpoint key missing for selected rows")
        return
    sent = 0
    for endpoint_key in endpoint_keys:
        self._send_endpoint_to_repeater(endpoint_key)
        sent += 1
        if sent >= 40:
            break
    self.log_to_ui(
        "[+] Logger: sent {} selected endpoints to Repeater".format(sent)
    )

def _clear_logger_logs(self, emit_log=True):
    """Clear in-memory logger events and table output."""
    cleared = 0
    with self.logger_lock:
        cleared = int(len(self.logger_events or []))
        if hasattr(self.logger_events, "__class__") and hasattr(
            self.logger_events, "popleft"
        ):
            self.logger_events = self.logger_events.__class__()
        else:
            self.logger_events = []
        self.logger_view_events = []
        self.logger_dropped_count = 0
        self.logger_last_prune_ts = ""
    if getattr(self, "logger_table_model", None) is not None:
        self.logger_table_model.setRowCount(0)
    if getattr(self, "logger_request_area", None) is not None:
        self.logger_request_area.setText("")
    if getattr(self, "logger_response_area", None) is not None:
        self.logger_response_area.setText("")
    if getattr(self, "logger_stats_label", None) is not None:
        self.logger_stats_label.setText("Events: 0 | Showing: 0 | Dropped: 0")
    if emit_log:
        self.log_to_ui("[*] Logger++ events cleared")
    return cleared

def _export_logger_view(self):
    """Export current Logger++ filtered view as JSONL/JSON/CSV."""
    with self.logger_lock:
        events = list(self.logger_view_events or [])
    if not events:
        self.log_to_ui("[!] Logger++: no rows to export")
        return

    export_dir = self._get_export_dir("Logger_Export")
    if not export_dir:
        return
    export_format = "JSONL"
    export_combo = getattr(self, "logger_export_format_combo", None)
    if export_combo is not None:
        export_format = self._ascii_safe(
            str(export_combo.getSelectedItem()) if export_combo.getSelectedItem() is not None else "JSONL"
        ).upper()
    if export_format not in ["JSONL", "JSON", "CSV"]:
        export_format = "JSONL"

    if export_format == "JSON":
        filename = "logger_view.json"
    elif export_format == "CSV":
        filename = "logger_view.csv"
    else:
        filename = "logger_view.jsonl"
    filepath = os.path.join(export_dir, filename)
    writer = None
    try:
        writer = FileWriter(filepath)
        if export_format == "JSON":
            writer.write(json.dumps(events, indent=2))
        elif export_format == "CSV":
            columns = [
                "seq",
                "time",
                "tool",
                "method",
                "host",
                "path",
                "query",
                "status",
                "response_length",
                "inferred_type",
                "tags",
            ]
            writer.write(",".join(columns) + "\n")
            for event in events:
                row = []
                for key in columns:
                    value = self._ascii_safe(event.get(key) or "")
                    value = value.replace('"', '""')
                    row.append('"{}"'.format(value))
                writer.write(",".join(row) + "\n")
        else:
            for event in events:
                writer.write(json.dumps(event) + "\n")
        self.log_to_ui(
            "[+] Logger++ exported {} rows ({}) to {}".format(
                len(events), export_format, filepath
            )
        )
    except Exception as e:
        self.log_to_ui("[!] Logger++ export failed: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as close_err:
                self._callbacks.printError(
                    "Logger++ export close error: {}".format(str(close_err))
                )

def _recon_backfill_history(self, force=False):
    """Backfill Recon endpoint inventory from existing Burp Proxy history."""
    with self.lock:
        if getattr(self, "recon_backfill_running", False):
            self.log_to_ui("[*] Recon backfill already running")
            return
        if (not force) and getattr(self, "recon_backfilled_once", False):
            return
        before_endpoints = len(self.api_data)
        before_samples = 0
        for raw_entries in self.api_data.values():
            if isinstance(raw_entries, list):
                before_samples += len(raw_entries)
            elif raw_entries:
                before_samples += 1
        self.recon_backfill_running = True

    def _worker():
        scanned = 0
        skipped = 0
        errors = 0
        added_endpoints = 0
        added_samples = 0
        prior_suspend_logger = bool(
            getattr(self, "_suspend_logger_capture_during_recon_backfill", False)
        )
        setattr(self, "_suspend_logger_capture_during_recon_backfill", True)
        try:
            max_seed = int(getattr(self, "max_endpoints", 800) or 800) * 6
            max_seed = max(1000, min(120000, max_seed))
            messages = self._proxy_history_tail_window(max_seed)
            scanned = len(messages)

            for message_info in messages:
                try:
                    if not message_info:
                        skipped += 1
                        continue
                    request = message_info.getRequest()
                    response = message_info.getResponse()
                    if (not request) or (not response):
                        skipped += 1
                        continue
                    self._process_traffic(message_info, source_tool="Proxy")
                except Exception as row_err:
                    errors += 1
                    self._callbacks.printError(
                        "Recon backfill row error: {}".format(str(row_err))
                    )
        except Exception as e:
            errors += 1
            self._callbacks.printError("Recon backfill failed: {}".format(str(e)))
        finally:
            setattr(
                self,
                "_suspend_logger_capture_during_recon_backfill",
                prior_suspend_logger,
            )
            with self.lock:
                after_endpoints = len(self.api_data)
                after_samples = 0
                for raw_entries in self.api_data.values():
                    if isinstance(raw_entries, list):
                        after_samples += len(raw_entries)
                    elif raw_entries:
                        after_samples += 1
                added_endpoints = max(0, after_endpoints - before_endpoints)
                added_samples = max(0, after_samples - before_samples)
                self.recon_backfill_running = False
                if scanned > 0:
                    self.recon_backfilled_once = True
            self._schedule_capture_ui_refresh(force=True)
            if scanned == 0:
                self.log_to_ui("[*] Recon backfill: no proxy history available")
            else:
                self.log_to_ui(
                    "[+] Recon backfill complete: scanned {} | +endpoints {} | +samples {} | skipped {} | errors {}".format(
                        scanned,
                        added_endpoints,
                        added_samples,
                        skipped,
                        errors,
                    )
                )

    worker = threading.Thread(target=_worker, name="recon-backfill")
    worker.daemon = True
    worker.start()

def _logger_backfill_history(self, force=False):
    """Backfill Logger++ with existing Burp Proxy history for current project/session."""
    with self.logger_lock:
        if getattr(self, "logger_backfill_running", False):
            self.log_to_ui("[*] Logger++ backfill already running")
            return
        existing_count = len(getattr(self, "logger_events", []) or [])
        if (not force) and existing_count > 0:
            self.log_to_ui(
                "[*] Logger++ already has {} events (use Clear Logs then Backfill to reseed)".format(
                    existing_count
                )
            )
            return
        self.logger_backfill_running = True

    def _worker():
        scanned = 0
        added = 0
        skipped = 0
        errors = 0
        try:
            max_seed = int(getattr(self, "logger_max_rows", 20000) or 20000)
            max_seed = max(500, min(40000, max_seed * 3))
            messages = self._proxy_history_tail_window(max_seed)
            scanned = len(messages)

            for message_info in messages:
                try:
                    if not message_info:
                        skipped += 1
                        continue
                    request = message_info.getRequest()
                    response = message_info.getResponse()
                    if (not request) or (not response):
                        skipped += 1
                        continue

                    req_info = self._helpers.analyzeRequest(message_info)
                    resp_info = self._helpers.analyzeResponse(response)
                    url = req_info.getUrl()
                    if not url:
                        skipped += 1
                        continue

                    method = self._ascii_safe(req_info.getMethod() or "GET").upper()
                    path = self._ascii_safe(url.getPath() or "/")
                    normalized_path = self._normalize_path(path)
                    endpoint_key = "{}:{}".format(method, normalized_path)

                    entry = {
                        "method": method,
                        "path": path,
                        "normalized_path": normalized_path,
                        "host": self._ascii_safe(url.getHost() or "", lower=True),
                        "protocol": self._ascii_safe(url.getProtocol() or "", lower=True),
                        "port": int(url.getPort() or 0),
                        "query_string": self._ascii_safe(url.getQuery() or ""),
                        "headers": self._extract_headers(req_info),
                        "request_body": "",
                        "response_status": int(resp_info.getStatusCode() or 0),
                        "response_headers": self._extract_response_headers(resp_info),
                        "response_body": "",
                        "response_length": max(
                            0, len(response) - int(resp_info.getBodyOffset() or 0)
                        ),
                        "source_tool": "Proxy",
                        "content_type": self._get_content_type(resp_info),
                    }
                    with self.lock:
                        tags = list(self.endpoint_tags.get(endpoint_key, []) or [])
                    self._logger_capture_event(
                        endpoint_key,
                        entry,
                        tags=tags,
                        bypass_capture=True,
                        sync_recon=False,
                    )
                    added += 1
                except Exception as row_err:
                    errors += 1
                    self._callbacks.printError(
                        "Logger++ backfill row error: {}".format(str(row_err))
                    )
        except Exception as e:
            errors += 1
            self._callbacks.printError("Logger++ backfill failed: {}".format(str(e)))
        finally:
            self._logger_trim_if_needed(force=True)
            self._schedule_logger_ui_refresh(force=True)
            with self.logger_lock:
                self.logger_backfill_running = False
                if added > 0:
                    self.logger_backfilled_once = True
            if scanned == 0:
                self.log_to_ui("[*] Logger++ backfill: no proxy history available")
            else:
                self.log_to_ui(
                    "[+] Logger++ backfill complete: scanned {} | added {} | skipped {} | errors {}".format(
                        scanned, added, skipped, errors
                    )
                )

    worker = threading.Thread(target=_worker, name="logger-backfill")
    worker.daemon = True
    worker.start()

def _open_target_base_scope_popup(self):
    """Open popup editor for multiline base URL/host targeting scope."""
    current_text = "\n".join(self.target_base_scope_lines)
    editor = JTextArea(current_text, 12, 60)
    editor.setLineWrap(False)
    editor.setWrapStyleWord(False)

    content = JPanel(BorderLayout(0, 6))
    content.add(
        JLabel(
            "Enter one base URL/host per line (examples: https://www.allocine.fr, allocine.fr)"
        ),
        BorderLayout.NORTH,
    )
    content.add(JScrollPane(editor), BorderLayout.CENTER)

    decision = JOptionPane.showConfirmDialog(
        self._panel,
        content,
        "Target Base URLs",
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
    )
    if decision != JOptionPane.OK_OPTION:
        return

    parsed = self._parse_target_base_scope_text(editor.getText())
    self.target_base_scope_lines = parsed["lines"]
    self.target_base_scope_hosts = parsed["hosts"]
    self.target_base_scope_bases = parsed["bases"]
    self._save_text_setting(
        "target_base_scope_lines", "\n".join(self.target_base_scope_lines)
    )

    line_count = len(self.target_base_scope_lines)
    if line_count == 0:
        self.log_to_ui("[*] Target base scope cleared")
        return

    scope_msg = (
        "[+] Target base scope updated: {} lines, {} hosts, {} base domains".format(
            line_count,
            len(self.target_base_scope_hosts),
            len(self.target_base_scope_bases),
        )
    )
    if parsed["invalid_count"] > 0:
        scope_msg += " ({} invalid ignored)".format(parsed["invalid_count"])
    self.log_to_ui(scope_msg)

def _sanitize_apihunter_custom_target_line(self, raw_line):
    """Sanitize one custom ApiHunter target line into canonical base URL."""
    line = self._ascii_safe(raw_line or "")
    line = re.sub(r"[\x00-\x1f\x7f]", "", line).strip()
    if not line or line.startswith("#"):
        return {
            "skip": True,
            "valid": False,
            "target": "",
            "error": "",
            "raw": "",
        }

    candidate = line.strip("'\"`")
    if len(candidate) > 2048:
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "entry too long",
            "raw": line,
        }
    if (" " in candidate) or ("\t" in candidate):
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "contains whitespace",
            "raw": line,
        }

    probe = candidate
    if "://" not in probe:
        probe = "https://" + probe.lstrip("/")
    try:
        parsed = URL(probe)
    except Exception as parse_err:
        _ = parse_err
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "not a valid URL",
            "raw": line,
        }

    scheme = self._ascii_safe(parsed.getProtocol() or "", lower=True).strip()
    if scheme not in ["http", "https"]:
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "only http/https schemes are allowed",
            "raw": line,
        }

    host = self._ascii_safe(parsed.getHost() or "", lower=True).strip()
    if host.endswith("."):
        host = host[:-1]
    if (
        (not host)
        or ("/" in host)
        or ("\\" in host)
        or (" " in host)
        or ("@" in host)
        or (not re.match(r"^[a-z0-9.\-:]+$", host))
    ):
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "invalid host",
            "raw": line,
        }
    if parsed.getUserInfo() is not None:
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "userinfo in URL is not allowed",
            "raw": line,
        }

    port = parsed.getPort()
    if port != -1 and (port < 1 or port > 65535):
        return {
            "skip": False,
            "valid": False,
            "target": "",
            "error": "invalid port",
            "raw": line,
        }
    if port == -1:
        port = 443 if scheme == "https" else 80

    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        target = "{}://{}/".format(scheme, host)
    else:
        target = "{}://{}:{}/".format(scheme, host, port)

    return {
        "skip": False,
        "valid": True,
        "target": target,
        "error": "",
        "raw": line,
    }

def _parse_apihunter_custom_targets_text(self, text, max_entries=20):
    """Parse multiline ApiHunter custom targets into canonical base URLs."""
    try:
        limit = int(max_entries)
    except Exception as limit_err:
        _ = limit_err
        limit = 20
    if limit < 1:
        limit = 20

    targets = []
    seen = set()
    invalid_lines = []
    for line_number, raw_line in enumerate(self._ascii_safe(text).splitlines(), 1):
        result = self._sanitize_apihunter_custom_target_line(raw_line)
        if result.get("skip"):
            continue
        if not result.get("valid"):
            invalid_lines.append(
                {
                    "line": line_number,
                    "value": self._ascii_safe(result.get("raw") or ""),
                    "error": self._ascii_safe(result.get("error") or "invalid URL"),
                }
            )
            continue
        target = self._ascii_safe(result.get("target") or "").strip()
        if not target:
            continue
        dedup_key = (
            self._apihunter_target_key(target)
            if hasattr(self, "_apihunter_target_key")
            else target
        )
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        targets.append(target)

    too_many_count = max(0, len(targets) - limit)
    if too_many_count > 0:
        targets = targets[:limit]

    return {
        "targets": targets,
        "invalid_lines": invalid_lines,
        "invalid_count": len(invalid_lines),
        "too_many_count": too_many_count,
    }

def _open_apihunter_custom_targets_popup(self):
    """Open popup editor for ApiHunter custom target base URLs."""
    current_text = "\n".join(getattr(self, "apihunter_custom_targets_lines", []) or [])
    editor = JTextArea(current_text, 12, 60)
    editor.setLineWrap(False)
    editor.setWrapStyleWord(False)

    content = JPanel(BorderLayout(0, 6))
    content.add(
        JLabel(
            "Enter one URL/host per line (max 20). Input is sanitized and normalized to base URLs."
        ),
        BorderLayout.NORTH,
    )
    content.add(JScrollPane(editor), BorderLayout.CENTER)

    decision = JOptionPane.showConfirmDialog(
        self._panel,
        content,
        "ApiHunter Custom Targets",
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
    )
    if decision != JOptionPane.OK_OPTION:
        return

    parsed = self._parse_apihunter_custom_targets_text(editor.getText(), max_entries=20)
    too_many_count = int(parsed.get("too_many_count", 0) or 0)
    invalid_lines = list(parsed.get("invalid_lines", []) or [])
    if too_many_count > 0:
        JOptionPane.showMessageDialog(
            self._panel,
            "ApiHunter custom targets accepts up to 20 entries. Remove {} extra line(s).".format(
                too_many_count
            ),
            "ApiHunter Custom Targets",
            JOptionPane.ERROR_MESSAGE,
        )
        return
    if invalid_lines:
        preview = []
        for item in invalid_lines[:5]:
            preview.append(
                "Line {}: {} ({})".format(
                    int(item.get("line", 0) or 0),
                    self._ascii_safe(item.get("value") or "")[:80],
                    self._ascii_safe(item.get("error") or "invalid URL"),
                )
            )
        if len(invalid_lines) > 5:
            preview.append("... and {} more invalid line(s)".format(len(invalid_lines) - 5))
        JOptionPane.showMessageDialog(
            self._panel,
            "Invalid URL entries detected:\n\n{}".format("\n".join(preview)),
            "ApiHunter Custom Targets",
            JOptionPane.ERROR_MESSAGE,
        )
        return

    self.apihunter_custom_targets_lines = list(parsed.get("targets", []) or [])
    self._save_text_setting(
        "apihunter_custom_targets_lines",
        "\n".join(self.apihunter_custom_targets_lines),
    )

    count = len(self.apihunter_custom_targets_lines)
    if count == 0:
        self.log_to_ui("[*] ApiHunter custom targets cleared")
    else:
        self.log_to_ui(
            "[+] ApiHunter custom targets updated: {} base URL(s)".format(count)
        )

def _get_apihunter_custom_targets_override(self):
    """Return current ApiHunter custom-target toggle state and sanitized targets."""
    enabled = False
    checkbox = getattr(self, "apihunter_use_custom_targets_checkbox", None)
    if checkbox is not None:
        enabled = bool(checkbox.isSelected())

    lines = list(getattr(self, "apihunter_custom_targets_lines", []) or [])
    parsed = self._parse_apihunter_custom_targets_text("\n".join(lines), max_entries=20)
    targets = list(parsed.get("targets", []) or [])
    invalid_count = int(parsed.get("invalid_count", 0) or 0)
    too_many_count = int(parsed.get("too_many_count", 0) or 0)

    error = ""
    if enabled:
        if invalid_count > 0:
            error = "ApiHunter custom targets contains invalid URL lines. Open 'Custom Targets...' and fix them."
        elif too_many_count > 0:
            error = "ApiHunter custom targets supports up to 20 entries."
        elif len(targets) == 0:
            error = "ApiHunter custom targets is enabled but no valid URLs are configured."

    return {
        "enabled": enabled,
        "targets": targets,
        "invalid_count": invalid_count,
        "too_many_count": too_many_count,
        "error": error,
    }

def _parse_target_base_scope_text(self, text):
    """Parse multiline target scope input into host/base-domain sets."""
    lines = []
    hosts = set()
    bases = set()
    invalid_count = 0
    seen = set()
    for raw_line in self._ascii_safe(text).splitlines():
        line = self._ascii_safe(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        host = self._extract_scope_host(line)
        if not host:
            invalid_count += 1
            continue
        lines.append(line)
        hosts.add(host)
        base = self._infer_base_domain(host)
        if base:
            bases.add(base)
    return {
        "lines": lines,
        "hosts": hosts,
        "bases": bases,
        "invalid_count": invalid_count,
    }

def _extract_scope_host(self, value):
    """Extract host from URL/host text for manual scope filtering."""
    text = self._ascii_safe(value, lower=True).strip()
    if not text:
        return ""

    probe = text
    if "://" not in probe:
        probe = "https://" + probe.lstrip("/")
    host = ""
    try:
        parsed = URL(probe)
        host = self._ascii_safe(parsed.getHost(), lower=True).strip()
    except Exception as e:
        self._callbacks.printError(
            "Target scope parser fallback for '{}': {}".format(probe, str(e))
        )
        host = ""

    if not host:
        fallback = text.split("/")[0].split("?")[0].split("#")[0].strip()
        host = self._ascii_safe(fallback, lower=True).strip()

    if not host:
        return ""

    if host.endswith("."):
        host = host[:-1]
    if ":" in host and host.count(":") == 1:
        host = host.split(":", 1)[0].strip()
    if not host or " " in host:
        return ""
    return host

def _get_target_scope_override(self):
    """Return effective manual scope override state for external scans."""
    lines = list(self.target_base_scope_lines)
    hosts = set(self.target_base_scope_hosts)
    bases = set(self.target_base_scope_bases)
    enabled = bool(self.target_base_scope_only_enabled and (hosts or bases))
    return {
        "enabled": enabled,
        "lines": lines,
        "hosts": hosts,
        "bases": bases,
    }

def _host_matches_target_scope(self, host, scope_override):
    """Check if a host belongs to manual base URL scope (exact or derivative)."""
    text = self._ascii_safe(host, lower=True).strip()
    if not text:
        return False
    if text in scope_override.get("hosts", set()):
        return True
    base = self._infer_base_domain(text)
    if not base:
        return False
    return base in scope_override.get("bases", set())

def export_by_host(self):
    """Export endpoints for selected host only"""
    host = str(self.host_filter.getSelectedItem())
    if host == "All":
        with self.lock:
            hosts = sorted(
                set(self._get_entry(e)["host"] for e in self.api_data.values())
            )
        if not hosts:
            self.log_to_ui("[!] No hosts to export")
            return
        host = str(
            JOptionPane.showInputDialog(
                self._panel,
                "Select host to export:",
                "Export Host",
                JOptionPane.QUESTION_MESSAGE,
                None,
                hosts,
                hosts[0],
            )
        )
        if not host:
            return

    with self.lock:
        filtered_data = {
            k: v
            for k, v in self.api_data.items()
            if self._get_entry(v)["host"] == host
        }
    if not filtered_data:
        self.log_to_ui("[!] No endpoints for host: {}".format(host))
        return

    self.log_to_ui(
        "[*] Exporting {} endpoints for {}".format(len(filtered_data), host)
    )
    self._export_data(filtered_data, "_" + host.replace(".", "_"))

def _select_export_scope_data(self, export_name):
    """Select export scope and return (scope_label, data dict)."""
    if not self.api_data:
        self.log_to_ui("[!] No API data to export")
        return None, None

    options = ["All Endpoints", "Filtered View", "Current Host"]
    selected = JOptionPane.showInputDialog(
        self._panel,
        "Select scope for {} export:".format(export_name),
        "{} Export Scope".format(export_name),
        JOptionPane.QUESTION_MESSAGE,
        None,
        options,
        options[1],
    )
    if selected is None:
        return None, None

    scope = str(selected)
    if scope == "All Endpoints":
        with self.lock:
            return scope, dict(self.api_data)

    if scope == "Filtered View":
        filtered = dict(self._filter_endpoints())
        if not filtered:
            self.log_to_ui("[!] Filtered view is empty")
            return None, None
        return scope, filtered

    host = str(self.host_filter.getSelectedItem())
    if host == "All":
        with self.lock:
            hosts = sorted(
                set(self._get_entry(e)["host"] for e in self.api_data.values())
            )
        if not hosts:
            self.log_to_ui("[!] No hosts available for export")
            return None, None
        host = JOptionPane.showInputDialog(
            self._panel,
            "Select host for {} export:".format(export_name),
            "{} Host".format(export_name),
            JOptionPane.QUESTION_MESSAGE,
            None,
            hosts,
            hosts[0],
        )
        if host is None:
            return None, None
        host = str(host)

    with self.lock:
        host_data = {
            k: v
            for k, v in self.api_data.items()
            if self._get_entry(v)["host"] == host
        }
    if not host_data:
        self.log_to_ui("[!] No endpoints for host: {}".format(host))
        return None, None
    return "Host: {}".format(host), host_data

def _split_path_segments(self, path):
    """Split path into non-empty segments for export clients."""
    safe_path = self._ascii_safe(path or "/").strip()
    if not safe_path.startswith("/"):
        safe_path = "/" + safe_path
    return [segment for segment in safe_path.split("/") if segment]

def _parse_query_pairs(self, query_string):
    """Parse query string into ordered key/value pairs."""
    pairs = []
    safe_query = self._ascii_safe(query_string or "").strip()
    if not safe_query:
        return pairs
    for part in safe_query.split("&"):
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, ""
        pairs.append(
            {
                "key": self._ascii_safe(key),
                "value": self._ascii_safe(value),
            }
        )
    return pairs

def _build_entry_url(self, entry):
    """Build full URL and normalized components from a captured entry."""
    protocol = self._ascii_safe(entry.get("protocol") or "https", lower=True).strip() or "https"
    host = self._ascii_safe(entry.get("host") or "").strip()
    if not host:
        return "", protocol, host, "", []

    path = self._ascii_safe(
        entry.get("path") or entry.get("normalized_path") or "/"
    ).strip()
    if not path.startswith("/"):
        path = "/" + path
    query_string = self._ascii_safe(entry.get("query_string") or "").strip()
    url = "{}://{}{}".format(protocol, host, path)
    if query_string:
        url += "?" + query_string
    return url, protocol, host, path, self._parse_query_pairs(query_string)

def _build_postman_collection(self, data_to_export, collection_name):
    """Build Postman Collection v2.1 payload from endpoint data."""
    host_groups = {}
    for endpoint_key, entries in data_to_export.items():
        entry = self._get_entry(entries)
        host = self._ascii_safe(entry.get("host") or "unknown-host")
        if host not in host_groups:
            host_groups[host] = []
        host_groups[host].append((endpoint_key, entries))

    postman_items = []
    for host in sorted(host_groups.keys()):
        request_items = []
        for endpoint_key, entries in sorted(host_groups[host], key=lambda item: item[0]):
            entry = self._get_entry(entries)
            method = self._ascii_safe(entry.get("method") or "GET").upper()
            url, protocol, host_value, path, query_pairs = self._build_entry_url(entry)
            headers = []
            raw_headers = entry.get("headers", {})
            if isinstance(raw_headers, dict):
                for key, value in raw_headers.items():
                    name = self._ascii_safe(key).strip()
                    header_value = self._ascii_safe(value).strip()
                    if not name:
                        continue
                    if name.lower() in ["host", "content-length", "connection"]:
                        continue
                    headers.append({"key": name, "value": header_value})

            request_obj = {
                "method": method,
                "header": headers,
                "url": {
                    "raw": url,
                    "protocol": protocol,
                    "host": [part for part in host_value.split(".") if part],
                    "path": self._split_path_segments(path),
                    "query": query_pairs,
                },
            }

            raw_body = self._ascii_safe(entry.get("request_body") or "")
            if raw_body and method in ["POST", "PUT", "PATCH", "DELETE"]:
                request_obj["body"] = {"mode": "raw", "raw": raw_body}

            request_items.append(
                {
                    "name": self._ascii_safe(endpoint_key),
                    "request": request_obj,
                    "response": [],
                }
            )

        postman_items.append({"name": host, "item": request_items})

    return {
        "info": {
            "name": self._ascii_safe(collection_name),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": "Generated by BurpAPISecuritySuite",
        },
        "item": postman_items,
    }

def _build_insomnia_export(self, data_to_export, workspace_name):
    """Build Insomnia export JSON payload from endpoint data."""
    workspace_id = "wrk_burpapisecuritysuite"
    env_id = "env_burpapisecuritysuite"
    resources = [
        {
            "_id": workspace_id,
            "_type": "workspace",
            "name": self._ascii_safe(workspace_name),
        },
        {
            "_id": env_id,
            "_type": "environment",
            "parentId": workspace_id,
            "name": "Base Environment",
            "data": {},
        },
    ]

    host_groups = {}
    for endpoint_key, entries in data_to_export.items():
        entry = self._get_entry(entries)
        host = self._ascii_safe(entry.get("host") or "unknown-host")
        if host not in host_groups:
            host_groups[host] = []
        host_groups[host].append((endpoint_key, entries))

    request_counter = 1
    group_counter = 1
    for host in sorted(host_groups.keys()):
        group_id = "fld_{:04d}".format(group_counter)
        group_counter += 1
        resources.append(
            {
                "_id": group_id,
                "_type": "request_group",
                "parentId": workspace_id,
                "name": host,
            }
        )

        for endpoint_key, entries in sorted(host_groups[host], key=lambda item: item[0]):
            entry = self._get_entry(entries)
            method = self._ascii_safe(entry.get("method") or "GET").upper()
            url, _, _, _, query_pairs = self._build_entry_url(entry)
            headers = []
            raw_headers = entry.get("headers", {})
            if isinstance(raw_headers, dict):
                for key, value in raw_headers.items():
                    name = self._ascii_safe(key).strip()
                    header_value = self._ascii_safe(value).strip()
                    if not name:
                        continue
                    if name.lower() in ["host", "content-length", "connection"]:
                        continue
                    headers.append({"name": name, "value": header_value})

            request_obj = {
                "_id": "req_{:05d}".format(request_counter),
                "_type": "request",
                "parentId": group_id,
                "name": self._ascii_safe(endpoint_key),
                "method": method,
                "url": url,
                "parameters": [
                    {"name": pair["key"], "value": pair["value"]}
                    for pair in query_pairs
                ],
                "headers": headers,
            }

            raw_body = self._ascii_safe(entry.get("request_body") or "")
            if raw_body and method in ["POST", "PUT", "PATCH", "DELETE"]:
                request_obj["body"] = {
                    "mimeType": "application/json",
                    "text": raw_body,
                }

            resources.append(request_obj)
            request_counter += 1

    return {
        "_type": "export",
        "__export_format": 4,
        "__export_date": SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(Date()),
        "__export_source": "burpapisecuritysuite",
        "resources": resources,
    }

def _export_postman_collection(self):
    """Export Recon data as Postman Collection v2.1 JSON."""
    scope_label, data_to_export = self._select_export_scope_data("Postman")
    if not data_to_export:
        return

    export_dir = self._get_export_dir("Postman_Export")
    if not export_dir:
        self.log_to_ui("[!] Cannot create export directory")
        return

    import os

    collection_name = "Burp API Security Suite ({})".format(scope_label)
    collection = self._build_postman_collection(data_to_export, collection_name)
    filepath = os.path.join(export_dir, "postman_collection.json")
    writer = None
    try:
        writer = FileWriter(filepath)
        writer.write(json.dumps(collection, indent=2))
        host_count = len(set(self._get_entry(v)["host"] for v in data_to_export.values()))
        self.log_to_ui(
            "[+] Postman export: {} endpoints, {} hosts".format(
                len(data_to_export), host_count
            )
        )
        self.log_to_ui("[+] Folder: {}".format(export_dir))
        self.log_to_ui("[+] File: {}".format(filepath))
    except Exception as e:
        self.log_to_ui("[!] Postman export failed: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing Postman export file: {}".format(str(e))
                )

def _export_insomnia_collection(self):
    """Export Recon data as Insomnia import JSON."""
    scope_label, data_to_export = self._select_export_scope_data("Insomnia")
    if not data_to_export:
        return

    export_dir = self._get_export_dir("Insomnia_Export")
    if not export_dir:
        self.log_to_ui("[!] Cannot create export directory")
        return

    import os

    workspace_name = "Burp API Security Suite ({})".format(scope_label)
    export_payload = self._build_insomnia_export(data_to_export, workspace_name)
    filepath = os.path.join(export_dir, "insomnia_collection.json")
    writer = None
    try:
        writer = FileWriter(filepath)
        writer.write(json.dumps(export_payload, indent=2))
        host_count = len(set(self._get_entry(v)["host"] for v in data_to_export.values()))
        self.log_to_ui(
            "[+] Insomnia export: {} endpoints, {} hosts".format(
                len(data_to_export), host_count
            )
        )
        self.log_to_ui("[+] Folder: {}".format(export_dir))
        self.log_to_ui("[+] File: {}".format(filepath))
    except Exception as e:
        self.log_to_ui("[!] Insomnia export failed: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing Insomnia export file: {}".format(str(e))
                )

def _show_text_dialog(self, title, text, rows=26, cols=120):
    """Show read-only monospaced text in a scrollable dialog."""
    area = JTextArea(int(rows), int(cols))
    area.setEditable(False)
    area.setFont(Font("Monospaced", Font.PLAIN, 11))
    area.setText(self._ascii_safe(text or ""))
    area.setCaretPosition(0)
    scroll = JScrollPane(area)
    JOptionPane.showMessageDialog(
        self._panel,
        scroll,
        self._ascii_safe(title or "Details"),
        JOptionPane.INFORMATION_MESSAGE,
    )

def _show_ai_copy_exit_dialog(self, title, text, rows=30, cols=140):
    """Show standardized AI export popup with Copy + Exit actions."""
    area = JTextArea(int(rows), int(cols))
    area.setEditable(False)
    area.setFont(Font("Monospaced", Font.PLAIN, 11))
    payload = self._ascii_safe(text or "")
    area.setText(payload)
    area.setCaretPosition(0)
    scroll = JScrollPane(area)
    options = ["Copy", "Exit"]
    selected = JOptionPane.showOptionDialog(
        self._panel,
        scroll,
        self._ascii_safe(title or "AI Export"),
        JOptionPane.DEFAULT_OPTION,
        JOptionPane.INFORMATION_MESSAGE,
        None,
        options,
        options[0],
    )
    if selected == 0:
        self._copy_to_clipboard(payload)
        return True
    return False

def _collect_recon_grep_targets(self, entry, scope_label):
    """Build grep targets for one sample based on selected scope."""
    targets = []
    scope = self._ascii_safe(scope_label or "Any", lower=True).strip()
    if scope not in ["any", "request", "response", "req+resp"]:
        scope = "any"

    if scope in ["any", "request", "req+resp"]:
        req_text = "\n".join(
            [
                "{} {}".format(
                    self._ascii_safe(entry.get("method") or "").upper(),
                    self._ascii_safe(
                        entry.get("path") or entry.get("normalized_path") or "/"
                    ),
                ),
                self._ascii_safe(entry.get("query_string") or ""),
                json.dumps(entry.get("headers", {}) or {}, sort_keys=True),
                self._ascii_safe(entry.get("request_body") or "")[:10000],
            ]
        )
        targets.append(("request", req_text))

    if scope in ["any", "response", "req+resp"]:
        resp_text = "\n".join(
            [
                "status={}".format(int(entry.get("response_status", 0) or 0)),
                json.dumps(entry.get("response_headers", {}) or {}, sort_keys=True),
                self._ascii_safe(entry.get("response_body") or "")[:10000],
            ]
        )
        targets.append(("response", resp_text))
    return targets

def _run_recon_grep(self):
    """Logger++-style regex grep across captured request/response history."""
    pattern_text = self._ascii_safe(self.recon_regex_field.getText() or "").strip()
    if not pattern_text:
        pattern_input = JOptionPane.showInputDialog(
            self._panel,
            "Enter regex pattern for Recon grep:",
            "Recon Grep",
            JOptionPane.PLAIN_MESSAGE,
        )
        if pattern_input is None:
            return
        pattern_text = self._ascii_safe(pattern_input).strip()
        if not pattern_text:
            self.log_to_ui("[!] Recon grep cancelled (empty regex)")
            return
        self.recon_regex_field.setText(pattern_text)

    scope_label = str(self.recon_regex_scope_combo.getSelectedItem())
    try:
        regex_obj = re.compile(pattern_text, re.IGNORECASE | re.MULTILINE)
    except re.error as regex_err:
        err_msg = self._ascii_safe(regex_err)
        self.log_to_ui("[!] Recon grep invalid regex: {}".format(err_msg))
        return

    with self.lock:
        snapshot = dict(self.api_data)

    if not snapshot:
        self.log_to_ui("[!] Recon grep: no captured endpoints")
        return

    lines = []
    lines.append("RECON GREP")
    lines.append("=" * 80)
    lines.append("[*] Regex: {}".format(pattern_text))
    lines.append("[*] Scope: {}".format(scope_label))
    lines.append("")

    matched_endpoints = set()
    matched_samples = 0
    extracted_groups = 0
    max_lines = 800

    for endpoint_key in sorted(snapshot.keys()):
        entries = snapshot.get(endpoint_key, [])
        entries_list = entries if isinstance(entries, list) else [entries]
        sample_hits = 0

        for sample_index, entry in enumerate(entries_list):
            targets = self._collect_recon_grep_targets(entry, scope_label)
            for target_name, target_text in targets:
                target_matches = list(regex_obj.finditer(target_text))
                if not target_matches:
                    continue
                matched_endpoints.add(endpoint_key)
                sample_hits += 1
                matched_samples += 1
                lines.append("[MATCH] {} | sample #{} | {}".format(
                    endpoint_key, sample_index + 1, target_name
                ))

                for match_index, match_obj in enumerate(target_matches[:3]):
                    groups = list(match_obj.groups() or [])
                    if groups:
                        extracted_groups += len(groups)
                        lines.append("  groups[{}]: {}".format(
                            match_index + 1,
                            ", ".join([self._ascii_safe(g) for g in groups]),
                        ))
                    else:
                        snippet = self._ascii_safe(match_obj.group(0) or "")
                        if len(snippet) > 160:
                            snippet = snippet[:157] + "..."
                        lines.append("  hit[{}]: {}".format(match_index + 1, snippet))

                if len(lines) >= max_lines:
                    lines.append("")
                    lines.append("[*] Output truncated at {} lines".format(max_lines))
                    self._show_text_dialog("Recon Grep Results", "\n".join(lines))
                    self.log_to_ui(
                        "[+] Recon grep: {} endpoints matched (truncated output)".format(
                            len(matched_endpoints)
                        )
                    )
                    return

        if sample_hits > 0:
            lines.append("  -> endpoint hits: {}".format(sample_hits))
            lines.append("")

    lines.append("=" * 80)
    lines.append("[*] Matched Endpoints: {}".format(len(matched_endpoints)))
    lines.append("[*] Matched Samples: {}".format(matched_samples))
    lines.append("[*] Captured Groups: {}".format(extracted_groups))
    if not matched_endpoints:
        lines.append("[+] No matches found")

    self._show_text_dialog("Recon Grep Results", "\n".join(lines))
    self.log_to_ui(
        "[+] Recon grep complete: {} endpoint(s) matched".format(
            len(matched_endpoints)
        )
    )

def _iter_recon_param_items(self, entry):
    """Delegate Recon parameter iteration to extracted helper module."""
    return recon_param_intel.iter_recon_param_items(self, entry)

def _tokenize_recon_words(self, text, max_terms=200):
    """Delegate Recon tokenization to extracted helper module."""
    return recon_param_intel.tokenize_recon_words(self, text, max_terms=max_terms)

def _collect_hidden_param_candidates(self, data_to_scan):
    """Delegate hidden parameter candidate collection to extracted helper module."""
    return recon_param_intel.collect_hidden_param_candidates(self, data_to_scan)

def _score_hidden_param_candidate(self, normalized_entry, candidate):
    """Delegate hidden parameter scoring to extracted helper module."""
    return recon_param_intel.score_hidden_param_candidate(
        self, normalized_entry, candidate
    )

def _run_recon_hidden_params_for_scope(self, scope_label, data_to_scan):
    """Delegate hidden parameter analysis to extracted helper module."""
    return recon_param_intel.run_recon_hidden_params_for_scope(
        self, scope_label, data_to_scan
    )

def _run_recon_hidden_params(self):
    """Delegate hidden parameter action to extracted helper module."""
    return recon_param_intel.run_recon_hidden_params(self)

def _run_recon_hidden_params_selected(self, endpoint_key):
    """Delegate selected-endpoint hidden parameter action to helper module."""
    return recon_param_intel.run_recon_hidden_params_selected(self, endpoint_key)

def _param_risk_hint(self, param_name):
    """Delegate parameter risk hint classification to extracted helper module."""
    return recon_param_intel.param_risk_hint(self, param_name)

def _collect_recon_param_intelligence(self, data_to_scan):
    """Delegate GAP-style parameter intelligence collection to helper module."""
    return recon_param_intel.collect_recon_param_intelligence(self, data_to_scan)

def _build_recon_param_intel_report(self, scope_label, intel_payload):
    """Delegate GAP-style report rendering to extracted helper module."""
    return recon_param_intel.build_recon_param_intel_report(
        self, scope_label, intel_payload
    )

def _run_recon_param_intel(self):
    """Delegate Recon parameter intelligence action to extracted helper module."""
    return recon_param_intel.run_recon_param_intel(self)

def _export_recon_param_intel(self):
    """Delegate Recon parameter intelligence export to helper module."""
    return recon_param_intel.export_recon_param_intel(self)

def _safe_export_name(self, text, fallback="item"):
    """Convert arbitrary label to filesystem-safe name."""
    safe = self._ascii_safe(text or "").strip()
    if not safe:
        return fallback
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", safe)
    safe = safe.strip("._")
    if not safe:
        safe = fallback
    return safe[:90]

def _build_recon_turbo_request_template(self, entry):
    """Build one Turbo Intruder request template with %s insertion marker."""
    method = self._ascii_safe(entry.get("method") or "GET").upper()
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    query = self._ascii_safe(entry.get("query_string") or "")
    body = self._ascii_safe(entry.get("request_body") or "")
    strategy = "fallback_query_param"

    if query:
        parts = query.split("&")
        replaced = False
        for idx, part in enumerate(parts):
            if "=" in part and (not replaced):
                key, _value = part.split("=", 1)
                parts[idx] = "{}=%s".format(self._ascii_safe(key))
                replaced = True
        if not replaced and len(parts) > 0:
            parts[0] = "{}=%s".format(self._ascii_safe(parts[0]))
            replaced = True
        query = "&".join([self._ascii_safe(p) for p in parts if p is not None])
        strategy = "query_value"
    elif re.search(r"/[0-9a-f]{24}(?=/|$)", path, re.IGNORECASE):
        path = re.sub(r"/[0-9a-f]{24}(?=/|$)", "/%s", path, count=1, flags=re.IGNORECASE)
        strategy = "path_objectid"
    elif re.search(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", path, re.IGNORECASE):
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
            "/%s",
            path,
            count=1,
            flags=re.IGNORECASE,
        )
        strategy = "path_uuid"
    elif re.search(r"/[0-9]+(?=/|$)", path):
        path = re.sub(r"/[0-9]+(?=/|$)", "/%s", path, count=1)
        strategy = "path_numeric_id"
    elif body and method in ["POST", "PUT", "PATCH", "DELETE"]:
        if re.search(r'":\s*"[^"]*"', body):
            body = re.sub(
                r'":\s*"[^"]*"',
                '": "%s"',
                body,
                count=1,
            )
            strategy = "json_string_value"
        elif re.search(r'":\s*[0-9]+', body):
            body = re.sub(
                r'":\s*[0-9]+',
                '": %s',
                body,
                count=1,
            )
            strategy = "json_numeric_value"
        else:
            strategy = "request_body_unmodified"
    else:
        query = "ti_payload=%s"
        strategy = "fallback_query_param"

    target = path
    if query:
        target = "{}?{}".format(path, query)

    headers = []
    headers.append("Host: {}".format(self._ascii_safe(entry.get("host") or "")))
    for key, value in (entry.get("headers", {}) or {}).items():
        name = self._ascii_safe(key).strip()
        data = self._ascii_safe(value).strip()
        if not name:
            continue
        if name.lower() in ["host", "content-length", "connection"]:
            continue
        headers.append("{}: {}".format(name, data))

    if body and method in ["POST", "PUT", "PATCH", "DELETE"]:
        if not any(h.lower().startswith("content-length:") for h in [self._ascii_safe(x, lower=True) for x in headers]):
            headers.append("Content-Length: {}".format(len(body)))

    request_line = "{} {} HTTP/1.1".format(method, target)
    request_text = request_line + "\r\n" + "\r\n".join(headers) + "\r\n\r\n"
    if body:
        request_text += body
    return request_text, strategy

def _build_recon_turbo_manifest(self, scope_label, data_to_export):
    """Build lightweight manifest metadata for Recon Turbo export."""
    items = []
    for endpoint_key in sorted(data_to_export.keys()):
        entries = data_to_export.get(endpoint_key, [])
        entry = self._get_entry(entries)
        entries_list = entries if isinstance(entries, list) else [entries]
        tools = sorted(
            set([self._get_recon_entry_tool(sample) for sample in entries_list])
        )
        items.append(
            {
                "endpoint": self._ascii_safe(endpoint_key),
                "method": self._ascii_safe(entry.get("method") or "").upper(),
                "host": self._ascii_safe(entry.get("host") or ""),
                "path": self._ascii_safe(
                    entry.get("path") or entry.get("normalized_path") or "/"
                ),
                "samples": len(entries_list),
                "source_tools": tools,
                "tags": list(self.endpoint_tags.get(endpoint_key, []) or []),
            }
        )
    return {
        "scope": self._ascii_safe(scope_label),
        "generated_at": SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date()),
        "total_endpoints": len(items),
        "endpoints": items,
    }

def _build_recon_turbo_basic_script(self):
    """Generate starter Turbo Intruder script with learn-mode filtering."""
    return """# Recon Turbo Pack - Basic Attack
# Replace words.txt with your payload source.

def queueRequests(target, wordlists):
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=10,
    requestsPerConnection=50,
    pipeline=False,
    engine=Engine.THREADED,
)

# Teach baseline response signatures
engine.queue(target.req, target.baseInput, learn=1)

for word in open('payloads.txt'):
    payload = word.rstrip()
    if not payload:
        continue
    engine.queue(target.req, payload)

def handleResponse(req, interesting):
if interesting:
    table.add(req)
"""

def _build_recon_turbo_race_script(self):
    """Generate starter Turbo Intruder single-gate race script."""
    return """# Recon Turbo Pack - Race Gate
# Use this for TOCTOU/race-condition probes.

def queueRequests(target, wordlists):
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,
    requestsPerConnection=1,
    pipeline=False,
    engine=Engine.BURP2,
)

for i in range(20):
    engine.queue(target.req, gate='race1')
engine.openGate('race1')

def handleResponse(req, interesting):
table.add(req)
"""

def _build_recon_turbo_pack_from_data(self, scope_label, data_to_export):
    """Export Turbo Intruder-ready Recon package for provided scope data."""
    if not data_to_export:
        self.log_to_ui("[!] Turbo Pack export: no endpoints in selected scope")
        return

    export_dir = self._get_export_dir("Recon_TurboPack")
    if not export_dir:
        self.log_to_ui("[!] Turbo Pack export: cannot create export directory")
        return

    import os

    requests_dir = os.path.join(export_dir, "requests")
    scripts_dir = os.path.join(export_dir, "scripts")
    try:
        if not os.path.exists(requests_dir):
            os.makedirs(requests_dir)
        if not os.path.exists(scripts_dir):
            os.makedirs(scripts_dir)
    except Exception as e:
        self.log_to_ui("[!] Turbo Pack export failed: {}".format(str(e)))
        return

    payload_values = set(["1", "2", "3", "10", "100", "admin", "guest", "test"])
    request_count = 0

    for index, endpoint_key in enumerate(sorted(data_to_export.keys())):
        entries = data_to_export.get(endpoint_key, [])
        entry = self._get_entry(entries)
        request_text, strategy = self._build_recon_turbo_request_template(entry)
        base_name = self._safe_export_name(
            "{:04d}_{}".format(index + 1, endpoint_key), "endpoint"
        )
        request_filename = os.path.join(requests_dir, base_name + ".txt")
        writer = None
        try:
            writer = FileWriter(request_filename)
            writer.write(request_text)
            request_count += 1
        except Exception as e:
            self._callbacks.printError(
                "Turbo request export failed for {}: {}".format(endpoint_key, str(e))
            )
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Turbo request file close failed: {}".format(str(e))
                    )

        if strategy.startswith("path_"):
            payload_values.update(["0", "-1", "999", "1000"])
        if strategy.startswith("json_"):
            payload_values.update(['"admin"', '"true"', "0", "99999"])

    files_to_write = {
        os.path.join(scripts_dir, "basic.py"): self._build_recon_turbo_basic_script(),
        os.path.join(scripts_dir, "race_gate.py"): self._build_recon_turbo_race_script(),
        os.path.join(export_dir, "payloads.txt"): "\n".join(sorted(payload_values)) + "\n",
        os.path.join(export_dir, "README.txt"): (
            "Recon Turbo Pack\n"
            "===============\n"
            "1. In Burp, open Turbo Intruder.\n"
            "2. Load one request template from requests/*.txt.\n"
            "3. Load one script from scripts/*.py (basic.py or race_gate.py).\n"
            "4. Edit payload source if needed (payloads.txt).\n"
            "5. Launch attack and review interesting-only results.\n"
        ),
        os.path.join(export_dir, "turbo_manifest.json"): json.dumps(
            self._build_recon_turbo_manifest(scope_label, data_to_export),
            indent=2,
        ),
    }

    for filepath, content in files_to_write.items():
        writer = None
        try:
            writer = FileWriter(filepath)
            writer.write(content)
        except Exception as e:
            self._callbacks.printError(
                "Turbo support file write failed ({}): {}".format(filepath, str(e))
            )
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Turbo support file close failed ({}): {}".format(
                            filepath, str(e)
                        )
                    )

    self.log_to_ui(
        "[+] Recon Turbo Pack export complete: {} requests ({})".format(
            request_count, self._ascii_safe(scope_label)
        )
    )
    self.log_to_ui("[+] Folder: {}".format(export_dir))

def _export_recon_turbo_pack(self):
    """Export Turbo Intruder-ready package from selected Recon scope."""
    scope_label, data_to_export = self._select_export_scope_data("Turbo Intruder")
    if not data_to_export:
        return
    self._build_recon_turbo_pack_from_data(scope_label, data_to_export)

def _export_recon_turbo_pack_selected(self, endpoint_key):
    """Export Turbo Intruder package for one selected Recon endpoint."""
    with self.lock:
        if endpoint_key not in self.api_data:
            self.log_to_ui("[!] Selected endpoint not found for Turbo export")
            return
        dataset = {endpoint_key: list(self.api_data.get(endpoint_key) or [])}
    self._build_recon_turbo_pack_from_data("Selected Endpoint", dataset)

def _sync_logger_from_recon_snapshot(self, data_snapshot, source_tool_label="ReconSync"):
    """Seed Logger rows from a Recon snapshot to keep both tabs aligned."""
    if not isinstance(data_snapshot, dict) or (not data_snapshot):
        return 0

    with self.lock:
        endpoint_tags_snapshot = {
            self._ascii_safe(key): list(value or [])
            for key, value in (self.endpoint_tags or {}).items()
        }

    with self.logger_lock:
        before_count = len(getattr(self, "logger_events", []) or [])

    max_rows = int(getattr(self, "logger_max_rows", 20000) or 20000)
    max_seed = max(500, min(40000, max_rows))
    seeded = 0
    truncated = False

    for endpoint_key in sorted(data_snapshot.keys()):
        if seeded >= max_seed:
            truncated = True
            break
        entries = data_snapshot.get(endpoint_key, [])
        entries_list = entries if isinstance(entries, list) else [entries]
        for sample in entries_list:
            if seeded >= max_seed:
                truncated = True
                break
            if not isinstance(sample, dict):
                continue
            try:
                method = self._ascii_safe(sample.get("method") or "GET").upper()
                path = self._ascii_safe(
                    sample.get("path") or sample.get("normalized_path") or "/"
                )
                if not path.startswith("/"):
                    path = "/" + path
                normalized_path = self._ascii_safe(
                    sample.get("normalized_path") or ""
                ).strip()
                if not normalized_path:
                    normalized_path = self._normalize_path(path)
                host = self._ascii_safe(sample.get("host") or "", lower=True).strip()
                query = self._ascii_safe(sample.get("query_string") or "")
                endpoint_key_value = self._ascii_safe(endpoint_key).strip()
                if not endpoint_key_value:
                    endpoint_key_value = "{}:{}".format(method, normalized_path)
                entry = {
                    "method": method,
                    "path": path,
                    "normalized_path": normalized_path,
                    "host": host,
                    "protocol": self._ascii_safe(
                        sample.get("protocol") or "https", lower=True
                    ),
                    "port": int(sample.get("port", 443) or 443),
                    "query_string": query,
                    "headers": dict(sample.get("headers") or {}),
                    "request_body": self._ascii_safe(sample.get("request_body") or ""),
                    "response_status": int(sample.get("response_status", 0) or 0),
                    "response_headers": dict(sample.get("response_headers") or {}),
                    "response_body": self._ascii_safe(sample.get("response_body") or ""),
                    "response_length": int(sample.get("response_length", 0) or 0),
                    "response_time_ms": int(sample.get("response_time_ms", 0) or 0),
                    "source_tool": self._ascii_safe(
                        sample.get("source_tool") or source_tool_label
                    ),
                    "content_type": self._ascii_safe(
                        sample.get("content_type") or "unknown"
                    ),
                }
                tags = list(endpoint_tags_snapshot.get(endpoint_key_value, []) or [])
                self._logger_capture_event(
                    endpoint_key_value,
                    entry,
                    tags=tags,
                    bypass_capture=True,
                    sync_recon=False,
                )
                seeded += 1
            except Exception as row_err:
                self._callbacks.printError(
                    "Logger sync from Recon row error: {}".format(str(row_err))
                )

    self._logger_trim_if_needed(force=True)
    self._schedule_logger_ui_refresh(force=True)
    with self.logger_lock:
        after_count = len(getattr(self, "logger_events", []) or [])
    added = max(0, after_count - before_count)
    if truncated:
        self.log_to_ui(
            "[*] Logger sync from Recon truncated at {} rows (max logger seed)".format(
                max_seed
            )
        )
    return added

def _int_or_default(self, value, default_value=0):
    try:
        return int(value)
    except Exception as value_err:
        _ = value_err
        return int(default_value)

def _current_import_sample_limit(self):
    combo = getattr(self, "sample_limit", None)
    if combo is None:
        return 3
    try:
        raw = combo.getSelectedItem()
        limit = self._int_or_default(raw, 3)
    except Exception as limit_err:
        _ = limit_err
        limit = 3
    return max(1, min(10, int(limit)))

def _normalize_header_dict(self, raw_headers):
    """Normalize headers from dict/list-of-pairs into plain string dict."""
    normalized = {}
    if isinstance(raw_headers, dict):
        for raw_name, raw_value in raw_headers.items():
            name = self._ascii_safe(raw_name).strip()
            if not name:
                continue
            normalized[name] = self._ascii_safe(raw_value)
        return normalized
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if not isinstance(item, dict):
                continue
            name = self._ascii_safe(item.get("name")).strip()
            if not name:
                continue
            normalized[name] = self._ascii_safe(item.get("value"))
    return normalized

def _extract_content_type_from_headers(self, headers_map, fallback_value="unknown"):
    if not isinstance(headers_map, dict):
        return self._ascii_safe(fallback_value or "unknown")
    for raw_name, raw_value in headers_map.items():
        name = self._ascii_safe(raw_name, lower=True).strip()
        if name == "content-type":
            value = self._ascii_safe(raw_value).strip()
            if value:
                return value
    return self._ascii_safe(fallback_value or "unknown")

def _parse_url_parts_from_text(self, url_text):
    """Parse URL into protocol/host/port/path/query fields with safe fallbacks."""
    raw_url = self._ascii_safe(url_text).strip()
    if not raw_url:
        return {
            "protocol": "https",
            "host": "",
            "port": 443,
            "path": "/",
            "query_string": "",
            "url": "",
        }

    protocol = "https"
    host = ""
    port = 443
    path = "/"
    query_string = ""

    try:
        parsed = URL(raw_url)
        protocol = self._ascii_safe(parsed.getProtocol() or "https", lower=True).strip() or "https"
        host = self._ascii_safe(parsed.getHost() or "", lower=True).strip()
        path = self._ascii_safe(parsed.getPath() or "/").strip() or "/"
        query_string = self._ascii_safe(parsed.getQuery() or "")
        parsed_port = self._int_or_default(parsed.getPort(), 0)
        default_port = self._int_or_default(parsed.getDefaultPort(), 0)
        if parsed_port > 0:
            port = parsed_port
        elif default_port > 0:
            port = default_port
        else:
            port = 443 if protocol == "https" else 80
    except Exception as parse_err:
        self._callbacks.printError(
            "Import URL parse fallback for '{}': {}".format(raw_url, str(parse_err))
        )
        match = re.match(
            r"^(https?)://([^/:?#]+)(?::([0-9]+))?([^?#]*)?(?:\?([^#]*))?",
            raw_url,
            re.IGNORECASE,
        )
        if match:
            protocol = self._ascii_safe(match.group(1) or "https", lower=True).strip() or "https"
            host = self._ascii_safe(match.group(2) or "", lower=True).strip()
            parsed_port = self._int_or_default(match.group(3), 0)
            port = parsed_port if parsed_port > 0 else (443 if protocol == "https" else 80)
            raw_path = self._ascii_safe(match.group(4) or "/").strip() or "/"
            path = raw_path if raw_path.startswith("/") else "/" + raw_path
            query_string = self._ascii_safe(match.group(5) or "")
        else:
            path = self._ascii_safe(raw_url).strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            protocol = "https"
            host = ""
            port = 443
            query_string = ""

    if not path.startswith("/"):
        path = "/" + path
    normalized_path = self._normalize_path(path)
    return {
        "protocol": protocol,
        "host": host,
        "port": int(port),
        "path": path,
        "normalized_path": normalized_path,
        "query_string": query_string,
        "url": raw_url,
    }

def _derive_import_auth_methods(self, headers_map, request_body_text, param_map):
    """Infer auth method labels from imported request metadata."""
    auth_methods = []
    header_names = [
        self._ascii_safe(name, lower=True).strip()
        for name in (headers_map or {}).keys()
    ]
    header_values = [
        self._ascii_safe(value, lower=True).strip()
        for value in (headers_map or {}).values()
    ]
    body_lower = self._ascii_safe(request_body_text or "", lower=True)

    if "authorization" in header_names:
        auth_methods.append("Bearer Token")
    if any(name in header_names for name in ["x-api-key", "api-key", "apikey"]):
        auth_methods.append("API Key")
    if "cookie" in header_names:
        auth_methods.append("Cookie")
    if any("bearer " in value for value in header_values):
        auth_methods.append("Bearer Token")
    if any("session" in value or "token" in value for value in header_values):
        auth_methods.append("Cookie")
    if "jwt" in body_lower or "access_token" in body_lower or "refresh_token" in body_lower:
        auth_methods.append("JWT")

    params = dict(param_map or {})
    cookie_params = params.get("cookie") if isinstance(params, dict) else {}
    if isinstance(cookie_params, dict) and cookie_params:
        auth_methods.append("Cookie")

    normalized = []
    seen = set()
    for item in auth_methods:
        label = self._ascii_safe(item).strip()
        if not label:
            continue
        lower = self._ascii_safe(label, lower=True)
        if lower in seen:
            continue
        seen.add(lower)
        normalized.append(label)
    if not normalized:
        normalized = ["None"]
    return normalized

def _extract_param_map_from_har_request(self, request_obj):
    """Extract parameter names from HAR request fields."""
    params = {"url": {}, "body": {}, "cookie": {}, "json": {}}
    if not isinstance(request_obj, dict):
        return params

    for pair in request_obj.get("queryString", []) or []:
        if not isinstance(pair, dict):
            continue
        name = self._ascii_safe(pair.get("name") or "").strip()
        if name:
            params["url"][name] = "string"

    for cookie_obj in request_obj.get("cookies", []) or []:
        if not isinstance(cookie_obj, dict):
            continue
        name = self._ascii_safe(cookie_obj.get("name") or "").strip()
        if name:
            params["cookie"][name] = "string"

    post_data = request_obj.get("postData") or {}
    if isinstance(post_data, dict):
        for post_param in post_data.get("params", []) or []:
            if not isinstance(post_param, dict):
                continue
            name = self._ascii_safe(post_param.get("name") or "").strip()
            if name:
                params["body"][name] = "string"
        mime = self._ascii_safe(post_data.get("mimeType") or "", lower=True)
        post_text = self._ascii_safe(post_data.get("text") or "")
        if "json" in mime and post_text.strip():
            try:
                parsed_json = json.loads(post_text)
                if isinstance(parsed_json, dict):
                    for key in parsed_json.keys():
                        name = self._ascii_safe(key).strip()
                        if name:
                            params["json"][name] = "string"
            except Exception as json_err:
                self._callbacks.printError(
                    "Import JSON body parse failed (HAR): {}".format(str(json_err))
                )

    return params

def _build_cookie_header_for_host(self, cookie_payload, host_name):
    """Build Cookie header for one host from Excalibur cookies export payload."""
    if not isinstance(cookie_payload, dict):
        return ""
    cookie_roots = cookie_payload.get("cookies")
    if not isinstance(cookie_roots, dict):
        return ""

    host = self._ascii_safe(host_name or "", lower=True).strip()
    if not host:
        return ""

    candidates = []
    for raw_domain, cookie_map in cookie_roots.items():
        domain = self._ascii_safe(raw_domain or "", lower=True).strip()
        if (not domain) or (not isinstance(cookie_map, dict)):
            continue
        clean_domain = domain.lstrip(".")
        if not clean_domain:
            continue
        if host == clean_domain or host.endswith("." + clean_domain):
            for cookie_name, cookie_value in cookie_map.items():
                name = self._ascii_safe(cookie_name).strip()
                if not name:
                    continue
                value = self._ascii_safe(cookie_value)
                candidates.append("{}={}".format(name, value))
    if not candidates:
        return ""
    return "; ".join(candidates)

def _coerce_import_entry_shape(self, entry, source_tool_label):
    """Fill missing import entry fields and compute analysis helpers."""
    if not isinstance(entry, dict):
        return None

    method = self._ascii_safe(entry.get("method") or "GET").upper()
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    normalized_path = self._ascii_safe(entry.get("normalized_path") or "").strip()
    if not normalized_path:
        normalized_path = self._normalize_path(path)

    protocol = self._ascii_safe(entry.get("protocol") or "https", lower=True).strip() or "https"
    host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
    port = self._int_or_default(entry.get("port"), 443 if protocol == "https" else 80)
    query_string = self._ascii_safe(entry.get("query_string") or "")
    headers = self._normalize_header_dict(entry.get("headers") or {})
    request_body = self._ascii_safe(entry.get("request_body") or "")
    response_headers = self._normalize_header_dict(entry.get("response_headers") or {})
    response_body = self._ascii_safe(entry.get("response_body") or "")
    response_status = self._int_or_default(entry.get("response_status"), 0)
    response_length = self._int_or_default(entry.get("response_length"), len(response_body))
    response_time_ms = self._int_or_default(entry.get("response_time_ms"), 0)
    content_type = self._ascii_safe(
        entry.get("content_type")
        or self._extract_content_type_from_headers(
            response_headers,
            fallback_value=self._extract_content_type_from_headers(headers, fallback_value="unknown"),
        )
    ).strip() or "unknown"

    parameters = dict(entry.get("parameters") or {})
    for param_bucket in ["url", "body", "cookie", "json"]:
        bucket = parameters.get(param_bucket)
        if isinstance(bucket, list):
            parameters[param_bucket] = {self._ascii_safe(x).strip(): "string" for x in bucket if self._ascii_safe(x).strip()}
        elif not isinstance(bucket, dict):
            parameters[param_bucket] = {}

    auth_detected = list(entry.get("auth_detected") or [])
    if not auth_detected:
        auth_detected = self._derive_import_auth_methods(headers, request_body, parameters)
    else:
        auth_detected = [self._ascii_safe(x) for x in auth_detected if self._ascii_safe(x).strip()] or ["None"]

    api_patterns = list(entry.get("api_patterns") or [])
    if not api_patterns:
        api_patterns = self._detect_api_patterns(normalized_path, content_type, response_body)

    encryption_indicators = entry.get("encryption_indicators")
    if not isinstance(encryption_indicators, dict):
        encryption_indicators = self._detect_encryption(request_body, response_body, headers)
    reflected = []
    param_types = {}
    for bucket_name in ["url", "body", "cookie", "json"]:
        bucket = parameters.get(bucket_name, {})
        if isinstance(bucket, dict):
            for param_name in bucket.keys():
                clean_name = self._ascii_safe(param_name).strip()
                if clean_name:
                    param_types[clean_name] = "string"
    param_patterns = entry.get("param_patterns")
    if not isinstance(param_patterns, dict):
        param_patterns = {
            "reflected": reflected,
            "param_types": param_types,
        }
    else:
        if not isinstance(param_patterns.get("reflected"), list):
            param_patterns["reflected"] = reflected
        if not isinstance(param_patterns.get("param_types"), dict):
            param_patterns["param_types"] = param_types

    safe_entry = {
        "method": method,
        "path": path,
        "normalized_path": normalized_path,
        "host": host,
        "protocol": protocol,
        "port": int(port),
        "query_string": query_string,
        "parameters": parameters,
        "headers": headers,
        "request_body": request_body,
        "response_status": int(response_status),
        "response_headers": response_headers,
        "response_body": response_body,
        "response_length": int(response_length),
        "response_time_ms": int(response_time_ms),
        "captured_at": self._ascii_safe(entry.get("captured_at") or ""),
        "captured_at_epoch_ms": self._int_or_default(entry.get("captured_at_epoch_ms"), 0),
        "source_tool": self._ascii_safe(entry.get("source_tool") or source_tool_label),
        "content_type": content_type,
        "auth_detected": auth_detected,
        "api_patterns": api_patterns,
        "jwt_detected": entry.get("jwt_detected"),
        "encryption_indicators": encryption_indicators,
        "param_patterns": param_patterns,
    }
    return safe_entry

def _build_suite_export_snapshot(self, data):
    """Parse native BurpAPISecuritySuite export shape into import snapshot."""
    snapshot = {}
    endpoints = data.get("endpoints", []) if isinstance(data, dict) else []
    if not isinstance(endpoints, list):
        return snapshot

    sample_limit = self._current_import_sample_limit()

    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        try:
            method = self._ascii_safe(endpoint.get("method") or "GET").upper()
            normalized_path = self._ascii_safe(endpoint.get("normalized_path") or "/").strip() or "/"
            if not normalized_path.startswith("/"):
                normalized_path = "/" + normalized_path
            endpoint_key = self._ascii_safe(endpoint.get("endpoint") or "").strip()
            if not endpoint_key:
                endpoint_key = "{}:{}".format(method, normalized_path)

            samples = endpoint.get("sample_requests", []) or []
            if not isinstance(samples, list) or (not samples):
                samples = [{}]
            response_codes = endpoint.get("response_codes", []) or []
            content_types = endpoint.get("content_types", []) or []

            built_entries = []
            for idx, sample in enumerate(samples[:sample_limit]):
                if not isinstance(sample, dict):
                    sample = {}
                entry = {
                    "method": method,
                    "path": self._ascii_safe(
                        sample.get("path") or normalized_path
                    ),
                    "normalized_path": normalized_path,
                    "host": self._ascii_safe(endpoint.get("host") or "", lower=True),
                    "protocol": "https",
                    "port": 443,
                    "query_string": self._ascii_safe(sample.get("query") or ""),
                    "parameters": endpoint.get(
                        "parameters",
                        {"url": {}, "body": {}, "cookie": {}, "json": {}},
                    ),
                    "headers": sample.get("headers") or {},
                    "request_body": self._ascii_safe(sample.get("request_body") or ""),
                    "response_status": self._int_or_default(
                        sample.get("response_status"),
                        response_codes[0] if response_codes else 200,
                    ),
                    "response_headers": {},
                    "response_body": self._ascii_safe(sample.get("response_body") or ""),
                    "response_length": self._int_or_default(
                        endpoint.get("avg_response_length"), 0
                    ),
                    "response_time_ms": self._int_or_default(
                        endpoint.get("avg_response_time_ms"), 0
                    ),
                    "source_tool": "Import",
                    "content_type": (
                        self._ascii_safe(content_types[idx] if idx < len(content_types) else "")
                        or (self._ascii_safe(content_types[0]) if content_types else "unknown")
                    ),
                    "auth_detected": endpoint.get("auth_methods", ["None"]),
                    "api_patterns": endpoint.get("api_patterns", []),
                    "jwt_detected": endpoint.get("jwt_claims"),
                    "encryption_indicators": {
                        "likely_encrypted": bool(endpoint.get("encryption_detected", False)),
                        "types": list(endpoint.get("encryption_types", []) or []),
                    },
                    "param_patterns": {
                        "reflected": list(endpoint.get("reflected_params", []) or []),
                        "param_types": dict(endpoint.get("param_type_summary", {}) or {}),
                    },
                }
                shaped = self._coerce_import_entry_shape(entry, "Import")
                if shaped is not None:
                    built_entries.append(shaped)
            if built_entries:
                snapshot[endpoint_key] = built_entries
        except Exception as endpoint_err:
            self._callbacks.printError(
                "Import suite-export endpoint parse error: {}".format(str(endpoint_err))
            )
    return snapshot

def _build_har_snapshot(self, har_entries, source_tool_label, cookie_payload=None):
    """Parse HAR entries into Recon snapshot format."""
    snapshot = {}
    if not isinstance(har_entries, list):
        return snapshot

    sample_limit = self._current_import_sample_limit()

    for har_entry in har_entries:
        if not isinstance(har_entry, dict):
            continue
        try:
            request_obj = har_entry.get("request") or {}
            response_obj = har_entry.get("response") or {}
            if not isinstance(request_obj, dict):
                request_obj = {}
            if not isinstance(response_obj, dict):
                response_obj = {}

            method = self._ascii_safe(request_obj.get("method") or "GET").upper()
            url_parts = self._parse_url_parts_from_text(request_obj.get("url") or "")
            headers = self._normalize_header_dict(request_obj.get("headers") or [])
            if "Cookie" not in headers and "cookie" not in [self._ascii_safe(x, lower=True) for x in headers.keys()]:
                synthesized_cookie = self._build_cookie_header_for_host(
                    cookie_payload,
                    url_parts.get("host"),
                )
                if synthesized_cookie:
                    headers["Cookie"] = synthesized_cookie

            post_data = request_obj.get("postData") or {}
            request_body = ""
            if isinstance(post_data, dict):
                request_body = self._ascii_safe(post_data.get("text") or "")

            response_headers = self._normalize_header_dict(response_obj.get("headers") or [])
            response_content = response_obj.get("content") or {}
            if not isinstance(response_content, dict):
                response_content = {}
            response_body = self._ascii_safe(response_content.get("text") or "")
            content_type = self._ascii_safe(
                response_content.get("mimeType")
                or self._extract_content_type_from_headers(response_headers)
                or self._extract_content_type_from_headers(headers)
                or "unknown"
            )
            parameters = self._extract_param_map_from_har_request(request_obj)
            entry = {
                "method": method,
                "path": url_parts.get("path") or "/",
                "normalized_path": url_parts.get("normalized_path") or "/",
                "host": url_parts.get("host") or "",
                "protocol": url_parts.get("protocol") or "https",
                "port": self._int_or_default(url_parts.get("port"), 443),
                "query_string": url_parts.get("query_string") or "",
                "parameters": parameters,
                "headers": headers,
                "request_body": request_body,
                "response_status": self._int_or_default(response_obj.get("status"), 0),
                "response_headers": response_headers,
                "response_body": response_body,
                "response_length": self._int_or_default(
                    response_obj.get("bodySize"),
                    self._int_or_default(response_content.get("size"), len(response_body)),
                ),
                "response_time_ms": self._int_or_default(har_entry.get("time"), 0),
                "captured_at": self._ascii_safe(har_entry.get("startedDateTime") or ""),
                "captured_at_epoch_ms": 0,
                "source_tool": source_tool_label,
                "content_type": content_type,
            }
            shaped = self._coerce_import_entry_shape(entry, source_tool_label)
            if shaped is None:
                continue
            endpoint_key = "{}:{}".format(shaped.get("method"), shaped.get("normalized_path"))
            bucket = snapshot.get(endpoint_key)
            if bucket is None:
                bucket = []
                snapshot[endpoint_key] = bucket
            if len(bucket) < sample_limit:
                bucket.append(shaped)
        except Exception as har_err:
            self._callbacks.printError(
                "Import HAR entry parse error: {}".format(str(har_err))
            )
    return snapshot

def _build_replay_studio_snapshot(self, replay_payload):
    """Parse Excalibur replay-studio scenarios into synthetic Recon entries."""
    snapshot = {}
    if not isinstance(replay_payload, dict):
        return snapshot
    scenarios = replay_payload.get("scenarios") or []
    if not isinstance(scenarios, list):
        return snapshot

    sample_limit = self._current_import_sample_limit()

    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        source = scenario.get("source") or {}
        if not isinstance(source, dict):
            continue
        url_parts = self._parse_url_parts_from_text(source.get("url") or "")
        method = self._ascii_safe(source.get("method") or "GET").upper()
        state_obj = source.get("state")
        state_text = self._ascii_safe(json.dumps(state_obj, sort_keys=True) if state_obj is not None else "")
        variants = scenario.get("variants") or []
        variant_names = []
        if isinstance(variants, list):
            for variant in variants:
                if not isinstance(variant, dict):
                    continue
                name = self._ascii_safe(variant.get("name") or "").strip()
                if name:
                    variant_names.append(name)
        synthetic_body = ""
        if variant_names:
            synthetic_body = "Replay variants: {}".format(", ".join(variant_names[:6]))
        if state_text:
            synthetic_body = (
                synthetic_body + "\nState: " + state_text
                if synthetic_body
                else "State: " + state_text
            )

        entry = {
            "method": method,
            "path": url_parts.get("path") or "/",
            "normalized_path": url_parts.get("normalized_path") or "/",
            "host": url_parts.get("host") or "",
            "protocol": url_parts.get("protocol") or "https",
            "port": self._int_or_default(url_parts.get("port"), 443),
            "query_string": url_parts.get("query_string") or "",
            "parameters": {"url": {}, "body": {}, "cookie": {}, "json": {}},
            "headers": {},
            "request_body": synthetic_body,
            "response_status": 0,
            "response_headers": {},
            "response_body": "",
            "response_length": 0,
            "response_time_ms": 0,
            "captured_at": self._ascii_safe(replay_payload.get("generated_at") or ""),
            "captured_at_epoch_ms": 0,
            "source_tool": "Excalibur Replay Studio",
            "content_type": "application/json",
        }
        shaped = self._coerce_import_entry_shape(entry, "Excalibur Replay Studio")
        if shaped is None:
            continue
        endpoint_key = "{}:{}".format(shaped.get("method"), shaped.get("normalized_path"))
        bucket = snapshot.get(endpoint_key)
        if bucket is None:
            bucket = []
            snapshot[endpoint_key] = bucket
        if len(bucket) < sample_limit:
            bucket.append(shaped)
    return snapshot

def _merge_import_snapshots(self, primary_snapshot, extra_snapshot):
    merged = {}
    for source_snapshot in [primary_snapshot, extra_snapshot]:
        if not isinstance(source_snapshot, dict):
            continue
        for key, entries in source_snapshot.items():
            endpoint_key = self._ascii_safe(key).strip()
            if not endpoint_key:
                continue
            normalized_entries = entries if isinstance(entries, list) else [entries]
            if endpoint_key not in merged:
                merged[endpoint_key] = []
            for entry in normalized_entries:
                if isinstance(entry, dict):
                    merged[endpoint_key].append(entry)
    return merged

def _identify_import_payload_kind(self, data):
    if isinstance(data, dict) and isinstance(data.get("endpoints"), list):
        return "suite_export"
    if isinstance(data, dict):
        schema = self._ascii_safe(
            data.get("schema") or data.get("bridge_schema"),
            lower=True,
        ).strip()
        if schema == "excalibur-burp-bridge/v1":
            return "excalibur_bridge"
        if isinstance((data.get("log") or {}).get("entries"), list):
            return "har"
        if isinstance(data.get("scenarios"), list) and data.get("total_scenarios") is not None:
            return "excalibur_replay_studio"
        if isinstance(data.get("cookies"), dict) and data.get("total_count") is not None:
            return "excalibur_cookies"
        if isinstance(data.get("auth_drift_radar"), dict) or isinstance(data.get("exploration_heatmap"), dict):
            return "excalibur_insights"
        if isinstance(data.get("captures"), list):
            return "excalibur_bridge"
    return "unknown"

def _discover_excalibur_sidecar_paths(self, filepath):
    """Discover sibling Excalibur export artifacts for one selected file."""
    info = {
        "har": "",
        "cookies": "",
        "replay": "",
        "insights": "",
    }
    path_text = self._ascii_safe(filepath or "").strip()
    if not path_text:
        return info
    directory = os.path.dirname(path_text)
    filename = os.path.basename(path_text)

    patterns = [
        "-cookies.json",
        "-replay-studio.json",
        "-insights.json",
        ".har",
    ]
    base_name = filename
    for suffix in patterns:
        if base_name.endswith(suffix):
            base_name = base_name[: -len(suffix)]
            break
    if not base_name.startswith("excalibur-session-"):
        return info

    candidates = {
        "har": os.path.join(directory, "{}.har".format(base_name)),
        "cookies": os.path.join(directory, "{}-cookies.json".format(base_name)),
        "replay": os.path.join(directory, "{}-replay-studio.json".format(base_name)),
        "insights": os.path.join(directory, "{}-insights.json".format(base_name)),
    }
    for key, candidate in candidates.items():
        if os.path.isfile(candidate):
            info[key] = candidate
    return info

def _load_json_file_for_import(self, filepath):
    with open(filepath, "r") as handle:
        return json.load(handle)

def _build_excalibur_bridge_snapshot(self, bridge_payload):
    """Parse `excalibur-burp-bridge/v1` payload into Recon snapshot."""
    snapshot = {}
    if not isinstance(bridge_payload, dict):
        return snapshot
    captures = bridge_payload.get("captures") or []
    if not isinstance(captures, list):
        return snapshot

    sample_limit = self._current_import_sample_limit()

    for capture in captures:
        if not isinstance(capture, dict):
            continue
        try:
            request_obj = capture.get("request") or {}
            response_obj = capture.get("response") or {}
            timing_obj = capture.get("timing") or {}
            context_obj = capture.get("context") or {}
            if not isinstance(request_obj, dict):
                request_obj = {}
            if not isinstance(response_obj, dict):
                response_obj = {}
            if not isinstance(timing_obj, dict):
                timing_obj = {}
            if not isinstance(context_obj, dict):
                context_obj = {}

            method = self._ascii_safe(request_obj.get("method") or "GET").upper()
            url_parts = self._parse_url_parts_from_text(request_obj.get("url") or "")
            headers = self._normalize_header_dict(request_obj.get("headers") or {})
            response_headers = self._normalize_header_dict(response_obj.get("headers") or {})
            content_type = self._ascii_safe(
                request_obj.get("content_type")
                or response_obj.get("content_type")
                or self._extract_content_type_from_headers(response_headers)
                or self._extract_content_type_from_headers(headers)
                or "unknown"
            )
            entry = {
                "method": method,
                "path": self._ascii_safe(url_parts.get("path") or "/"),
                "normalized_path": self._ascii_safe(url_parts.get("normalized_path") or "/"),
                "host": self._ascii_safe(url_parts.get("host") or "", lower=True),
                "protocol": self._ascii_safe(url_parts.get("protocol") or "https", lower=True),
                "port": self._int_or_default(url_parts.get("port"), 443),
                "query_string": self._ascii_safe(url_parts.get("query_string") or ""),
                "parameters": {
                    "url": {},
                    "body": {},
                    "cookie": {},
                    "json": {},
                },
                "headers": headers,
                "request_body": self._ascii_safe(request_obj.get("body") or ""),
                "response_status": self._int_or_default(response_obj.get("status"), 0),
                "response_headers": response_headers,
                "response_body": self._ascii_safe(response_obj.get("body") or ""),
                "response_length": self._int_or_default(response_obj.get("length"), 0),
                "response_time_ms": self._int_or_default(timing_obj.get("response_time_ms"), 0),
                "captured_at": self._ascii_safe(
                    timing_obj.get("captured_at") or bridge_payload.get("exported_at") or ""
                ),
                "captured_at_epoch_ms": self._int_or_default(timing_obj.get("captured_at_epoch_ms"), 0),
                "source_tool": self._ascii_safe(
                    context_obj.get("source_tool")
                    or bridge_payload.get("producer", {}).get("name")
                    or "Excalibur Bridge"
                ),
                "content_type": content_type,
            }
            shaped = self._coerce_import_entry_shape(entry, "Excalibur Bridge")
            if shaped is None:
                continue
            endpoint_key = "{}:{}".format(shaped.get("method"), shaped.get("normalized_path"))
            bucket = snapshot.get(endpoint_key)
            if bucket is None:
                bucket = []
                snapshot[endpoint_key] = bucket
            if len(bucket) < sample_limit:
                bucket.append(shaped)
        except Exception as bridge_err:
            self._callbacks.printError(
                "Import bridge capture parse error: {}".format(str(bridge_err))
            )
    return snapshot

def _resolve_import_payload(self, filepath, root_payload):
    """Build one normalized snapshot from supported import formats."""
    payload_kind = self._identify_import_payload_kind(root_payload)
    resolved_snapshot = {}
    import_meta = {
        "kind": payload_kind,
        "source_tool_label": "Import",
        "excalibur_detected": False,
        "sidecars": {},
    }

    if payload_kind == "suite_export":
        resolved_snapshot = self._build_suite_export_snapshot(root_payload)
        import_meta["source_tool_label"] = "Import"
        return resolved_snapshot, import_meta

    sidecar_paths = self._discover_excalibur_sidecar_paths(filepath)
    import_meta["sidecars"] = sidecar_paths
    import_meta["excalibur_detected"] = any(
        bool(path_value) for path_value in sidecar_paths.values()
    ) or payload_kind.startswith("excalibur") or payload_kind in ["har", "excalibur_replay_studio", "excalibur_cookies", "excalibur_insights"]

    har_payload = None
    replay_payload = None
    cookie_payload = None
    insights_payload = None

    if payload_kind == "har":
        har_payload = root_payload
    elif payload_kind == "excalibur_replay_studio":
        replay_payload = root_payload
    elif payload_kind == "excalibur_cookies":
        cookie_payload = root_payload
    elif payload_kind == "excalibur_insights":
        insights_payload = root_payload
    elif payload_kind == "excalibur_bridge":
        resolved_snapshot = self._build_excalibur_bridge_snapshot(root_payload)
        import_meta["source_tool_label"] = "Excalibur Bridge"
        return resolved_snapshot, import_meta

    for sidecar_kind, sidecar_path in sidecar_paths.items():
        if (not sidecar_path) or sidecar_path == filepath:
            continue
        try:
            sidecar_payload = self._load_json_file_for_import(sidecar_path)
            if sidecar_kind == "har" and har_payload is None:
                har_payload = sidecar_payload
            elif sidecar_kind == "cookies" and cookie_payload is None:
                cookie_payload = sidecar_payload
            elif sidecar_kind == "replay" and replay_payload is None:
                replay_payload = sidecar_payload
            elif sidecar_kind == "insights" and insights_payload is None:
                insights_payload = sidecar_payload
        except Exception as sidecar_err:
            self._callbacks.printError(
                "Import sidecar load failed ({}): {}".format(sidecar_path, str(sidecar_err))
            )

    if har_payload is not None:
        try:
            entries = ((har_payload.get("log") or {}).get("entries")) if isinstance(har_payload, dict) else []
            resolved_snapshot = self._build_har_snapshot(
                entries,
                "Excalibur HAR",
                cookie_payload=cookie_payload,
            )
            import_meta["source_tool_label"] = "Excalibur HAR"
        except Exception as har_err:
            self._callbacks.printError(
                "Import HAR snapshot build failed: {}".format(str(har_err))
            )
            resolved_snapshot = {}

    replay_snapshot = {}
    if replay_payload is not None:
        try:
            replay_snapshot = self._build_replay_studio_snapshot(replay_payload)
        except Exception as replay_err:
            self._callbacks.printError(
                "Import replay snapshot build failed: {}".format(str(replay_err))
            )
            replay_snapshot = {}

    merged_snapshot = self._merge_import_snapshots(resolved_snapshot, replay_snapshot)
    if not merged_snapshot and payload_kind == "excalibur_replay_studio":
        import_meta["source_tool_label"] = "Excalibur Replay Studio"
        merged_snapshot = replay_snapshot

    if insights_payload is not None and isinstance(insights_payload, dict):
        auth_drift_total = self._int_or_default(
            (insights_payload.get("auth_drift_radar") or {}).get("total_events"), 0
        )
        blind_spot_count = len(
            ((insights_payload.get("exploration_heatmap") or {}).get("blind_spots") or [])
        )
        self.log_to_ui(
            "[*] Excalibur insights loaded: auth_drift_events={} blind_spots={}".format(
                auth_drift_total, blind_spot_count
            )
        )

    return merged_snapshot, import_meta

def _merge_import_snapshot_into_recon(self, import_snapshot):
    """Insert parsed import snapshot into Recon state."""
    imported = 0
    skipped = 0
    imported_snapshot = {}
    if not isinstance(import_snapshot, dict):
        return imported, skipped, imported_snapshot

    for endpoint_key in sorted(import_snapshot.keys()):
        entries = import_snapshot.get(endpoint_key, [])
        entries_list = entries if isinstance(entries, list) else [entries]
        sanitized_entries = []
        for raw_entry in entries_list:
            shaped = self._coerce_import_entry_shape(raw_entry, "Import")
            if shaped is not None:
                sanitized_entries.append(shaped)
        if not sanitized_entries:
            continue

        key = self._ascii_safe(endpoint_key).strip()
        if not key:
            sample = sanitized_entries[0]
            key = "{}:{}".format(sample.get("method"), sample.get("normalized_path"))

        with self.lock:
            if key in self.api_data:
                skipped += 1
                continue
            self.api_data[key] = list(sanitized_entries)
            first = sanitized_entries[0]
            self.endpoint_tags[key] = self._auto_tag(first)
            self.endpoint_times[key] = [
                self._int_or_default(item.get("response_time_ms"), 0)
                for item in sanitized_entries
            ]
            imported_snapshot[key] = [dict(item) for item in sanitized_entries]
            imported += 1
    return imported, skipped, imported_snapshot

def _run_excalibur_auto_pipeline(self, imported_count):
    """Auto-run deep-logic refresh after Excalibur imports."""
    if imported_count <= 0:
        return
    if not bool(getattr(self, "excalibur_auto_pipeline_enabled", True)):
        self.log_to_ui("[*] Excalibur auto-pipeline disabled; skipping invariant refresh")
        return
    self.log_to_ui(
        "[*] Excalibur auto-pipeline: refreshing Differential + Sequence + Golden + State + Token Lineage + Parity Drift"
    )
    self._refresh_sequence_invariants_from_recon(None)

def import_data(self):
    """Import Suite export JSON, Excalibur HAR/session artifacts, or bridge bundles."""
    chooser = JFileChooser()
    chooser.setDialogTitle("Import API Security Suite / Excalibur JSON")
    if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
        filepath = chooser.getSelectedFile().getAbsolutePath()
        try:
            data = self._load_json_file_for_import(filepath)
            import_snapshot, import_meta = self._resolve_import_payload(filepath, data)
            imported, skipped, imported_snapshot = self._merge_import_snapshot_into_recon(import_snapshot)

            source_label = self._ascii_safe(import_meta.get("source_tool_label") or "Import")
            kind_label = self._ascii_safe(import_meta.get("kind") or "unknown")
            self.log_to_ui(
                "[+] Imported {} endpoints from {} (kind={}, source={})".format(
                    imported, filepath, kind_label, source_label
                )
            )
            if skipped > 0:
                self.log_to_ui(
                    "[*] Import skipped {} existing endpoint keys".format(skipped)
                )
            SwingUtilities.invokeLater(
                lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
            )
            SwingUtilities.invokeLater(lambda: self._update_host_filter())
            SwingUtilities.invokeLater(lambda: self._update_stats())
            SwingUtilities.invokeLater(lambda: self.refresh_view())
            SwingUtilities.invokeLater(lambda: self._refresh_recon_invariant_status_label())
            if imported_snapshot:
                logger_added = int(
                    self._sync_logger_from_recon_snapshot(
                        imported_snapshot, source_tool_label=source_label
                    )
                    or 0
                )
                self.log_to_ui(
                    "[+] Logger sync from import: {} rows added".format(logger_added)
                )
            if bool(import_meta.get("excalibur_detected", False)):
                self._run_excalibur_auto_pipeline(imported)
        except Exception as e:
            self.log_to_ui("[!] Import failed: {}".format(str(e)))
            import traceback

            self._callbacks.printError(traceback.format_exc())

def _entry_to_excalibur_bridge_capture(self, endpoint_key, entry, endpoint_tags):
    """Convert one captured entry into Excalibur bridge capture format."""
    normalized_entry = self._coerce_import_entry_shape(entry, "Bridge Export")
    if not normalized_entry:
        return None
    url_info = self._build_entry_url(normalized_entry)
    full_url = self._ascii_safe(url_info.get("url") or "").strip()
    if not full_url:
        protocol = self._ascii_safe(normalized_entry.get("protocol") or "https", lower=True)
        host = self._ascii_safe(normalized_entry.get("host") or "", lower=True)
        port = self._int_or_default(normalized_entry.get("port"), 443 if protocol == "https" else 80)
        path = self._ascii_safe(normalized_entry.get("path") or "/")
        query = self._ascii_safe(normalized_entry.get("query_string") or "")
        if query:
            full_url = "{}://{}:{}{}?{}".format(protocol, host, port, path, query)
        else:
            full_url = "{}://{}:{}{}".format(protocol, host, port, path)

    request_headers = self._normalize_header_dict(normalized_entry.get("headers") or {})
    response_headers = self._normalize_header_dict(normalized_entry.get("response_headers") or {})
    capture = {
        "request": {
            "method": self._ascii_safe(normalized_entry.get("method") or "GET").upper(),
            "url": full_url,
            "headers": request_headers,
            "body": self._ascii_safe(normalized_entry.get("request_body") or ""),
            "content_type": self._extract_content_type_from_headers(
                request_headers,
                fallback_value=normalized_entry.get("content_type") or "unknown",
            ),
        },
        "response": {
            "status": self._int_or_default(normalized_entry.get("response_status"), 0),
            "headers": response_headers,
            "body": self._ascii_safe(normalized_entry.get("response_body") or ""),
            "length": self._int_or_default(normalized_entry.get("response_length"), 0),
            "content_type": self._extract_content_type_from_headers(
                response_headers,
                fallback_value=normalized_entry.get("content_type") or "unknown",
            ),
        },
        "timing": {
            "response_time_ms": self._int_or_default(normalized_entry.get("response_time_ms"), 0),
            "captured_at": self._ascii_safe(normalized_entry.get("captured_at") or ""),
            "captured_at_epoch_ms": self._int_or_default(normalized_entry.get("captured_at_epoch_ms"), 0),
        },
        "context": {
            "endpoint_key": self._ascii_safe(endpoint_key or ""),
            "source_tool": self._ascii_safe(normalized_entry.get("source_tool") or ""),
            "normalized_path": self._ascii_safe(normalized_entry.get("normalized_path") or ""),
            "host": self._ascii_safe(normalized_entry.get("host") or "", lower=True),
            "tags": list(endpoint_tags or []),
            "auth_methods": list(normalized_entry.get("auth_detected") or []),
        },
    }
    return capture

def _build_excalibur_bridge_bundle(self, data_to_export, scope_label):
    """Build shared Excalibur bridge bundle from Recon snapshot."""
    captures = []
    endpoint_count = 0
    if isinstance(data_to_export, dict):
        endpoint_count = len(data_to_export)
        for endpoint_key in sorted(data_to_export.keys()):
            entries = data_to_export.get(endpoint_key, [])
            entries_list = entries if isinstance(entries, list) else [entries]
            with self.lock:
                endpoint_tags = list(
                    (self.endpoint_tags.get(endpoint_key) or [])
                )
            for entry in entries_list:
                capture = self._entry_to_excalibur_bridge_capture(
                    endpoint_key,
                    entry,
                    endpoint_tags,
                )
                if capture is not None:
                    captures.append(capture)
    exported_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    bundle = {
        "schema": "excalibur-burp-bridge/v1",
        "producer": {
            "name": "BurpAPISecuritySuite",
            "module": "burp_capture_export_and_tooling_methods",
        },
        "exported_at": exported_at,
        "scope": self._ascii_safe(scope_label or "All"),
        "summary": {
            "endpoint_count": int(endpoint_count),
            "capture_count": int(len(captures)),
        },
        "captures": captures,
    }
    return bundle

def _export_data(self, data_to_export, suffix=""):
    """Helper to export data"""
    timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
    analysis = {
        "metadata": {
            "timestamp": timestamp,
            "total_endpoints": len(data_to_export),
            "total_requests": sum(len(v) for v in data_to_export.values()),
        },
        "endpoints": [],
        "api_structure": self._analyze_structure_for(data_to_export),
        "security_observations": self._analyze_security_for(data_to_export),
        "llm_prompt": self._generate_llm_prompt(),
    }

    for endpoint_key, entries in data_to_export.items():
        entry = self._get_entry(entries)
        entries_list = entries if isinstance(entries, list) else [entries]
        endpoint_summary = {
            "endpoint": endpoint_key,
            "method": entry["method"],
            "normalized_path": entry["normalized_path"],
            "host": self._get_entry(entries)["host"],
            "sample_count": len(entries_list),
            "parameters": self._merge_params(entries_list),
            "auth_methods": list(
                set([a for e in entries_list for a in e["auth_detected"]])
            ),
            "response_codes": list(
                set([e["response_status"] for e in entries_list])
            ),
            "content_types": list(set([e["content_type"] for e in entries_list])),
            "api_patterns": list(
                set([p for e in entries_list for p in e["api_patterns"]])
            ),
            "avg_response_length": sum(e["response_length"] for e in entries_list)
            / len(entries_list),
            "avg_response_time_ms": sum(
                e.get("response_time_ms", 0) for e in entries_list
            )
            / len(entries_list),
            "jwt_claims": entry.get("jwt_detected"),
            "encryption_detected": any(
                e.get("encryption_indicators", {}).get("likely_encrypted")
                for e in entries_list
            ),
            "encryption_types": list(
                set(
                    [
                        t
                        for e in entries_list
                        for t in e.get("encryption_indicators", {}).get("types", [])
                    ]
                )
            ),
            "reflected_params": list(
                set(
                    [
                        p
                        for e in entries_list
                        for p in e.get("param_patterns", {}).get("reflected", [])
                    ]
                )
            ),
            "param_type_summary": self._summarize_param_types(entries_list),
            "sample_requests": [self._format_sample(e) for e in entries_list[:3]],
        }
        analysis["endpoints"].append(endpoint_summary)

    import os

    host_name = suffix.replace("_", "").replace(".", "_") if suffix else ""
    export_dir = self._get_export_dir("HostExport{}".format(host_name))
    if not export_dir:
        self.log_to_ui("[!] Cannot create export directory")
        return
    filename = os.path.join(export_dir, "api_analysis.json")
    bridge_filename = os.path.join(export_dir, "excalibur_bridge_bundle.json")
    writer = None
    bridge_writer = None
    try:
        writer = FileWriter(filename)
        writer.write(json.dumps(analysis, indent=2))
        bridge_scope = suffix if suffix else "All"
        bridge_bundle = self._build_excalibur_bridge_bundle(
            data_to_export,
            scope_label=bridge_scope,
        )
        bridge_writer = FileWriter(bridge_filename)
        bridge_writer.write(json.dumps(bridge_bundle, indent=2))
        self.log_to_ui(
            "[+] Exported {} endpoints to: {}".format(
                len(data_to_export), export_dir
            )
        )
        self.log_to_ui("[+] Excalibur bridge bundle: {}".format(bridge_filename))
    except Exception as e:
        self.log_to_ui("[!] Export failed: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError("Error closing writer: " + str(e))
        if bridge_writer:
            try:
                bridge_writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing bridge writer: " + str(e)
                )

def _openapi_schema_from_inferred_type(self, inferred_type):
    """Map inferred parameter type hints to OpenAPI schema fragments."""
    hint = self._ascii_safe(inferred_type or "string", lower=True).strip()
    if hint == "boolean":
        return {"type": "boolean"}
    if hint == "integer":
        return {"type": "integer"}
    if hint == "float":
        return {"type": "number", "format": "float"}
    if hint == "uuid":
        return {"type": "string", "format": "uuid"}
    if hint == "email":
        return {"type": "string", "format": "email"}
    if hint == "json":
        return {"type": "object"}
    return {"type": "string"}

def _build_openapi_spec_from_capture(self, data_snapshot, scope_label="All"):
    """Generate OpenAPI 3.0.3 document from captured endpoint snapshots."""
    if not isinstance(data_snapshot, dict):
        data_snapshot = {}

    paths = {}
    host_counts = {}
    auth_schemes = set()
    method_order = ["get", "post", "put", "patch", "delete", "options", "head"]

    for endpoint_key in sorted(data_snapshot.keys()):
        entries = data_snapshot.get(endpoint_key, [])
        entries_list = entries if isinstance(entries, list) else [entries]
        if not entries_list:
            continue
        entry = self._get_entry(entries_list)

        method = self._ascii_safe(entry.get("method") or "GET").upper()
        path = self._ascii_safe(entry.get("normalized_path") or entry.get("path") or "/")
        if not path.startswith("/"):
            path = "/" + path
        method_key = self._ascii_safe(method, lower=True)
        if method_key not in method_order:
            method_key = "get"

        host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
        if host:
            host_counts[host] = host_counts.get(host, 0) + 1

        path_item = paths.get(path)
        if not isinstance(path_item, dict):
            path_item = {}
            paths[path] = path_item

        op_suffix = re.sub(r"[^a-zA-Z0-9]+", "_", path).strip("_")
        if not op_suffix:
            op_suffix = "root"
        operation = {
            "summary": "Observed {} {}".format(method, path),
            "operationId": "{}_{}".format(method_key, op_suffix),
            "tags": [self._split_path_segments(path)[0] if self._split_path_segments(path) else "root"],
            "parameters": [],
            "responses": {},
        }

        path_param_names = []
        for holder in re.findall(r"\{([^}]+)\}", path):
            safe_holder = self._ascii_safe(holder).strip()
            if safe_holder and safe_holder not in path_param_names:
                path_param_names.append(safe_holder)
                operation["parameters"].append(
                    {
                        "name": safe_holder,
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                )

        inferred_types = self._infer_param_types(entry)
        merged_params = self._merge_params(entries_list)
        url_params = merged_params.get("url", {})
        if isinstance(url_params, dict):
            for name in sorted(url_params.keys()):
                safe_name = self._ascii_safe(name).strip()
                if (not safe_name) or (safe_name in path_param_names):
                    continue
                operation["parameters"].append(
                    {
                        "name": safe_name,
                        "in": "query",
                        "required": False,
                        "schema": self._openapi_schema_from_inferred_type(
                            inferred_types.get(safe_name, "string")
                        ),
                    }
                )

        request_properties = {}
        for source_name in ["body", "json"]:
            source_params = merged_params.get(source_name, {})
            if not isinstance(source_params, dict):
                continue
            for name in sorted(source_params.keys()):
                safe_name = self._ascii_safe(name).strip()
                if not safe_name:
                    continue
                request_properties[safe_name] = self._openapi_schema_from_inferred_type(
                    inferred_types.get(safe_name, "string")
                )
        if request_properties:
            operation["requestBody"] = {
                "required": method in ["POST", "PUT", "PATCH"],
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": request_properties}
                    }
                },
            }

        response_statuses = {}
        response_types = {}
        auth_seen = set()
        source_tools = set()
        for sample in entries_list[:80]:
            status = int(sample.get("response_status", 0) or 0)
            status_key = "default" if status <= 0 else str(status)
            response_statuses[status_key] = response_statuses.get(status_key, 0) + 1

            content_type = self._ascii_safe(sample.get("content_type") or "", lower=True)
            if status_key not in response_types:
                response_types[status_key] = set()
            if "json" in content_type:
                response_types[status_key].add("application/json")
            elif "xml" in content_type:
                response_types[status_key].add("application/xml")
            elif content_type:
                response_types[status_key].add("text/plain")

            for auth_item in sample.get("auth_detected", []) or []:
                safe_auth = self._ascii_safe(auth_item, lower=True)
                if safe_auth:
                    auth_seen.add(safe_auth)
            tool_name = self._ascii_safe(sample.get("source_tool") or "")
            if tool_name:
                source_tools.add(tool_name)

        for status_key in sorted(
            response_statuses.keys(),
            key=lambda x: (999 if x == "default" else int(x), x),
        ):
            description = "Captured response"
            if status_key != "default":
                status_int = int(status_key)
                if status_int == 200:
                    description = "Successful response"
                elif status_int == 201:
                    description = "Created"
                elif status_int == 204:
                    description = "No content"
                elif status_int in [400, 422]:
                    description = "Validation/client error"
                elif status_int in [401, 403]:
                    description = "Authorization error"
                elif status_int == 404:
                    description = "Not found"
                elif status_int >= 500:
                    description = "Server error"
            response_obj = {"description": description}
            media_types = sorted(list(response_types.get(status_key, set()) or []))
            if media_types:
                content_obj = {}
                for media_type in media_types:
                    schema_obj = {"type": "object"} if "json" in media_type else {"type": "string"}
                    content_obj[media_type] = {"schema": schema_obj}
                response_obj["content"] = content_obj
            operation["responses"][status_key] = response_obj
        if not operation["responses"]:
            operation["responses"] = {"default": {"description": "Captured response"}}

        security = []
        if any("bearer" in item for item in auth_seen):
            security.append({"bearerAuth": []})
            auth_schemes.add("bearerAuth")
        if any("api key" in item for item in auth_seen):
            security.append({"apiKeyAuth": []})
            auth_schemes.add("apiKeyAuth")
        if any("cookie" in item for item in auth_seen):
            security.append({"cookieAuth": []})
            auth_schemes.add("cookieAuth")
        if security:
            operation["security"] = security

        operation["x-burp-capture"] = {
            "endpoint_key": self._ascii_safe(endpoint_key),
            "sample_count": len(entries_list),
            "source_tools": sorted(list(source_tools)),
            "observed_auth_types": sorted(list(auth_seen)),
        }
        path_item[method_key] = operation

    top_host = ""
    if host_counts:
        top_host = sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
    server_url = "https://{}".format(top_host) if top_host else "https://example.com"

    components = {"securitySchemes": {}}
    if "bearerAuth" in auth_schemes:
        components["securitySchemes"]["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    if "apiKeyAuth" in auth_schemes:
        components["securitySchemes"]["apiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
        }
    if "cookieAuth" in auth_schemes:
        components["securitySchemes"]["cookieAuth"] = {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
        }

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Captured API (Generated)",
            "version": "1.0.0",
            "description": "Auto-generated from BurpAPISecuritySuite captured traffic (scope: {}).".format(
                self._ascii_safe(scope_label)
            ),
        },
        "servers": [{"url": server_url}],
        "paths": paths,
        "x-generated-by": "BurpAPISecuritySuite",
        "x-generated-at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if components["securitySchemes"]:
        spec["components"] = components
    return self._sanitize_for_ai_payload(spec)

def _generate_openapi_from_capture(self, event=None):
    """One-click OpenAPI generation from captured Recon traffic."""
    with self.lock:
        snapshot = dict(self.api_data)
    if not snapshot:
        self.log_to_ui("[!] OpenAPI generation: no captured endpoints")
        if hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.setText("[!] OpenAPI generation: no captured endpoints\n")
        return

    scope_label = "All Endpoints"
    selected_host = ""
    try:
        if hasattr(self, "host_filter") and self.host_filter is not None:
            selected_host = self._ascii_safe(
                str(self.host_filter.getSelectedItem()) if self.host_filter.getSelectedItem() is not None else "",
                lower=True,
            ).strip()
    except Exception as e:
        self._callbacks.printError(
            "OpenAPI generation host-filter read error: {}".format(str(e))
        )
        selected_host = ""

    scoped_data = {}
    if selected_host and selected_host != "all":
        for endpoint_key, entries in snapshot.items():
            host = self._ascii_safe(
                self._get_entry(entries).get("host") or "", lower=True
            ).strip()
            if host == selected_host:
                scoped_data[endpoint_key] = entries
        scope_label = "Host: {}".format(selected_host)
    else:
        scoped_data = snapshot

    if not scoped_data:
        self.log_to_ui("[!] OpenAPI generation: no endpoints in current scope")
        if hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.setText(
                "[!] OpenAPI generation: no endpoints in current scope\n"
            )
        return

    spec = self._build_openapi_spec_from_capture(scoped_data, scope_label=scope_label)
    export_dir = self._get_export_dir("OpenAPI_Generated")
    if not export_dir:
        self.log_to_ui("[!] OpenAPI generation: cannot create export directory")
        return

    filepath = os.path.join(export_dir, "openapi_generated.json")
    writer = None
    try:
        writer = FileWriter(filepath)
        writer.write(json.dumps(spec, indent=2))
    except Exception as e:
        self.log_to_ui("[!] OpenAPI generation failed: {}".format(str(e)))
        return
    finally:
        if writer:
            try:
                writer.close()
            except Exception as close_err:
                self._callbacks.printError(
                    "OpenAPI generation writer close error: {}".format(str(close_err))
                )

    path_count = len((spec.get("paths", {}) or {}).keys())
    operation_count = 0
    for path_item in (spec.get("paths", {}) or {}).values():
        if not isinstance(path_item, dict):
            continue
        for key in path_item.keys():
            if key in ["get", "post", "put", "patch", "delete", "options", "head"]:
                operation_count += 1

    self.log_to_ui(
        "[+] OpenAPI generated: {} paths / {} operations ({})".format(
            path_count, operation_count, scope_label
        )
    )
    self.log_to_ui("[+] OpenAPI file: {}".format(filepath))

    if hasattr(self, "openapi_spec_field") and self.openapi_spec_field is not None:
        self.openapi_spec_field.setText(filepath)
    if hasattr(self, "openapi_area") and self.openapi_area is not None:
        self.openapi_area.setText(
            "\n".join(
                [
                    "[+] Generated OpenAPI from captured traffic",
                    "[*] Scope: {}".format(scope_label),
                    "[*] Paths: {}".format(path_count),
                    "[*] Operations: {}".format(operation_count),
                    "[*] File: {}".format(filepath),
                    "",
                    "[*] Tip: click 'Run Drift' to compare this generated spec against future captured traffic.",
                ]
            )
            + "\n"
        )

def _analyze_structure_for(self, data):
    """Analyze structure for specific dataset"""
    structure = {
        "api_types": set(),
        "http_methods": set(),
        "auth_methods": set(),
        "base_paths": set(),
    }
    for entries in data.values():
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            structure["http_methods"].add(entry["method"])
            structure["auth_methods"].update(entry["auth_detected"])
            structure["api_types"].update(entry["api_patterns"])
            path = entry["normalized_path"]
            if path.startswith("/api/"):
                structure["base_paths"].add("/api/")
            elif path.startswith("/v1/"):
                structure["base_paths"].add("/v1/")
    return {k: list(v) for k, v in structure.items()}

def _analyze_security_for(self, data):
    """Analyze security for specific dataset"""
    return self._analyze_security(data)

def show_endpoint_details(self, endpoint_key):
    return jython_size_helpers.show_endpoint_details(self, endpoint_key)

def createMenuItems(self, invocation):
    """Create context menu items"""
    menu_items = ArrayList()

    # Only show menu for requests
    if invocation.getInvocationContext() in [
        invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
        invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
    ]:
        messages = invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            menu_item = JMenuItem("Send to API Security Suite")
            menu_item.addActionListener(lambda e: self._send_to_recon(messages[0]))
            menu_items.add(menu_item)

            repeater_item = JMenuItem("Send to Repeater")
            repeater_item.addActionListener(
                lambda e: self._send_to_repeater(messages[0])
            )
            menu_items.add(repeater_item)

    return menu_items if menu_items.size() > 0 else None

def _send_to_recon(self, messageInfo):
    """Manually add request to API Security Suite"""
    self.log_to_ui("[*] Manually adding request to API Security Suite...")
    self._process_traffic(messageInfo, source_tool="Manual")

def _send_to_repeater(self, messageInfo):
    """Send request to Burp Repeater"""
    httpService = messageInfo.getHttpService()
    self._callbacks.sendToRepeater(
        httpService.getHost(),
        httpService.getPort(),
        httpService.getProtocol() == "https",
        messageInfo.getRequest(),
        None,
    )
    self.log_to_ui(
        "[+] Sent to Repeater: {}://{}".format(
            httpService.getProtocol(), httpService.getHost()
        )
    )

def _send_endpoint_to_repeater(self, endpoint_key):
    """Reconstruct and send endpoint to Repeater"""
    with self.lock:
        if endpoint_key not in self.api_data:
            return
        entries = self.api_data[endpoint_key]
    entry = self._get_entry(entries)

    # Build request line
    path = entry["path"]
    if entry.get("query_string"):
        path += "?" + entry["query_string"]
    request_line = "{} {} HTTP/1.1\r\n".format(entry["method"], path)

    # Build headers
    headers = []
    headers.append("Host: {}".format(entry["host"]))
    for k, v in entry.get("headers", {}).items():
        if k.lower() != "host":
            headers.append("{}: {}".format(k, v))

    # Build full request
    request_str = request_line + "\r\n".join(headers) + "\r\n\r\n"
    if entry.get("request_body"):
        request_str += entry["request_body"]

    request_bytes = self._helpers.stringToBytes(request_str)

    # Send to Repeater
    use_https = entry["protocol"] == "https"
    port = entry["port"]
    if port == -1:
        port = 443 if use_https else 80

    self._callbacks.sendToRepeater(
        entry["host"], port, use_https, request_bytes, endpoint_key
    )
    self.log_to_ui("[+] Sent to Repeater: {}".format(endpoint_key))

def _build_url(self, entry, include_path=True):
    """Helper to build URL from entry"""
    port = (
        entry["port"]
        if entry["port"] != -1
        else (443 if entry["protocol"] == "https" else 80)
    )
    base = "{}://{}:{}".format(entry["protocol"], entry["host"], port)
    return base + entry["path"] if include_path else base

def _export_urls_to_file(
    self, export_dir, filename, include_path=True, unique_hosts=False
):
    """Helper to export URLs to file"""
    import os

    filepath = os.path.join(export_dir, filename)
    writer = None
    try:
        writer = FileWriter(filepath)
        with self.lock:
            data_snapshot = list(self.api_data.items())
        if unique_hosts:
            hosts = set()
            for key, entries in data_snapshot:
                url = self._build_url(self._get_entry(entries), False)
                if url not in hosts:
                    hosts.add(url)
                    writer.write(url + "\n")
        else:
            for _, entries in data_snapshot:
                writer.write(
                    self._build_url(self._get_entry(entries), include_path) + "\n"
                )
        return filepath
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing file {}: {}".format(filepath, str(e))
                )

def _run_tool_async(self, cmd, output_area, result_processor=None):
    """
    Run external tool asynchronously with heartbeat and result processing.
    Fixes hanging UI and missing output issues.
    """
    import os
    import subprocess
    import tempfile
    import threading
    import time as time_module

    # Helper to identify tool for logging
    tool_name = cmd[0].split("/")[-1] if "/" in cmd[0] else cmd[0]

    def run_thread():
        try:
            cmd_str = " ".join(cmd)
            # Update UI immediately
            SwingUtilities.invokeLater(
                lambda: output_area.append("[*] Command: {}\n\n".format(cmd_str))
            )
            self.log_to_ui("[*] Running: {}".format(tool_name))

            capture_fd = None
            capture_path = None
            capture_handle = None
            process = None

            try:
                capture_fd, capture_path = tempfile.mkstemp(
                    prefix="burp_tool_async_", suffix=".log"
                )
                os.close(capture_fd)
                capture_fd = None
                capture_handle = open(capture_path, "wb")
                # File-backed capture avoids PIPE deadlocks on noisy tools.
                process = subprocess.Popen(
                    cmd,
                    stdout=capture_handle,
                    stderr=subprocess.STDOUT,
                    shell=False,
                )
            finally:
                if capture_handle:
                    try:
                        capture_handle.close()
                    except Exception as close_err:
                        self._callbacks.printError(
                            "{} capture close error: {}".format(
                                tool_name, str(close_err)
                            )
                        )

            start_time = time_module.time()
            timeout = 600  # 10 minutes
            result_count = 0
            last_read_offset = 0

            SwingUtilities.invokeLater(
                lambda: output_area.append("[*] Stage: Running...\n")
            )

            def pump_capture():
                """Read newly-written capture bytes and append to UI."""
                if not capture_path or (not os.path.exists(capture_path)):
                    return 0
                try:
                    with open(capture_path, "rb") as reader:
                        reader.seek(last_read_offset)
                        chunk = reader.read()
                except Exception as read_err:
                    self._callbacks.printError(
                        "{} capture read error: {}".format(
                            tool_name, str(read_err)
                        )
                    )
                    return 0

                if not chunk:
                    return 0

                decoded = self._decode_process_data(
                    chunk, "{} stdout chunk".format(tool_name)
                )
                if not decoded:
                    return 0

                clean_text = self.ANSI_ESCAPE_PATTERN.sub("", decoded)
                non_empty_lines = [
                    line for line in clean_text.splitlines() if line.strip()
                ]
                if non_empty_lines:
                    SwingUtilities.invokeLater(
                        lambda t=clean_text: output_area.append(t)
                    )
                return len(chunk), len(non_empty_lines)

            def cleanup_capture_file():
                if capture_path and os.path.exists(capture_path):
                    try:
                        os.remove(capture_path)
                    except Exception as cleanup_err:
                        self._callbacks.printError(
                            "{} capture cleanup error: {}".format(
                                tool_name, str(cleanup_err)
                            )
                        )

            # Non-blocking monitor loop (no readline on pipes).
            while process.poll() is None:
                elapsed = int(time_module.time() - start_time)
                if elapsed > timeout:
                    try:
                        process.kill()
                        process.wait()
                    except Exception as e:
                        self._callbacks.printError(
                            "Process kill failed: {}".format(str(e))
                        )
                    SwingUtilities.invokeLater(
                        lambda: output_area.append(
                            "\n[!] Timeout after {}s\n".format(timeout)
                        )
                    )
                    cleanup_capture_file()
                    return

                pumped = pump_capture()
                if pumped:
                    bytes_read, lines_read = pumped
                    last_read_offset += bytes_read
                    result_count += lines_read
                time_module.sleep(0.2)

            process.wait()
            pumped = pump_capture()
            if pumped:
                bytes_read, lines_read = pumped
                last_read_offset += bytes_read
                result_count += lines_read

            total_time = int(time_module.time() - start_time)

            if result_count == 0:
                SwingUtilities.invokeLater(
                    lambda: output_area.append(
                        "\n[!] Complete: {}s | No results (target may be slow/unreachable)\n".format(
                            total_time
                        )
                    )
                )
                self.log_to_ui(
                    "[!] {}: {}s, no results".format(tool_name, total_time)
                )
            else:
                SwingUtilities.invokeLater(
                    lambda: output_area.append(
                        "\n[+] Complete: {}s | {} results\n".format(
                            total_time, result_count
                        )
                    )
                )
                self.log_to_ui(
                    "[+] {}: {}s, {} results".format(
                        tool_name, total_time, result_count
                    )
                )

            # Trigger result processor (file reading)
            if result_processor:
                SwingUtilities.invokeLater(result_processor)

            cleanup_capture_file()

        except Exception as e:
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda: output_area.append(
                    "\n[!] Critical Error: {}\n".format(err_msg)
                )
            )
            self.log_to_ui("[!] {} error: {}".format(tool_name, err_msg))
            print(err_msg)  # Print to Burp console for debugging
            try:
                if capture_path and os.path.exists(capture_path):
                    os.remove(capture_path)
            except Exception as cleanup_err:
                self._callbacks.printError(
                    "{} capture cleanup error: {}".format(
                        tool_name, str(cleanup_err)
                    )
                )

    # Start the thread
    t = threading.Thread(target=run_thread)
    t.daemon = True
    t.start()

def _process_file_results(self, output_file, output_area):
    """
    Generic helper to read output files and display them in the UI.
    """
    import os

    try:
        if not os.path.exists(output_file):
            output_area.append(
                "\n[!] Expected output file not found: {}\n".format(output_file)
            )
            return

        with open(output_file, "r") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]

        count = len(lines)

        summary = "\n" + "=" * 60 + "\n"
        summary += " RESULT SUMMARY\n"
        summary += "=" * 60 + "\n"
        summary += "[+] File: {}\n".format(output_file)
        summary += "[+] Total Results Found: {}\n".format(count)

        if count > 0:
            summary += "\n--- First 20 Results ---\n"
            summary += "\n".join(lines[:20])
            if count > 20:
                summary += "\n... ({} more results in file)".format(count - 20)
        else:
            summary += "\n[!] No results found in output file.\n"

        summary += "\n" + "=" * 60 + "\n"
        output_area.append(summary)

    except Exception as e:
        output_area.append(
            "\n[!] Error processing results file: {}\n".format(str(e))
        )

def _export_httpx_urls(self):
    """Export URLs for HTTPX probing - only saves when user clicks Export"""
    if not self.api_data:
        self.httpx_area.setText("[!] No endpoints to export\n")
        return
    export_dir = self._get_export_dir("HTTPX_Export")
    if not export_dir:
        return
    try:
        filepath = self._export_urls_to_file(export_dir, "urls.txt")
        self.httpx_area.setText(
            "[+] Exported {} URLs\n[+] File: {}\n[+] Folder: {}\n".format(
                len(self.api_data), filepath, export_dir
            )
        )
        self.log_to_ui("[+] Exported HTTPX URLs to: {}".format(export_dir))
    except Exception as e:
        self.httpx_area.append("[!] Export failed: {}\n".format(str(e)))

def _clean_url(self, url):
    r"""Remove \n\t and other unwanted characters from URL"""
    return re.sub(r"[\n\t\r]", "", url.strip())

def _cleanup_temp_dir(self, temp_dir, context):
    """Delete temporary directory and report cleanup failures explicitly."""
    import os
    import shutil

    if not temp_dir:
        return
    if not os.path.exists(temp_dir):
        return

    try:
        shutil.rmtree(temp_dir)
    except Exception as e:
        self._callbacks.printError(
            "Cleanup error ({}): {}".format(context, str(e))
        )

def _resolve_custom_command(self, tool_name, checkbox, field, context, output_area):
    """Resolve command template when custom command override is enabled."""
    import os

    use_custom = checkbox.isSelected()
    if not use_custom:
        return False, None

    template = field.getText().strip()
    if not template:
        output_area.setText(
            "[!] {} custom command enabled but empty\n".format(tool_name)
        )
        output_area.append(
            "[*] Uncheck 'Enable Custom' or provide a command\n"
        )
        return True, None

    try:
        rendered_command = template.format(**context).strip()
    except KeyError as e:
        placeholder = str(e).strip("'\"")
        output_area.setText(
            "[!] {} custom command has unknown placeholder: {{{}}}\n".format(
                tool_name, placeholder
            )
        )
        output_area.append(
            "[*] Supported placeholders: {}\n".format(
                ", ".join(sorted(context.keys()))
            )
        )
        return True, None
    except Exception as e:
        output_area.setText(
            "[!] {} custom command template error: {}\n".format(tool_name, str(e))
        )
        return True, None

    if not rendered_command:
        output_area.setText(
            "[!] {} custom command became empty after formatting\n".format(tool_name)
        )
        return True, None

    # Custom command mode is intentionally strict: no shell control operators,
    # no command substitution, and token-level safe-character allow-list.
    is_safe, blocked_reason = self._validate_custom_command_safety(rendered_command)
    if not is_safe:
        output_area.setText(
            "[!] {} custom command blocked by safety policy\n".format(tool_name)
        )
        output_area.append("[!] Reason: {}\n".format(blocked_reason))
        output_area.append(
            "[*] Allowed: direct command tokens and simple pipelines only; chaining/redirection/subshell are blocked.\n"
        )
        output_area.append(
            "[*] If you need complex pipelines, run them manually outside extension custom mode.\n"
        )
        self.log_to_ui(
            "[!] {} custom command blocked by safety policy".format(tool_name)
        )
        return True, None

    try:
        shlex.split(rendered_command, posix=(os.name != "nt"))
    except Exception as e:
        output_area.setText(
            "[!] {} custom command is invalid: {}\n".format(tool_name, str(e))
        )
        return True, None

    self.log_to_ui(
        "[*] {} custom command enabled (trusted operator mode, strict safety checks active)".format(
            tool_name
        )
    )
    return True, rendered_command

def _validate_custom_command_safety(self, command_text):
    """Validate custom command text against strict shell-safety policy."""
    import os

    text = self._ascii_safe(command_text or "").strip()
    if not text:
        return False, "Command text is empty"

    forbidden_fragments = [
        "`",
        "$(",
        "${",
        "&&",
        "||",
        ";",
        ">",
        "<",
        "\n",
        "\r",
    ]
    for fragment in forbidden_fragments:
        if fragment in text:
            return False, "Forbidden shell fragment: {}".format(fragment)

    try:
        tokens = shlex.split(text, posix=(os.name != "nt"))
    except Exception as e:
        return False, "Unable to parse command tokens: {}".format(self._ascii_safe(e))

    if not tokens:
        return False, "No executable token found"
    if tokens[0] == "|" or tokens[-1] == "|":
        return False, "Pipeline separator cannot start or end command"
    for idx in range(1, len(tokens)):
        if tokens[idx] == "|" and tokens[idx - 1] == "|":
            return False, "Consecutive pipeline separators are not allowed"

    token_allow_pattern = re.compile(r"^[A-Za-z0-9_./:@%+=,?\\\- ()]+$")
    allowed_separator_tokens = set(["|"])
    for token in tokens:
        token_text = self._ascii_safe(token).strip()
        if not token_text:
            return False, "Command includes empty token"
        if token_text in allowed_separator_tokens:
            continue
        if not token_allow_pattern.match(token_text):
            return (
                False,
                "Token has unsupported characters: {}".format(token_text[:120]),
            )

    return True, ""

def _build_shell_command(self, command_text):
    """Build OS-aware shell command wrapper for custom command execution."""
    import os

    if os.name == "nt":
        return ["cmd", "/c", command_text]

    if os.path.exists("/bin/bash"):
        return ["/bin/bash", "-lc", command_text]
    if os.path.exists("/bin/sh"):
        return ["/bin/sh", "-lc", command_text]
    return ["sh", "-lc", command_text]

def _decode_process_data(self, data, context):
    """Decode subprocess output safely for Jython/Python compatibility."""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception as e:
        self._callbacks.printError("{} decode error: {}".format(context, str(e)))
        return str(data)

def _safe_pipe_read(self, pipe, context):
    """Read subprocess pipe safely and decode, tolerating already-closed streams."""
    if not pipe:
        return ""
    try:
        data = pipe.read()
    except (IOError, OSError, ValueError) as e:
        self._callbacks.printError("{} read error: {}".format(context, str(e)))
        return ""
    return self._decode_process_data(data, context)

def _ascii_safe(self, value, lower=False, max_len=None):
    """Return ASCII-safe text to prevent Unicode encode errors under Jython/Python2."""
    if value is None:
        text = ""
    else:
        text = value
    try:
        text_type = unicode  # noqa: F821 (Python2/Jython)
        if isinstance(text, text_type):
            normalized = text
        elif isinstance(text, str):
            try:
                normalized = text.decode("utf-8", errors="replace")
            except (AttributeError, TypeError, ValueError, UnicodeDecodeError):
                normalized = text_type(text)
        else:
            normalized = text_type(text)
        safe = normalized.encode("ascii", "backslashreplace")
    except NameError:
        # Python 3 path
        if isinstance(text, bytes):
            normalized = text.decode("utf-8", errors="replace")
        else:
            normalized = str(text)
        safe = normalized.encode("ascii", "backslashreplace").decode("ascii")
    except (TypeError, ValueError, UnicodeError):
        try:
            safe = repr(text)
        except (TypeError, ValueError):
            safe = "<unprintable>"

    if lower:
        safe = safe.lower()
    if max_len is not None and len(safe) > max_len:
        safe = safe[:max_len]
    return safe

def _probe_binary_help(self, binary_path, force_refresh=False):
    """Run lightweight binary help probes and cache result per path."""
    cache_key = "help::{}".format(binary_path)
    if force_refresh and cache_key in self._tool_help_cache:
        try:
            del self._tool_help_cache[cache_key]
        except Exception as cache_err:
            self._callbacks.printError(
                "Help probe cache refresh error ({}): {}".format(
                    binary_path, str(cache_err)
                )
            )
    if cache_key in self._tool_help_cache:
        return self._tool_help_cache[cache_key]

    import os
    import subprocess
    import tempfile
    import time as time_module

    best_output = ""
    last_error = None

    for help_flag in ["-h", "--help"]:
        cmd = [binary_path, help_flag]
        capture_path = None
        capture_handle = None
        process = None
        timed_out = False
        try:
            fd, capture_path = tempfile.mkstemp(
                prefix="burp_help_probe_", suffix=".log"
            )
            os.close(fd)
            capture_handle = open(capture_path, "wb")
            process = subprocess.Popen(
                cmd,
                stdout=capture_handle,
                stderr=subprocess.STDOUT,
                shell=False,
            )
        except Exception as e:
            last_error = str(e)
            if capture_handle:
                try:
                    capture_handle.close()
                except Exception as close_err:
                    self._callbacks.printError(
                        "Help probe file close error ({}): {}".format(
                            binary_path, str(close_err)
                        )
                    )
            if capture_path:
                try:
                    os.remove(capture_path)
                except Exception as rm_err:
                    self._callbacks.printError(
                        "Help probe file cleanup error ({}): {}".format(
                            binary_path, str(rm_err)
                        )
                    )
            continue

        timeout_seconds = 8
        started = time_module.time()
        while process.poll() is None:
            if time_module.time() - started > timeout_seconds:
                try:
                    process.kill()
                    process.wait()
                except Exception as kill_err:
                    self._callbacks.printError(
                        "Help probe kill error ({}): {}".format(
                            binary_path, str(kill_err)
                        )
                    )
                last_error = "timed out after {}s".format(timeout_seconds)
                timed_out = True
                break
            time_module.sleep(0.1)

        if capture_handle:
            try:
                capture_handle.close()
            except Exception as close_err:
                self._callbacks.printError(
                    "Help probe file close error ({}): {}".format(
                        binary_path, str(close_err)
                    )
                )

        combined = ""
        if capture_path:
            try:
                with open(capture_path, "rb") as reader:
                    combined_data = reader.read()
                combined = self._decode_process_data(
                    combined_data, "Help probe output ({})".format(binary_path)
                ).strip()
            except Exception as read_err:
                self._callbacks.printError(
                    "Help probe read error ({}): {}".format(
                        binary_path, str(read_err)
                    )
                )
            finally:
                try:
                    os.remove(capture_path)
                except Exception as rm_err:
                    self._callbacks.printError(
                        "Help probe file cleanup error ({}): {}".format(
                            binary_path, str(rm_err)
                        )
                    )

        if combined and len(combined) > len(best_output):
            best_output = combined

        help_markers = combined.lower()
        has_help_text = (
            "usage" in help_markers
            or "flags:" in help_markers
            or "options" in help_markers
        )
        if (not timed_out) and (process.returncode == 0 or has_help_text):
            result = (True, best_output or combined, None)
            self._tool_help_cache[cache_key] = result
            return result

        if not timed_out:
            last_error = "exit code {}".format(process.returncode)

    result = (False, best_output, last_error or "unable to execute command")
    self._tool_help_cache[cache_key] = result
    return result

def _validate_binary_signature(
    self,
    tool_name,
    binary_path,
    output_area,
    required_tokens=None,
    forbidden_tokens=None,
    fix_hint=None,
):
    """Validate local external binary signature/options before running scans."""
    required_tokens = required_tokens or []
    forbidden_tokens = forbidden_tokens or []

    probe_ok, help_text, probe_error = self._probe_binary_help(binary_path)
    if not probe_ok:
        output_area.setText(
            "[!] {} binary check failed: {}\n".format(tool_name, binary_path)
        )
        if probe_error:
            output_area.append("[!] {}\n".format(probe_error))
        if help_text:
            first_line = help_text.splitlines()[0] if help_text.splitlines() else ""
            if first_line:
                output_area.append("[!] Output: {}\n".format(first_line[:200]))
        if fix_hint:
            output_area.append("[*] {}\n".format(fix_hint))
        return False

    def _evaluate_signature(help_blob):
        help_blob_lower = (help_blob or "").lower()
        missing_local = [
            token for token in required_tokens if token.lower() not in help_blob_lower
        ]
        forbidden_local = [
            token for token in forbidden_tokens if token.lower() in help_blob_lower
        ]
        return missing_local, forbidden_local

    missing, forbidden = _evaluate_signature(help_text)

    # Self-heal stale/partial cached help output by forcing a fresh probe once.
    if required_tokens and missing and len(missing) == len(required_tokens):
        probe_ok_retry, help_text_retry, probe_error_retry = self._probe_binary_help(
            binary_path, force_refresh=True
        )
        if probe_ok_retry:
            help_text = help_text_retry
            missing, forbidden = _evaluate_signature(help_text)
        elif probe_error_retry:
            probe_error = probe_error_retry

    if missing or forbidden:
        output_area.setText(
            "[!] {} binary appears incompatible: {}\n".format(
                tool_name, binary_path
            )
        )
        if forbidden:
            output_area.append(
                "[!] Detected incompatible signature: {}\n".format(
                    ", ".join(forbidden)
                )
            )
        if missing:
            output_area.append(
                "[!] Missing expected options: {}\n".format(", ".join(missing))
            )
        if fix_hint:
            output_area.append("[*] {}\n".format(fix_hint))
        return False

    return True

def _tool_health_specs(self):
    """Return tool-health probe specifications for one-click diagnostics."""
    import os

    return [
        {
            "name": "Nuclei",
            "field": "nuclei_path_field",
            "fallback": [
                os.path.expanduser("~/go/bin/nuclei"),
                "nuclei",
            ],
            "required": ["-list", "-tags", "-etags", "-jsonl"],
            "forbidden": [],
        },
        {
            "name": "ApiHunter",
            "field": "apihunter_path_field",
            "fallback": [],
            "required": ["--urls", "--format", "--output", "--no-auto-report"],
            "forbidden": [],
        },
        {
            "name": "HTTPX",
            "field": "httpx_path_field",
            "fallback": [
                os.path.expanduser("~/go/bin/httpx"),
                "httpx",
            ],
            "required": ["-status-code", "-title"],
            "forbidden": [
                "a next generation http client",
                "usage: httpx <url> [options]",
            ],
        },
        {
            "name": "Katana",
            "field": "katana_path_field",
            "fallback": [
                os.path.expanduser("~/go/bin/katana"),
                "katana",
            ],
            "required": ["-list", "-d"],
            "forbidden": [],
        },
        {
            "name": "FFUF",
            "field": "ffuf_path_field",
            "fallback": [
                os.path.expanduser("~/go/bin/ffuf"),
                "ffuf",
            ],
            "required": ["-u", "-w"],
            "forbidden": [],
        },
        {
            "name": "SQLMap",
            "field": "sqlmap_path_field",
            "fallback": [
                os.path.expanduser("~/.local/bin/sqlmap"),
                "sqlmap",
            ],
            "required": ["-u", "--batch", "--level"],
            "forbidden": [],
        },
        {
            "name": "Dalfox",
            "field": "dalfox_path_field",
            "fallback": [
                os.path.expanduser("~/go/bin/dalfox"),
                "dalfox",
            ],
            "required": ["url", "--format", "-o"],
            "forbidden": [],
        },
        {
            "name": "Subfinder",
            "field": "asset_subfinder_path_field",
            "fallback": [
                os.path.expanduser("~/go/bin/subfinder"),
                "subfinder",
            ],
            "required": ["-d", "-silent"],
            "forbidden": [],
        },
    ]

def _resolve_tool_health_path(self, spec):
    """Resolve probe path from UI field first, then fallback candidates."""
    import os

    field_name = spec.get("field")
    if field_name and hasattr(self, field_name):
        try:
            field_obj = getattr(self, field_name)
            value = self._ascii_safe(field_obj.getText()).strip()
            if value:
                return value
        except Exception as e:
            self._callbacks.printError(
                "Tool health field read error ({}): {}".format(
                    spec.get("name", "unknown"), str(e)
                )
            )

    if self._ascii_safe(spec.get("name"), lower=True) == "apihunter":
        resolved = self._resolve_executable_from_path("apihunter", "")
        if resolved:
            return resolved

    for candidate in (spec.get("fallback") or []):
        safe_candidate = self._ascii_safe(candidate).strip()
        if safe_candidate:
            return safe_candidate
    return ""

def _resolve_executable_from_path(self, binary_name, configured_value):
    """Resolve executable to absolute path using process PATH + shell PATH probes."""
    import os
    import subprocess

    configured = self._ascii_safe(configured_value).strip()
    if configured:
        if os.path.isabs(configured) and os.path.isfile(configured) and os.access(
            configured, os.X_OK
        ):
            return configured
        if os.path.isfile(configured) and os.access(configured, os.X_OK):
            try:
                return os.path.abspath(configured)
            except Exception as resolve_err:
                self._callbacks.printError(
                    "Executable absolute-path resolve error ({}): {}".format(
                        configured, str(resolve_err)
                    )
                )
                return configured
        if os.sep in configured:
            return ""

    default_bin = self._ascii_safe(binary_name).strip()
    if not default_bin:
        return ""
    if os.name == "nt" and not default_bin.lower().endswith(".exe"):
        default_bin = default_bin + ".exe"

    for path_part in self._ascii_safe(os.environ.get("PATH") or "").split(os.pathsep):
        root = self._ascii_safe(path_part).strip()
        if not root:
            continue
        candidate = os.path.abspath(os.path.join(root, default_bin))
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    try:
        if os.name == "nt":
            probe_cmds = [["where", default_bin]]
        else:
            probe_cmds = [
                ["/bin/bash", "-lc", "command -v {} 2>/dev/null || true".format(default_bin)],
                ["/bin/bash", "-ic", "command -v {} 2>/dev/null || true".format(default_bin)],
            ]
        for probe_cmd in probe_cmds:
            probe = subprocess.Popen(
                probe_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_data, _ = probe.communicate()
            for raw_line in self._ascii_safe(stdout_data).splitlines():
                resolved = self._ascii_safe(raw_line).strip()
                if not resolved:
                    continue
                if os.path.isabs(resolved) and os.path.isfile(resolved) and os.access(
                    resolved, os.X_OK
                ):
                    return resolved
    except Exception as e:
        self._callbacks.printError(
            "{} PATH shell probe failed: {}".format(
                self._ascii_safe(binary_name), str(e)
            )
        )

    return ""

def _run_tool_health_check(self, event):
    """Run one-click health diagnostics for external tools."""
    self.log_to_ui("[*] Running Tool Health diagnostics...")

    def run_health():
        lines = []
        lines.append("=" * 80)
        lines.append("TOOL HEALTH CHECK")
        lines.append("=" * 80)
        lines.append(
            "[*] Timestamp: {}".format(
                SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())
            )
        )
        lines.append("")

        total = 0
        healthy = 0
        for spec in self._tool_health_specs():
            total += 1
            name = self._ascii_safe(spec.get("name") or "Unknown")
            path = self._resolve_tool_health_path(spec)
            lines.append("[*] {} | path={}".format(name, path or "<empty>"))
            if not path:
                lines.append("  [FAIL] missing path")
                continue

            probe_ok, help_text, probe_error = self._probe_binary_help(path)
            if not probe_ok:
                error_msg = self._ascii_safe(probe_error or "probe failed")
                lines.append("  [FAIL] {}".format(error_msg))
                continue

            check = self._evaluate_help_text(
                help_text or "",
                required_tokens=spec.get("required"),
                forbidden_tokens=spec.get("forbidden"),
            )
            if check.get("healthy"):
                healthy += 1
                lines.append("  [PASS] compatible")
            else:
                missing = check.get("missing") or []
                forbidden = check.get("forbidden_found") or []
                if missing:
                    lines.append("  [FAIL] missing options: {}".format(", ".join(missing)))
                if forbidden:
                    lines.append(
                        "  [FAIL] incompatible signature: {}".format(
                            ", ".join(forbidden)
                        )
                    )

        lines.append("")
        lines.append("[*] Healthy: {}/{}".format(healthy, total))
        lines.append("=" * 80)
        report = "\n".join(lines)

        SwingUtilities.invokeLater(lambda r=report: self.log_to_ui(r))

        def show_popup():
            text = JTextArea(report, 28, 120)
            text.setEditable(False)
            text.setLineWrap(False)
            text.setFont(Font("Monospaced", Font.PLAIN, 12))
            JOptionPane.showMessageDialog(
                self._panel,
                JScrollPane(text),
                "Tool Health",
                JOptionPane.INFORMATION_MESSAGE,
            )

        SwingUtilities.invokeLater(show_popup)

    worker = threading.Thread(target=run_health)
    worker.daemon = True
    worker.start()

def _extract_command_executables(self, command_text):
    """Extract executable tokens from simple shell command chains."""
    import os

    executables = []
    try:
        tokens = shlex.split(command_text, posix=(os.name != "nt"))
    except Exception as e:
        self._callbacks.printError(
            "Command executable parse error: {}".format(str(e))
        )
        return executables

    separators = set(["|", "||", "&&", ";"])
    expect_exec = True
    for token in tokens:
        if token in separators:
            expect_exec = True
            continue
        if not expect_exec:
            continue
        if "=" in token and "/" not in token:
            # Skip basic env assignments like KEY=value
            parts = token.split("=", 1)
            if len(parts) == 2 and parts[0]:
                continue
        executables.append(token)
        expect_exec = False

    return executables

def _validate_wayback_custom_command_tools(self, command_text, output_area):
    """Validate wayback custom command tools (gau/waybackurls) when present."""
    import os

    executables = self._extract_command_executables(command_text)
    checks = {
        "waybackurls": {
            "required": ["-dates", "-no-subs"],
            "forbidden": [],
            "hint": "Install waybackurls and ensure it is in PATH, or use full path in Custom Cmd.",
        },
        "gau": {
            "required": ["--subs", "--threads"],
            "forbidden": [],
            "hint": "Install gau and ensure it is in PATH, or use full path in Custom Cmd.",
        },
    }

    for executable in executables:
        name = os.path.basename(executable)
        if name not in checks:
            continue
        cfg = checks[name]
        if not self._validate_binary_signature(
            name,
            executable,
            output_area,
            required_tokens=cfg["required"],
            forbidden_tokens=cfg["forbidden"],
            fix_hint=cfg["hint"],
        ):
            return False

    return True

def _clear_tool_cancel(self, tool_key):
    """Clear cancellation event for a tool run."""
    event = self._tool_cancel_flags.get(tool_key)
    if event:
        event.clear()

def _set_tool_cancel(self, tool_key):
    """Set cancellation event for a tool run."""
    event = self._tool_cancel_flags.get(tool_key)
    if event:
        event.set()

def _is_tool_cancelled(self, tool_key):
    """Check whether user requested stop for a tool."""
    event = self._tool_cancel_flags.get(tool_key)
    return event.is_set() if event else False

def _set_active_tool_process(self, tool_key, process_obj):
    """Track currently running subprocess for a tool."""
    with self._tool_process_lock:
        self._active_tool_processes[tool_key] = process_obj

def _get_active_tool_process(self, tool_key):
    """Get currently running subprocess for a tool."""
    with self._tool_process_lock:
        return self._active_tool_processes.get(tool_key)

def _clear_active_tool_process(self, tool_key, process_obj=None):
    """Clear tracked subprocess for a tool, optionally by identity."""
    with self._tool_process_lock:
        current = self._active_tool_processes.get(tool_key)
        if current is None:
            return
        if process_obj is None or current is process_obj:
            self._active_tool_processes.pop(tool_key, None)

def _terminate_process_cross_platform(self, process_obj, tool_name):
    """Terminate process tree across Windows/macOS/Linux best-effort."""
    import os
    import subprocess
    import time as time_module

    if not process_obj:
        return True, "No running process"

    already_done = process_obj.poll() is not None
    if already_done:
        return True, "Process already finished"

    pid = getattr(process_obj, "pid", None)
    errors = []

    try:
        if pid:
            if os.name == "nt":
                kill_cmd = ["taskkill", "/PID", str(pid), "/T", "/F"]
                killer = subprocess.Popen(
                    kill_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                )
                killer.wait()
            else:
                # Kill children first, then parent (best-effort).
                for kill_cmd in [
                    ["pkill", "-TERM", "-P", str(pid)],
                    ["kill", "-TERM", str(pid)],
                ]:
                    killer = subprocess.Popen(
                        kill_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,
                    )
                    killer.wait()
    except Exception as e:
        errors.append("OS-level stop error: {}".format(str(e)))

    try:
        process_obj.terminate()
    except Exception as e:
        errors.append("terminate() error: {}".format(str(e)))

    wait_start = time_module.time()
    while process_obj.poll() is None and (time_module.time() - wait_start) < 3:
        time_module.sleep(0.1)

    if process_obj.poll() is None:
        try:
            process_obj.kill()
        except Exception as e:
            errors.append("kill() error: {}".format(str(e)))

    stopped = process_obj.poll() is not None
    if stopped:
        return True, "Stopped {}".format(tool_name)

    if errors:
        return False, " | ".join(errors)
    return False, "Process still running"

def _stop_tool_run(self, tool_key, tool_name, output_area):
    """Stop active external tool run with cross-platform kill behavior."""
    self._set_tool_cancel(tool_key)

    process_obj = self._get_active_tool_process(tool_key)
    if not process_obj:
        output_area.append(
            "[*] Stop requested for {} (no active subprocess detected)\n".format(
                tool_name
            )
        )
        self.log_to_ui("[*] Stop requested for {}".format(tool_name))
        return

    stopped, message = self._terminate_process_cross_platform(process_obj, tool_name)
    self._clear_active_tool_process(tool_key, process_obj)
    if stopped:
        output_area.append("[!] {} stop requested by user\n".format(tool_name))
        self.log_to_ui("[!] {} stopped by user".format(tool_name))
    else:
        output_area.append("[!] Failed to stop {}: {}\n".format(tool_name, message))
        self.log_to_ui("[!] {} stop failed: {}".format(tool_name, message))

def _pkill_external_tools(self, output_area=None):
    """Emergency stop: kill all scanner tools and orphan processes by name."""
    import os
    import platform
    import subprocess

    tool_specs = [
        ("apihunter", "ApiHunter"),
        ("nuclei", "Nuclei"),
        ("httpx", "HTTPX"),
        ("katana", "Katana"),
        ("ffuf", "FFUF"),
        ("wayback", "Wayback"),
        ("sqlmap", "SQLMap"),
        ("dalfox", "Dalfox"),
        ("assetdiscovery", "Subfinder"),
        ("graphqlanalysis", "GraphQL"),
    ]

    lines = [
        "[!] Emergency kill requested for external tools",
        "[*] Platform: {}".format(platform.system() or os.name),
    ]

    # Stop tracked processes first.
    for tool_key, tool_name in tool_specs:
        self._set_tool_cancel(tool_key)
        process_obj = self._get_active_tool_process(tool_key)
        if not process_obj:
            continue
        stopped, message = self._terminate_process_cross_platform(process_obj, tool_name)
        self._clear_active_tool_process(tool_key, process_obj)
        if stopped:
            lines.append("[+] {}: stopped tracked process".format(tool_name))
        else:
            lines.append("[!] {}: {}".format(tool_name, message))

    # Sweep orphan processes by executable pattern.
    if os.name == "nt":
        kill_names = [
            "apihunter.exe",
            "nuclei.exe",
            "httpx.exe",
            "katana.exe",
            "ffuf.exe",
            "waybackurls.exe",
            "gau.exe",
            "sqlmap.exe",
            "dalfox.exe",
            "subfinder.exe",
        ]
        for name in kill_names:
            try:
                process = subprocess.Popen(
                    ["taskkill", "/IM", name, "/F", "/T"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                )
                process.wait()
            except Exception as e:
                lines.append("[!] taskkill {} failed: {}".format(name, str(e)))
    else:
        kill_patterns = [
            "apihunter",
            "nuclei",
            "httpx",
            "katana",
            "ffuf",
            "waybackurls",
            "gau",
            "sqlmap",
            "dalfox",
            "subfinder",
        ]
        for pattern in kill_patterns:
            try:
                process = subprocess.Popen(
                    ["pkill", "-TERM", "-f", pattern],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                )
                process.wait()
            except OSError as e:
                # Fallback for minimal systems lacking pkill.
                try:
                    process = subprocess.Popen(
                        ["killall", "-q", pattern],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,
                    )
                    process.wait()
                    lines.append("[*] killall fallback used for {}".format(pattern))
                except Exception as fallback_err:
                    lines.append(
                        "[!] pkill/killall {} failed: {} | {}".format(
                            pattern, str(e), str(fallback_err)
                        )
                    )
            except Exception as e:
                lines.append("[!] pkill {} failed: {}".format(pattern, str(e)))

    summary = "\n".join(lines) + "\n"
    if output_area is not None:
        output_area.append(summary)
    self.log_to_ui(
        "[!] Emergency kill executed for apihunter/nuclei/httpx/katana/ffuf/wayback/sqlmap/dalfox/subfinder/graphql"
    )

def _stop_apihunter(self, event):
    self._stop_tool_run("apihunter", "ApiHunter", self.apihunter_area)

def _stop_nuclei(self, event):
    self._stop_tool_run("nuclei", "Nuclei", self.nuclei_area)

def _stop_httpx(self, event):
    self._stop_tool_run("httpx", "HTTPX", self.httpx_area)

def _stop_katana(self, event):
    self._stop_tool_run("katana", "Katana", self.katana_area)

def _stop_ffuf(self, event):
    self._stop_tool_run("ffuf", "FFUF", self.ffuf_area)

def _stop_wayback(self, event):
    self._stop_tool_run("wayback", "Wayback", self.wayback_area)

def _stop_sqlmap(self, event):
    self._stop_tool_run("sqlmap", "SQLMap", self.sqlmap_area)

def _stop_dalfox(self, event):
    self._stop_tool_run("dalfox", "Dalfox", self.dalfox_area)

__all__ = [
    "_extract_body",
    "_truncate_body_text_by_max_size",
    "_get_content_type",
    "_detect_auth",
    "_extract_jwt",
    "_detect_encryption",
    "_analyze_param_patterns",
    "_detect_api_patterns",
    "export_api_data",
    "_merge_params",
    "_format_sample",
    "_summarize_param_types",
    "_analyze_structure",
    "_check_endpoints",
    "_add_observation",
    "_analyze_security",
    "_generate_llm_prompt",
    "_get_export_dir",
    "clear_data",
    "_auto_tag",
    "_get_severity",
    "_get_recon_entry_tool",
    "_entry_matches_recon_regex",
    "_endpoint_matches_recon_regex",
    "_sync_noise_filter_checkboxes",
    "_has_high_signal_tags",
    "_recon_entry_is_noise",
    "_endpoint_is_recon_noise",
    "_logger_extract_tag_tokens",
    "_logger_event_is_noise",
    "_filter_endpoints",
    "_on_filter_change",
    "_persist_recon_filter_library",
    "_restore_recon_filter_library",
    "_refresh_recon_filter_library_combo",
    "_save_recon_filter",
    "_apply_recon_filter",
    "_remove_recon_filter",
    "_clear_recon_filters",
    "_on_group_change",
    "_on_refresh",
    "_prev_page",
    "_next_page",
    "_change_page_size",
    "refresh_view",
    "_group_endpoints",
    "_update_tab_title",
    "_update_stats",
    "_update_host_filter",
    "_update_tool_filter",
    "_update_tag_filter",
    "_schedule_capture_ui_refresh",
    "_run_capture_ui_refresh",
    "_logger_apply_runtime_settings",
    "_show_logger_help_popup",
    "_show_logger_capacity_help_popup",
    "_logger_trim_if_needed",
    "_logger_effective_preview_caps",
    "_logger_effective_header_preview_limit",
    "_sync_recon_entry_from_logger",
    "_logger_capture_event",
    "_logger_count_default_request_markers",
    "_logger_count_default_response_markers",
    "_schedule_logger_ui_refresh",
    "_run_logger_ui_refresh",
    "_refresh_logger_tool_filter",
    "_logger_event_in_scope",
    "_logger_count_regex_matches",
    "_run_logger_regex_search",
    "_logger_collect_grep_popup_matches",
    "_open_logger_grep_popup",
    "_reset_logger_regex_search",
    "_persist_logger_filter_library",
    "_restore_logger_filter_library",
    "_persist_logger_tag_rules",
    "_restore_logger_tag_rules",
    "_restore_logger_popup_persistence",
    "_refresh_logger_filter_library_combo",
    "_save_logger_filter",
    "_apply_logger_filter",
    "_remove_logger_filter",
    "_clear_logger_filters",
    "_logger_hex_to_color",
    "_logger_color_to_hex",
    "_logger_pick_color",
    "_logger_suggest_tag_palette",
    "_logger_builtin_tag_rules",
    "_ensure_logger_default_tag_rules",
    "_logger_preview_rule_matches",
    "_open_logger_tag_rules_popup",
    "_compile_logger_tag_rules",
    "_logger_rule_scope_text",
    "_logger_apply_tag_rules",
    "_logger_event_matches_filters",
    "_refresh_logger_view",
    "_logger_show_selected",
    "_logger_selected_indices",
    "_logger_select_all_rows",
    "_logger_event_full_url",
    "_entry_full_url",
    "_shell_single_quote",
    "_build_entry_request_text",
    "_build_entry_curl_command",
    "_build_ai_request_analysis_prompt",
    "_build_ai_request_export",
    "_logger_copy_selected_rows",
    "_resolve_recon_endpoint_key",
    "_show_recon_missing_detail_message",
    "_recon_show_selected_in_logger",
    "_logger_show_endpoint_detail",
    "_logger_send_selected_to_ai",
    "_logger_send_selected_to_repeater",
    "_clear_logger_logs",
    "_export_logger_view",
    "_recon_backfill_history",
    "_logger_backfill_history",
    "_open_target_base_scope_popup",
    "_sanitize_apihunter_custom_target_line",
    "_parse_apihunter_custom_targets_text",
    "_open_apihunter_custom_targets_popup",
    "_get_apihunter_custom_targets_override",
    "_parse_target_base_scope_text",
    "_extract_scope_host",
    "_get_target_scope_override",
    "_host_matches_target_scope",
    "export_by_host",
    "_select_export_scope_data",
    "_split_path_segments",
    "_parse_query_pairs",
    "_build_entry_url",
    "_build_postman_collection",
    "_build_insomnia_export",
    "_export_postman_collection",
    "_export_insomnia_collection",
    "_show_text_dialog",
    "_show_ai_copy_exit_dialog",
    "_collect_recon_grep_targets",
    "_run_recon_grep",
    "_iter_recon_param_items",
    "_tokenize_recon_words",
    "_collect_hidden_param_candidates",
    "_score_hidden_param_candidate",
    "_run_recon_hidden_params_for_scope",
    "_run_recon_hidden_params",
    "_run_recon_hidden_params_selected",
    "_param_risk_hint",
    "_collect_recon_param_intelligence",
    "_build_recon_param_intel_report",
    "_run_recon_param_intel",
    "_export_recon_param_intel",
    "_safe_export_name",
    "_build_recon_turbo_request_template",
    "_build_recon_turbo_manifest",
    "_build_recon_turbo_basic_script",
    "_build_recon_turbo_race_script",
    "_build_recon_turbo_pack_from_data",
    "_export_recon_turbo_pack",
    "_export_recon_turbo_pack_selected",
    "_sync_logger_from_recon_snapshot",
    "_int_or_default",
    "_current_import_sample_limit",
    "_normalize_header_dict",
    "_extract_content_type_from_headers",
    "_parse_url_parts_from_text",
    "_derive_import_auth_methods",
    "_extract_param_map_from_har_request",
    "_build_cookie_header_for_host",
    "_coerce_import_entry_shape",
    "_build_suite_export_snapshot",
    "_build_har_snapshot",
    "_build_replay_studio_snapshot",
    "_merge_import_snapshots",
    "_identify_import_payload_kind",
    "_discover_excalibur_sidecar_paths",
    "_load_json_file_for_import",
    "_build_excalibur_bridge_snapshot",
    "_resolve_import_payload",
    "_merge_import_snapshot_into_recon",
    "_run_excalibur_auto_pipeline",
    "import_data",
    "_entry_to_excalibur_bridge_capture",
    "_build_excalibur_bridge_bundle",
    "_export_data",
    "_openapi_schema_from_inferred_type",
    "_build_openapi_spec_from_capture",
    "_generate_openapi_from_capture",
    "_analyze_structure_for",
    "_analyze_security_for",
    "show_endpoint_details",
    "createMenuItems",
    "_send_to_recon",
    "_send_to_repeater",
    "_send_endpoint_to_repeater",
    "_send_endpoint_to_ai",
    "_build_url",
    "_export_urls_to_file",
    "_run_tool_async",
    "_process_file_results",
    "_export_httpx_urls",
    "_clean_url",
    "_cleanup_temp_dir",
    "_resolve_custom_command",
    "_build_shell_command",
    "_decode_process_data",
    "_safe_pipe_read",
    "_ascii_safe",
    "_probe_binary_help",
    "_validate_binary_signature",
    "_tool_health_specs",
    "_resolve_tool_health_path",
    "_resolve_executable_from_path",
    "_run_tool_health_check",
    "_extract_command_executables",
    "_validate_wayback_custom_command_tools",
    "_clear_tool_cancel",
    "_set_tool_cancel",
    "_is_tool_cancelled",
    "_set_active_tool_process",
    "_get_active_tool_process",
    "_clear_active_tool_process",
    "_terminate_process_cross_platform",
    "_stop_tool_run",
    "_pkill_external_tools",
    "_stop_apihunter",
    "_stop_nuclei",
    "_stop_httpx",
    "_stop_katana",
    "_stop_ffuf",
    "_stop_wayback",
    "_stop_sqlmap",
    "_stop_dalfox",
]
