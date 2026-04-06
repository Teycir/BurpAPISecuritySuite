# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Scoreless counterfactual differential analysis (passive-only, non-destructive)."""

import json
import re
import threading
import time

from javax.swing import SwingUtilities


_SENSITIVE_FIELD_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "session",
    "cookie",
    "ssn",
    "social",
    "iban",
    "card",
    "cvv",
    "salary",
    "balance",
    "credit",
    "debit",
    "bank",
    "account_number",
    "private",
)

_IDENTIFIER_TOKENS = (
    "id",
    "user_id",
    "account_id",
    "owner_id",
    "tenant_id",
    "organization_id",
    "org_id",
    "project_id",
    "customer_id",
    "subject",
    "sub",
)


def _counterfactual_request_format(self, entry):
    """Infer request representation class for differential invariants."""
    method = self._ascii_safe((entry or {}).get("method") or "GET").strip().upper() or "GET"
    body_text = self._ascii_safe((entry or {}).get("request_body") or "").strip()
    path_text = self._ascii_safe(
        (entry or {}).get("normalized_path") or (entry or {}).get("path") or "/",
        lower=True,
    )
    content_type = self._ascii_safe((entry or {}).get("content_type") or "", lower=True).strip()
    headers = dict((entry or {}).get("headers") or {})
    if (not content_type) and headers:
        for raw_key, raw_value in headers.items():
            key = self._ascii_safe(raw_key, lower=True).strip()
            if key == "content-type":
                content_type = self._ascii_safe(raw_value, lower=True).strip()
                break

    if method in ["GET", "HEAD", "OPTIONS"] and not body_text:
        return "no_body"
    if "/graphql" in path_text and ("json" in content_type or body_text.startswith("{")):
        return "graphql_json"
    if "json" in content_type:
        return "json"
    if "x-www-form-urlencoded" in content_type:
        return "form_urlencoded"
    if "multipart/form-data" in content_type:
        return "multipart"
    if "xml" in content_type or "soap" in content_type:
        return "xml"
    if body_text.startswith("{") or body_text.startswith("["):
        return "json_like"
    if "=" in body_text and "&" in body_text:
        return "form_like"
    if body_text:
        return "raw_body"
    return "unknown"


def _counterfactual_auth_context(self, entry):
    """Return normalized auth context fingerprint."""
    if hasattr(self, "_passive_auth_fingerprint"):
        try:
            return self._ascii_safe(self._passive_auth_fingerprint(entry), lower=True)
        except Exception as e:
            self._callbacks.printError(
                "Counterfactual auth fingerprint fallback error: {}".format(
                    self._ascii_safe(e)
                )
            )
    auth_detected = [(self._ascii_safe(x, lower=True)).strip() for x in ((entry or {}).get("auth_detected") or [])]
    auth_detected = [x for x in auth_detected if x]
    if auth_detected:
        return ",".join(sorted(list(set(auth_detected)))[:4])
    return "none"


def _counterfactual_is_weak_context(self, auth_context):
    """Treat anonymous/guest-like contexts as weak authorization contexts."""
    text = self._ascii_safe(auth_context or "", lower=True).strip()
    if not text:
        return True
    weak_tokens = ["none", "guest", "anonymous", "unauth", "public", "noauth"]
    return any(token in text for token in weak_tokens)


def _counterfactual_status_code(self, entry):
    try:
        return int((entry or {}).get("response_status", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _counterfactual_is_success(self, status_code):
    value = int(status_code or 0)
    return 200 <= value < 400


def _counterfactual_add_param_value(self, container, source_name, param_name, raw_value):
    source = self._ascii_safe(source_name, lower=True).strip() or "unknown"
    name = self._ascii_safe(param_name, lower=True).strip()
    if not name:
        return
    values_by_source = container.setdefault(name, {})
    slot = values_by_source.setdefault(source, set())

    if isinstance(raw_value, list):
        for item in raw_value:
            slot.add(self._ascii_safe(item))
        return
    if isinstance(raw_value, dict):
        try:
            slot.add(json.dumps(raw_value, sort_keys=True))
        except Exception as e:
            self._callbacks.printError(
                "Counterfactual param dict serialize warning: {}".format(
                    self._ascii_safe(e)
                )
            )
            slot.add(self._ascii_safe(raw_value))
        return
    slot.add(self._ascii_safe(raw_value))


def _counterfactual_param_source_values(self, entry):
    """Flatten parameter names into source->value map for precedence checks."""
    out = {}
    params = (entry or {}).get("parameters", {}) or {}
    if not isinstance(params, dict):
        return out

    for source_name, source_values in params.items():
        if isinstance(source_values, dict):
            for param_name, raw_value in source_values.items():
                self._counterfactual_add_param_value(
                    out, source_name, param_name, raw_value
                )
            continue
        if isinstance(source_values, list):
            for param_name in source_values:
                self._counterfactual_add_param_value(
                    out, source_name, param_name, "<present>"
                )
            continue
    return out


def _counterfactual_collect_json_paths(self, value, out_paths, prefix="", depth=0):
    """Collect dotted JSON keys up to a safe depth for sensitive field drift checks."""
    if depth > 6:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            safe_key = self._ascii_safe(key).strip()
            if not safe_key:
                continue
            dotted = "{}.{}".format(prefix, safe_key) if prefix else safe_key
            out_paths.add(dotted)
            self._counterfactual_collect_json_paths(
                child, out_paths, prefix=dotted, depth=depth + 1
            )
        return
    if isinstance(value, list):
        for item in value[:20]:
            self._counterfactual_collect_json_paths(
                item, out_paths, prefix=prefix, depth=depth + 1
            )


def _counterfactual_extract_sensitive_fields(self, entry):
    """Extract likely sensitive JSON field paths from response payload."""
    body_text = self._ascii_safe((entry or {}).get("response_body") or "")
    if not body_text:
        return []

    parsed = None
    if hasattr(self, "_parse_json_loose"):
        parsed = self._parse_json_loose(body_text)
    if parsed is None:
        looks_json = False
        trimmed = body_text.lstrip()
        if trimmed.startswith("{") or trimmed.startswith("["):
            looks_json = True
        if looks_json:
            try:
                parsed = json.loads(body_text)
            except Exception as parse_err:
                if getattr(self, "_callbacks", None) is not None:
                    self._callbacks.printError(
                        "Counterfactual JSON parse error: {}".format(
                            self._ascii_safe(parse_err)
                        )
                    )
                else:
                    raise

    candidate_paths = set()
    if parsed is not None:
        self._counterfactual_collect_json_paths(parsed, candidate_paths, prefix="", depth=0)
    else:
        # Non-JSON fallback: still capture key-like sensitive hints when present.
        for match in re.findall(r'"([A-Za-z0-9_\\-]{2,64})"\s*:', body_text):
            candidate_paths.add(self._ascii_safe(match))

    sensitive = []
    for path in sorted(list(candidate_paths)):
        lower = self._ascii_safe(path, lower=True)
        if any(token in lower for token in _SENSITIVE_FIELD_TOKENS):
            sensitive.append(path)
    return sensitive[:60]


def _counterfactual_add_finding(
    self,
    findings,
    invariant_name,
    title,
    severity,
    endpoint_key,
    evidence_lines,
    suggested_checks,
):
    findings.append(
        {
            "id": "cdf-{0:03d}".format(len(findings) + 1),
            "category": "COUNTERFACTUAL",
            "invariant": self._ascii_safe(invariant_name),
            "title": self._ascii_safe(title),
            "severity": self._ascii_safe(severity, lower=True),
            "endpoint_scope": [self._ascii_safe(endpoint_key)],
            "evidence": [
                self._ascii_safe(x) for x in list(evidence_lines or [])[:12]
                if self._ascii_safe(x).strip()
            ],
            "suggested_checks": [
                self._ascii_safe(x) for x in list(suggested_checks or [])[:8]
                if self._ascii_safe(x).strip()
            ],
            "non_destructive": True,
            "no_scoring": True,
        }
    )


def _counterfactual_is_identifier_param(self, param_name):
    text = self._ascii_safe(param_name or "", lower=True).strip()
    if not text:
        return False
    if text in _IDENTIFIER_TOKENS:
        return True
    return bool(re.search(r"(^|_|\\.)id$", text))


def _build_counterfactual_differential_package(self, data_snapshot):
    """Build deterministic, scoreless differential findings from passive snapshot."""
    endpoint_rows = {}
    for endpoint_key, entries in (data_snapshot or {}).items():
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            if not isinstance(entry, dict):
                continue
            endpoint = self._ascii_safe(endpoint_key)
            rows = endpoint_rows.setdefault(endpoint, [])
            status_code = self._counterfactual_status_code(entry)
            auth_context = self._counterfactual_auth_context(entry)
            rows.append(
                {
                    "entry": entry,
                    "request_format": self._counterfactual_request_format(entry),
                    "auth_context": auth_context,
                    "is_weak_auth": self._counterfactual_is_weak_context(auth_context),
                    "status_code": status_code,
                    "is_success": self._counterfactual_is_success(status_code),
                    "param_values": self._counterfactual_param_source_values(entry),
                    "sensitive_fields": self._counterfactual_extract_sensitive_fields(entry),
                }
            )

    findings = []
    for endpoint_key in sorted(endpoint_rows.keys()):
        rows = endpoint_rows.get(endpoint_key, [])
        if len(rows) < 2:
            continue

        # Invariant A: auth checks should be representation-invariant.
        format_stats = {}
        for row in rows:
            fmt = self._ascii_safe(row.get("request_format") or "unknown", lower=True)
            slot = format_stats.setdefault(
                fmt,
                {
                    "sample_count": 0,
                    "weak_success": False,
                    "strong_success": False,
                    "status_codes": set(),
                },
            )
            slot["sample_count"] += 1
            status_code = int(row.get("status_code", 0) or 0)
            if status_code:
                slot["status_codes"].add(status_code)
            if bool(row.get("is_success")):
                if bool(row.get("is_weak_auth")):
                    slot["weak_success"] = True
                else:
                    slot["strong_success"] = True

        if len(format_stats.keys()) >= 2:
            weak_open_formats = []
            protected_formats = []
            for fmt, slot in format_stats.items():
                if slot.get("weak_success"):
                    weak_open_formats.append(fmt)
                if (not slot.get("weak_success")) and slot.get("strong_success"):
                    protected_formats.append(fmt)
            if weak_open_formats and protected_formats:
                evidence = []
                for fmt, slot in sorted(format_stats.items()):
                    status_text = ",".join(
                        [self._ascii_safe(x) for x in sorted(list(slot.get("status_codes", set())))[:6]]
                    )
                    evidence.append(
                        "format={} samples={} weak_success={} strong_success={} statuses={}".format(
                            fmt,
                            int(slot.get("sample_count", 0) or 0),
                            bool(slot.get("weak_success")),
                            bool(slot.get("strong_success")),
                            status_text or "n/a",
                        )
                    )
                self._counterfactual_add_finding(
                    findings,
                    "authorization_must_be_representation_invariant",
                    "Auth enforcement appears to differ by request representation",
                    "high",
                    endpoint_key,
                    evidence,
                    [
                        "Replay identical business request in JSON, form, and multipart with the same weak auth context.",
                        "Verify one representation does not bypass checks enforced in another representation.",
                    ],
                )

        # Invariant B: identifier source precedence must not be ambiguous.
        conflict_samples = []
        weak_conflict_seen = False
        for row in rows:
            if not bool(row.get("is_success")):
                continue
            param_values = dict(row.get("param_values") or {})
            for param_name, source_values in param_values.items():
                if not self._counterfactual_is_identifier_param(param_name):
                    continue
                if not isinstance(source_values, dict):
                    continue
                if len(source_values.keys()) < 2:
                    continue
                flattened = set()
                for values in source_values.values():
                    for item in list(values or []):
                        value_text = self._ascii_safe(item).strip()
                        if value_text:
                            flattened.add(value_text)
                if len(flattened) < 2:
                    continue
                if bool(row.get("is_weak_auth")):
                    weak_conflict_seen = True
                source_fragments = []
                for source_name in sorted(source_values.keys()):
                    values_sorted = sorted(
                        [self._ascii_safe(x) for x in list(source_values.get(source_name, set()))]
                    )
                    source_fragments.append(
                        "{}={}".format(source_name, ",".join(values_sorted[:2]))
                    )
                conflict_samples.append(
                    "param={} {}".format(
                        self._ascii_safe(param_name), " | ".join(source_fragments[:4])
                    )
                )
                if len(conflict_samples) >= 6:
                    break
            if len(conflict_samples) >= 6:
                break
        if conflict_samples:
            self._counterfactual_add_finding(
                findings,
                "identifier_resolution_must_not_depend_on_source_precedence",
                "Conflicting identifier values from multiple sources reached successful responses",
                "critical" if weak_conflict_seen else "high",
                endpoint_key,
                conflict_samples,
                [
                    "Replay path/query/body identifier conflicts and verify server rejects ambiguous combinations.",
                    "Document and enforce one canonical identifier source with strict mismatch rejection.",
                ],
            )

        # Invariant C: weak-context sensitive field exposure should not exceed protected context.
        weak_sensitive = set()
        strong_sensitive = set()
        for row in rows:
            if not bool(row.get("is_success")):
                continue
            fields = set([self._ascii_safe(x) for x in (row.get("sensitive_fields") or [])])
            if not fields:
                continue
            if bool(row.get("is_weak_auth")):
                weak_sensitive |= fields
            else:
                strong_sensitive |= fields
        if weak_sensitive:
            leaked_only_to_weak = sorted(list(weak_sensitive - strong_sensitive))
            if (not strong_sensitive) or leaked_only_to_weak:
                evidence = []
                evidence.append(
                    "weak_sensitive_count={} strong_sensitive_count={}".format(
                        len(weak_sensitive), len(strong_sensitive)
                    )
                )
                if leaked_only_to_weak:
                    evidence.append(
                        "weak_only_fields={}".format(
                            ", ".join([self._ascii_safe(x) for x in leaked_only_to_weak[:8]])
                        )
                    )
                self._counterfactual_add_finding(
                    findings,
                    "sensitive_response_redaction_must_be_auth_monotonic",
                    "Weak-auth responses expose sensitive fields not seen in stronger contexts",
                    "high",
                    endpoint_key,
                    evidence,
                    [
                        "Replay same object read across guest/user/admin and diff field-level redaction.",
                        "Fail closed on weak contexts and verify serializer redaction parity per role.",
                    ],
                )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings.sort(
        key=lambda item: (
            severity_order.get(self._ascii_safe(item.get("severity"), lower=True), 4),
            self._ascii_safe(item.get("invariant"), lower=True),
            self._ascii_safe((item.get("endpoint_scope") or [""])[0], lower=True),
        )
    )

    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    invariant_distribution = {}
    for item in findings:
        sev = self._ascii_safe(item.get("severity"), lower=True)
        if sev not in severity_distribution:
            sev = "info"
        severity_distribution[sev] += 1
        inv = self._ascii_safe(item.get("invariant"))
        invariant_distribution[inv] = invariant_distribution.get(inv, 0) + 1

    return {
        "schema_version": "1.0",
        "generated_at": self._ascii_safe(time.strftime("%Y-%m-%d %H:%M:%S")),
        "analysis_type": "counterfactual_differentials",
        "no_scoring": True,
        "non_destructive": True,
        "finding_count": len(findings),
        "findings": findings,
        "summary": {
            "severity_distribution": severity_distribution,
            "invariant_distribution": invariant_distribution,
            "analyst_guidance": [
                "These are invariant breaks based on captured behavior differentials, not payload signatures.",
                "Prioritize endpoints where weak contexts differ by representation or identifier precedence.",
                "Replay checks should remain non-destructive unless explicit test authorization is provided.",
            ],
        },
    }


def _sort_and_store_counterfactual_payload(
    self,
    package,
    source_label="passive",
    scope_label="Filtered Scope",
    target_count=None,
):
    """Persist scoreless differential findings for UI/export/AI surfaces."""
    findings = list((package or {}).get("findings", []) or [])
    summary = dict((package or {}).get("summary", {}) or {})
    generated_at = self._ascii_safe(
        (package or {}).get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")
    )
    count_value = (
        int(target_count) if isinstance(target_count, int) and target_count >= 0 else None
    )
    with self.counterfactual_lock:
        self.counterfactual_findings = findings
        self.counterfactual_summary = summary
        self.counterfactual_meta = {
            "generated_at": generated_at,
            "source": self._ascii_safe(source_label),
            "scope": self._ascii_safe(scope_label),
            "target_count": count_value,
            "finding_count": len(findings),
            "analysis_type": "counterfactual_differentials",
            "no_scoring": True,
            "non_destructive": True,
        }
    self._refresh_recon_invariant_status_label_async()


def _format_counterfactual_output(self, package, scanned_count, total_available, scope_label):
    """Format scoreless differential findings for Passive tab output."""
    findings = list((package or {}).get("findings", []) or [])
    summary = dict((package or {}).get("summary", {}) or {})
    severity_distribution = dict(summary.get("severity_distribution", {}) or {})
    invariant_distribution = dict(summary.get("invariant_distribution", {}) or {})

    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("COUNTERFACTUAL DIFFERENTIAL RESULTS (NON-DESTRUCTIVE, NO SCORING)")
    lines.append("=" * 80)
    lines.append("[*] Scope: {}".format(self._ascii_safe(scope_label)))
    lines.append("[*] Endpoints Scanned: {} (of {})".format(scanned_count, total_available))
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(severity_distribution.get("critical", 0) or 0),
            int(severity_distribution.get("high", 0) or 0),
            int(severity_distribution.get("medium", 0) or 0),
            int(severity_distribution.get("info", 0) or 0),
        )
    )
    lines.append("[*] Invariants Triggered: {}".format(len(invariant_distribution)))
    lines.append("[*] Mode: Deterministic evidence (no confidence score ranking)")
    lines.append("")

    if not findings:
        lines.append("[+] No counterfactual differential breaks flagged in current scope.")
        lines.append("[*] Capture more multi-format and multi-auth traffic, then rerun.")
        return "\n".join(lines) + "\n"

    lines.append("TOP FINDINGS")
    lines.append("-" * 80)
    for finding in findings[:120]:
        severity = self._ascii_safe(finding.get("severity", "info"), lower=True).upper()
        title = self._ascii_safe(finding.get("title", ""))
        invariant = self._ascii_safe(finding.get("invariant", ""))
        endpoint = self._ascii_safe((finding.get("endpoint_scope") or [""])[0])
        lines.append("[{}] {}".format(severity, title))
        lines.append("  Invariant: {}".format(invariant))
        lines.append("  Endpoint: {}".format(endpoint))
        evidence = list(finding.get("evidence", []) or [])
        for item in evidence[:3]:
            lines.append("  Evidence: {}".format(self._ascii_safe(item)))
        suggested = list(finding.get("suggested_checks", []) or [])
        if suggested:
            lines.append("  Next: {}".format(self._ascii_safe(suggested[0])))
        lines.append("")

    if len(findings) > 120:
        lines.append("[*] {} more findings not shown".format(len(findings) - 120))
    lines.append("")
    lines.append("[*] Use 'Export Ledger' for differential JSON artifacts.")
    return "\n".join(lines) + "\n"


def _run_counterfactual_differentials(self, event):
    """Run passive-only counterfactual differential invariants."""
    context = None
    if hasattr(self, "_resolve_passive_scope_targets"):
        context = self._resolve_passive_scope_targets()
    if not context:
        return

    scope = context.get("scope")
    endpoint_keys = list(context.get("endpoint_keys") or [])
    total_available = int(context.get("total_available", 0) or 0)

    self.passive_area.setText(
        "[*] Starting counterfactual differential analysis (non-destructive, no scoring)...\n"
    )
    self.passive_area.append(
        "[*] Scope: {} | Targets: {} of {}\n\n".format(
            self._ascii_safe(scope), len(endpoint_keys), total_available
        )
    )

    def run_worker():
        try:
            snapshot = self._collect_passive_snapshot(endpoint_keys)
            package = self._build_counterfactual_differential_package(snapshot)
            self._sort_and_store_counterfactual_payload(
                package,
                source_label="counterfactual_run",
                scope_label=scope,
                target_count=len(snapshot),
            )
            text = self._format_counterfactual_output(
                package, len(snapshot), total_available, scope
            )
            finding_count = int(package.get("finding_count", 0) or 0)
            SwingUtilities.invokeLater(lambda t=text: self.passive_area.setText(t))
            SwingUtilities.invokeLater(
                lambda c=finding_count: self.log_to_ui(
                    "[+] Counterfactual differential complete (findings={})".format(c)
                )
            )
        except Exception as e:
            err_msg = self._ascii_safe(e)
            if getattr(self, "_callbacks", None) is not None:
                try:
                    import traceback

                    self._callbacks.printError(
                        "Counterfactual differential traceback:\n{}".format(
                            self._ascii_safe(traceback.format_exc())
                        )
                    )
                except Exception as trace_err:
                    self._callbacks.printError(
                        "Counterfactual traceback logging error: {}".format(
                            self._ascii_safe(trace_err)
                        )
                    )
            err_text = "[!] Counterfactual differential analysis failed: {}\n".format(
                err_msg
            )
            SwingUtilities.invokeLater(lambda t=err_text: self.passive_area.append(t))
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui(
                    "[!] Counterfactual differential error: {}".format(m)
                )
            )

    worker = threading.Thread(target=run_worker)
    worker.daemon = True
    worker.start()


__all__ = [
    "_counterfactual_request_format",
    "_counterfactual_auth_context",
    "_counterfactual_is_weak_context",
    "_counterfactual_status_code",
    "_counterfactual_is_success",
    "_counterfactual_add_param_value",
    "_counterfactual_param_source_values",
    "_counterfactual_collect_json_paths",
    "_counterfactual_extract_sensitive_fields",
    "_counterfactual_add_finding",
    "_counterfactual_is_identifier_param",
    "_build_counterfactual_differential_package",
    "_sort_and_store_counterfactual_payload",
    "_format_counterfactual_output",
    "_run_counterfactual_differentials",
]
