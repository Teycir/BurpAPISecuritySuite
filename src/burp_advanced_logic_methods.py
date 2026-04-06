# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Advanced deep-logic analytics: abuse chains, proof packets, guardrails, and role deltas."""
import re
import threading
import time

from javax.swing import SwingUtilities


def _normalize_endpoint_key(self, endpoint_key, entry):
    method = self._ascii_safe((entry or {}).get("method") or "").strip().upper()
    path = self._ascii_safe((entry or {}).get("normalized_path") or "").strip()
    if not path:
        path = self._normalize_path(self._ascii_safe((entry or {}).get("path") or "/"))
    if not method:
        endpoint_text = self._ascii_safe(endpoint_key)
        if ":" in endpoint_text:
            method = self._ascii_safe(endpoint_text.split(":", 1)[0]).strip().upper()
    if not method:
        method = "GET"
    return "{}:{}".format(method, path or "/")


def _flatten_snapshot_entries(self, data_snapshot):
    rows = []
    for endpoint_key, entries in (data_snapshot or {}).items():
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            if not isinstance(entry, dict):
                continue
            key = self._normalize_endpoint_key(endpoint_key, entry)
            host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
            method = self._ascii_safe(entry.get("method") or "GET").strip().upper() or "GET"
            path = self._ascii_safe(entry.get("normalized_path") or entry.get("path") or "/").strip()
            if not path.startswith("/"):
                path = "/" + path
            rows.append(
                {
                    "endpoint_key": key,
                    "host": host,
                    "method": method,
                    "path": path,
                    "entry": entry,
                }
            )
    return rows


def _entry_has_auth(self, entry):
    auth_values = [self._ascii_safe(x, lower=True) for x in ((entry or {}).get("auth_detected") or [])]
    if not auth_values:
        return False
    return any(x not in ["none", ""] for x in auth_values)


def _resource_hint_from_path(self, path_text):
    path = self._ascii_safe(path_text or "/", lower=True).strip()
    if not path:
        return "root"
    segments = [seg for seg in path.split("/") if seg]
    kept = []
    for seg in segments:
        if re.match(r"^v\d+(?:\.\d+)?$", seg):
            continue
        if seg in ["api", "rest", "graphql"]:
            continue
        if seg.startswith("{") and seg.endswith("}"):
            continue
        if re.match(r"^[0-9]+$", seg):
            continue
        kept.append(seg)
        if len(kept) >= 2:
            break
    if kept:
        return "/".join(kept)
    if segments:
        return segments[0]
    return "root"


def _is_auth_surface(self, method_text, path_text):
    method = self._ascii_safe(method_text or "", lower=True).strip().upper()
    path = self._ascii_safe(path_text or "", lower=True)
    if any(marker in path for marker in ["/login", "/auth", "/token", "/session", "/oauth", "/signin"]):
        return True
    if method in ["POST"] and any(marker in path for marker in ["/verify", "/mfa", "/refresh"]):
        return True
    return False


def _is_object_access_surface(self, path_text):
    path = self._ascii_safe(path_text or "", lower=True)
    if "{id}" in path or "{uuid}" in path or "{objectid}" in path:
        return True
    if re.search(r"/[0-9]+(?:/|$)", path):
        return True
    if re.search(r"/[0-9a-f]{24}(?:/|$)", path):
        return True
    if any(marker in path for marker in ["/user/", "/account/", "/order/", "/invoice/", "/profile/"]):
        return True
    return False


def _is_state_change_surface(self, method_text, path_text):
    method = self._ascii_safe(method_text or "", lower=True).strip().upper()
    path = self._ascii_safe(path_text or "", lower=True)
    if method in ["POST", "PUT", "PATCH", "DELETE"]:
        return True
    return any(
        marker in path
        for marker in [
            "/approve",
            "/reject",
            "/activate",
            "/disable",
            "/cancel",
            "/transfer",
            "/withdraw",
            "/refund",
            "/checkout",
            "/purchase",
            "/role",
            "/permission",
        ]
    )


def _score_to_label(self, score):
    value = float(score or 0.0)
    if value >= 0.85:
        return "high"
    if value >= 0.60:
        return "medium"
    return "low"


def _severity_from_score(self, score):
    value = float(score or 0.0)
    if value >= 0.90:
        return "critical"
    if value >= 0.72:
        return "high"
    if value >= 0.45:
        return "medium"
    return "info"


def _build_simple_ledger(self, findings):
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    confidence_distribution = {"high": 0, "medium": 0, "low": 0}
    for finding in list(findings or []):
        sev = self._ascii_safe(finding.get("severity") or "info", lower=True)
        if sev not in severity_distribution:
            sev = "info"
        severity_distribution[sev] += 1
        label = self._ascii_safe(finding.get("confidence_label") or "low", lower=True)
        if label not in confidence_distribution:
            label = "low"
        confidence_distribution[label] += 1
    return {
        "analysis_type": "advanced_logic",
        "severity_distribution": severity_distribution,
        "confidence_distribution": confidence_distribution,
        "finding_count": len(findings or []),
    }


def _build_abuse_chain_package(self, data_snapshot):
    rows = self._flatten_snapshot_entries(data_snapshot)
    route_map = {}
    for row in rows:
        key = row["endpoint_key"]
        if key not in route_map:
            route_map[key] = row
    nodes = list(route_map.values())

    auth_nodes = [n for n in nodes if self._is_auth_surface(n["method"], n["path"])]
    object_nodes = [n for n in nodes if self._is_object_access_surface(n["path"])]
    state_nodes = [n for n in nodes if self._is_state_change_surface(n["method"], n["path"])]

    findings = []
    seen_chain_ids = set()
    for state_node in state_nodes:
        state_resource = self._resource_hint_from_path(state_node.get("path"))
        state_host = self._ascii_safe(state_node.get("host"), lower=True)
        candidate_objects = []
        for obj_node in object_nodes:
            object_host = self._ascii_safe(obj_node.get("host"), lower=True)
            if state_host and object_host and state_host != object_host:
                continue
            object_resource = self._resource_hint_from_path(obj_node.get("path"))
            if state_resource == object_resource:
                candidate_objects.append(obj_node)
        if not candidate_objects:
            continue

        object_node = candidate_objects[0]
        object_resource = self._resource_hint_from_path(object_node.get("path"))
        candidate_auth = []
        for auth_node in auth_nodes:
            auth_host = self._ascii_safe(auth_node.get("host"), lower=True)
            if state_host and auth_host and state_host != auth_host:
                continue
            candidate_auth.append(auth_node)
        auth_node = candidate_auth[0] if candidate_auth else None

        chain_key = "|".join(
            [
                self._ascii_safe(auth_node.get("endpoint_key") if auth_node else "SESSION"),
                self._ascii_safe(object_node.get("endpoint_key")),
                self._ascii_safe(state_node.get("endpoint_key")),
            ]
        )
        if chain_key in seen_chain_ids:
            continue
        seen_chain_ids.add(chain_key)

        score = 0.45
        if auth_node is not None:
            score += 0.15
        if self._is_object_access_surface(object_node.get("path")):
            score += 0.15
        if self._is_state_change_surface(state_node.get("method"), state_node.get("path")):
            score += 0.15
        if state_resource == object_resource and state_resource not in ["", "root"]:
            score += 0.10
        if not self._entry_has_auth(object_node.get("entry")):
            score += 0.08
        if not self._entry_has_auth(state_node.get("entry")):
            score += 0.08
        if self._ascii_safe(state_node.get("method"), lower=True).strip().upper() in [
            "POST",
            "PATCH",
            "DELETE",
        ]:
            score += 0.08
        if score > 0.99:
            score = 0.99

        confidence_label = self._score_to_label(score)
        severity = self._severity_from_score(score)
        title = "Potential abuse chain to state change on {}".format(state_resource)
        invariant = "Auth -> object access -> state mutation reachable path"
        evidence = [
            "Auth surface: {}".format(
                self._ascii_safe(auth_node.get("endpoint_key")) if auth_node else "existing session token"
            ),
            "Object access: {}".format(self._ascii_safe(object_node.get("endpoint_key"))),
            "State mutation: {}".format(self._ascii_safe(state_node.get("endpoint_key"))),
        ]
        chain_steps = [
            {
                "stage": "auth",
                "endpoint": self._ascii_safe(auth_node.get("endpoint_key")) if auth_node else "SESSION_TOKEN",
                "reason": "obtain or reuse authenticated context",
            },
            {
                "stage": "object_access",
                "endpoint": self._ascii_safe(object_node.get("endpoint_key")),
                "reason": "access object-level resource candidate",
            },
            {
                "stage": "state_change",
                "endpoint": self._ascii_safe(state_node.get("endpoint_key")),
                "reason": "perform write/transition operation",
            },
        ]
        findings.append(
            {
                "title": title,
                "severity": severity,
                "confidence_score": round(score, 3),
                "confidence_label": confidence_label,
                "invariant": invariant,
                "resource": state_resource,
                "endpoint_scope": [
                    chain_steps[1]["endpoint"],
                    chain_steps[2]["endpoint"],
                ],
                "chain_steps": chain_steps,
                "evidence": evidence,
                "suggested_checks": [
                    "Replay chain with guest/user/admin tokens and compare enforcement at each step."
                ],
            }
        )

    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
            self._ascii_safe(item.get("resource"), lower=True),
        )
    )
    ledger = self._build_simple_ledger(findings)
    ledger["analysis_type"] = "abuse_chain_builder"
    return {
        "generated_at": self._ascii_safe(time.strftime("%Y-%m-%d %H:%M:%S")),
        "finding_count": len(findings),
        "findings": findings,
        "ledger": ledger,
    }


def _collect_strong_findings_for_proof_mode(self, packages_map):
    strong = []
    for source_key, package in (packages_map or {}).items():
        findings = list((package or {}).get("findings", []) or [])
        for finding in findings:
            score = float(finding.get("confidence_score", 0.0) or 0.0)
            severity = self._ascii_safe(finding.get("severity"), lower=True)
            if score >= 0.72 or severity in ["critical", "high"]:
                item = dict(finding)
                item["_source"] = self._ascii_safe(source_key)
                strong.append(item)
    strong.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
        )
    )
    return strong[:20]


def _redact_header_for_packet(self, key, value):
    name = self._ascii_safe(key)
    lower_name = self._ascii_safe(key, lower=True)
    raw = self._ascii_safe(value)
    if any(marker in lower_name for marker in ["authorization", "cookie", "token", "api-key", "apikey"]):
        return name, "<redacted>"
    return name, raw


def _packet_from_entry(self, endpoint_key, entry, step_index):
    protocol = self._ascii_safe(entry.get("protocol") or "https", lower=True).strip() or "https"
    host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
    port = int(entry.get("port", 0) or 0)
    path = self._ascii_safe(entry.get("path") or entry.get("normalized_path") or "/").strip()
    if not path.startswith("/"):
        path = "/" + path
    query = self._ascii_safe(entry.get("query_string") or "").strip()
    if (protocol == "https" and port in [0, 443]) or (protocol == "http" and port in [0, 80]):
        base_url = "{}://{}{}".format(protocol, host, path)
    else:
        base_url = "{}://{}:{}{}".format(protocol, host, port, path)
    url = "{}?{}".format(base_url, query) if query else base_url

    header_lines = []
    headers = dict(entry.get("headers") or {})
    for name, value in list(headers.items())[:12]:
        clean_name, clean_value = self._redact_header_for_packet(name, value)
        header_lines.append("{}: {}".format(clean_name, clean_value))

    body_text = self._ascii_safe(entry.get("request_body") or "")
    if len(body_text) > 600:
        body_text = body_text[:600] + "... [truncated]"

    return {
        "step": int(step_index),
        "endpoint": self._ascii_safe(endpoint_key),
        "method": self._ascii_safe(entry.get("method") or "GET").upper(),
        "url": url,
        "headers": header_lines,
        "body": body_text,
    }


def _build_proof_mode_packet_sets(
    self,
    data_snapshot,
    sequence_package=None,
    golden_package=None,
    state_package=None,
    abuse_chain_package=None,
):
    route_entry_map = {}
    for row in self._flatten_snapshot_entries(data_snapshot):
        key = row["endpoint_key"]
        if key not in route_entry_map:
            route_entry_map[key] = row.get("entry") or {}

    source_packages = {
        "sequence_invariants": sequence_package or {},
        "golden_tickets": golden_package or {},
        "state_transitions": state_package or {},
        "abuse_chains": abuse_chain_package or {},
    }
    strong_findings = self._collect_strong_findings_for_proof_mode(source_packages)
    packet_sets = []

    for idx, finding in enumerate(strong_findings):
        endpoint_scope = list(finding.get("endpoint_scope", []) or [])
        if not endpoint_scope:
            continue
        packets = []
        step = 1
        for endpoint_key in endpoint_scope[:3]:
            entry = route_entry_map.get(self._ascii_safe(endpoint_key))
            if not entry:
                continue
            packets.append(self._packet_from_entry(endpoint_key, entry, step))
            step += 1
        if not packets:
            continue
        score = float(finding.get("confidence_score", 0.0) or 0.0)
        packet_sets.append(
            {
                "id": "proof-{:03d}".format(idx + 1),
                "source_analysis": self._ascii_safe(finding.get("_source") or "advanced"),
                "title": self._ascii_safe(finding.get("title") or "Proof packet set"),
                "severity": self._ascii_safe(finding.get("severity") or "info"),
                "confidence_score": round(score, 3),
                "expected_vulnerable_signals": [
                    "low-priv role returns same/similar status/body as high-priv flow",
                    "state-changing request succeeds without stricter auth enforcement",
                ],
                "expected_safe_signals": [
                    "401/403/404 for low-priv step where high-priv succeeds",
                    "state transition blocked for unauthorized role",
                ],
                "packets": packets,
            }
        )

    return {
        "generated_at": self._ascii_safe(time.strftime("%Y-%m-%d %H:%M:%S")),
        "source_finding_count": len(strong_findings),
        "packet_set_count": len(packet_sets),
        "packet_sets": packet_sets,
    }


def _build_spec_guardrail_package(self, data_snapshot, state_package=None):
    route_entries = {}
    for row in self._flatten_snapshot_entries(data_snapshot):
        key = row["endpoint_key"]
        route_entries.setdefault(key, []).append(row.get("entry") or {})

    rules = []
    violations = []
    state_findings = list((state_package or {}).get("findings", []) or [])
    state_high_resources = set()
    for finding in state_findings:
        resource = self._ascii_safe(finding.get("resource") or "", lower=True).strip()
        if resource:
            state_high_resources.add(resource)

    for endpoint_key, entries in route_entries.items():
        total = len(entries)
        if total <= 0:
            continue
        auth_count = 0
        status_classes = set()
        param_presence = {}
        method = self._ascii_safe(endpoint_key.split(":", 1)[0]).strip().upper() if ":" in endpoint_key else "GET"
        path = self._ascii_safe(endpoint_key.split(":", 1)[1] if ":" in endpoint_key else endpoint_key, lower=True)
        resource_hint = self._resource_hint_from_path(path)
        for entry in entries:
            if self._entry_has_auth(entry):
                auth_count += 1
            try:
                status = int(entry.get("response_status", 0) or 0)
            except (TypeError, ValueError):
                status = 0
            if status > 0:
                status_classes.add(int(status / 100))
            names = self._extract_param_names(entry)
            for name in names:
                token = self._ascii_safe(name).strip()
                if token:
                    param_presence[token] = param_presence.get(token, 0) + 1

        required_auth = auth_count >= max(1, int(total * 0.6))
        required_params = sorted(
            [
                name
                for name, count in param_presence.items()
                if count >= max(1, int(total * 0.8))
            ]
        )[:20]
        rule = {
            "endpoint": endpoint_key,
            "required_auth": bool(required_auth),
            "allowed_status_classes": sorted([int(x) for x in status_classes]),
            "required_params": required_params,
            "resource_hint": resource_hint,
            "state_sensitive_resource": bool(resource_hint in state_high_resources),
        }
        rules.append(rule)

        for entry in entries:
            current_has_auth = self._entry_has_auth(entry)
            if required_auth and (not current_has_auth):
                score = 0.84
                violations.append(
                    {
                        "title": "Auth requirement drift",
                        "severity": self._severity_from_score(score),
                        "confidence_score": round(score, 3),
                        "confidence_label": self._score_to_label(score),
                        "invariant": "Endpoint should require auth based on observed baseline",
                        "resource": resource_hint,
                        "endpoint_scope": [endpoint_key],
                        "evidence": [
                            "Baseline auth ratio {} / {}".format(auth_count, total),
                            "Current sample has no detected auth markers",
                        ],
                        "suggested_checks": [
                            "Replay with guest/user/admin and verify unauthorized access is blocked."
                        ],
                    }
                )
            entry_params = set([self._ascii_safe(x) for x in self._extract_param_names(entry)])
            missing = [name for name in required_params if name not in entry_params]
            if missing:
                score = 0.61
                violations.append(
                    {
                        "title": "Required parameter drift",
                        "severity": self._severity_from_score(score),
                        "confidence_score": round(score, 3),
                        "confidence_label": self._score_to_label(score),
                        "invariant": "Observed required params missing from new sample",
                        "resource": resource_hint,
                        "endpoint_scope": [endpoint_key],
                        "evidence": [
                            "Missing params: {}".format(", ".join(missing[:6])),
                            "Required baseline params: {}".format(", ".join(required_params[:6])),
                        ],
                        "suggested_checks": [
                            "Validate server rejects requests missing required business/auth parameters."
                        ],
                    }
                )
            if method == "GET" and self._is_state_change_surface(method, path):
                score = 0.76
                violations.append(
                    {
                        "title": "Unsafe state transition method",
                        "severity": self._severity_from_score(score),
                        "confidence_score": round(score, 3),
                        "confidence_label": self._score_to_label(score),
                        "invariant": "State-changing action exposed on GET route",
                        "resource": resource_hint,
                        "endpoint_scope": [endpoint_key],
                        "evidence": [
                            "GET method with state/action-like path",
                            "Path: {}".format(path),
                        ],
                        "suggested_checks": [
                            "Require POST/PUT/PATCH with CSRF/auth controls for state mutations."
                        ],
                    }
                )

    violations.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
            self._ascii_safe(item.get("resource"), lower=True),
        )
    )
    ledger = self._build_simple_ledger(violations)
    ledger["analysis_type"] = "spec_guardrails_from_reality"
    return {
        "generated_at": self._ascii_safe(time.strftime("%Y-%m-%d %H:%M:%S")),
        "rule_count": len(rules),
        "violation_count": len(violations),
        "rules": rules,
        "violations": violations,
        "ledger": ledger,
    }


def _infer_role_label_from_entry(self, entry):
    headers = dict((entry or {}).get("headers") or {})
    for raw_key, raw_value in headers.items():
        key = self._ascii_safe(raw_key, lower=True).strip()
        if key in ["x-role", "x-user-role", "x-auth-role", "role"]:
            value = self._ascii_safe(raw_value, lower=True).strip()
            if value:
                return value

    jwt_obj = (entry or {}).get("jwt_detected")
    if isinstance(jwt_obj, dict):
        payload = jwt_obj.get("payload")
        if isinstance(payload, dict):
            role = payload.get("role")
            roles = payload.get("roles")
            if role:
                return self._ascii_safe(role, lower=True).strip()
            if isinstance(roles, list) and roles:
                return self._ascii_safe(roles[0], lower=True).strip()

    if self._entry_has_auth(entry):
        return "authenticated"
    return "guest"


def _role_rank(self, role_label):
    role = self._ascii_safe(role_label, lower=True).strip()
    mapping = {
        "unauth": 0,
        "guest": 0,
        "anonymous": 0,
        "authenticated": 1,
        "member": 1,
        "user": 2,
        "operator": 3,
        "manager": 3,
        "admin": 4,
        "root": 5,
        "superadmin": 5,
    }
    return int(mapping.get(role, 1))


def _build_role_delta_package(self, data_snapshot):
    route_role = {}
    for row in self._flatten_snapshot_entries(data_snapshot):
        endpoint_key = row["endpoint_key"]
        entry = row["entry"] or {}
        role = self._infer_role_label_from_entry(entry)
        bucket = route_role.setdefault(endpoint_key, {})
        bucket.setdefault(role, []).append(entry)

    findings = []
    for endpoint_key, by_role in route_role.items():
        if len(by_role.keys()) < 2:
            continue
        sorted_roles = sorted(by_role.keys(), key=lambda role: self._role_rank(role))
        high_role = sorted_roles[-1]
        high_rank = self._role_rank(high_role)
        high_entries = by_role.get(high_role, [])
        if not high_entries:
            continue

        def _summ(entries):
            statuses = []
            lengths = []
            for entry in entries:
                try:
                    statuses.append(int(entry.get("response_status", 0) or 0))
                except (TypeError, ValueError):
                    statuses.append(0)
                try:
                    lengths.append(int(entry.get("response_length", 0) or 0))
                except (TypeError, ValueError):
                    lengths.append(0)
            if not statuses:
                return {"success_rate": 0.0, "avg_len": 0.0, "status_set": set()}
            success = len([s for s in statuses if s >= 200 and s < 400])
            avg_len = float(sum(lengths)) / float(len(lengths))
            return {
                "success_rate": float(success) / float(len(statuses)),
                "avg_len": avg_len,
                "status_set": set(statuses),
            }

        high_summary = _summ(high_entries)
        for low_role in sorted_roles[:-1]:
            low_rank = self._role_rank(low_role)
            if low_rank >= high_rank:
                continue
            low_entries = by_role.get(low_role, [])
            if not low_entries:
                continue
            low_summary = _summ(low_entries)
            if high_summary["success_rate"] <= 0.0:
                continue

            success_ratio = 0.0
            if high_summary["success_rate"] > 0:
                success_ratio = low_summary["success_rate"] / high_summary["success_rate"]
            len_ratio = 0.0
            if high_summary["avg_len"] > 0:
                len_ratio = low_summary["avg_len"] / high_summary["avg_len"]
            overlap = len(list(low_summary["status_set"].intersection(high_summary["status_set"])))
            overlap_ratio = float(overlap) / float(max(1, len(high_summary["status_set"])))

            score = 0.25
            score += min(0.45, max(0.0, success_ratio) * 0.45)
            score += min(0.20, max(0.0, len_ratio) * 0.20)
            score += min(0.20, max(0.0, overlap_ratio) * 0.20)
            if low_role in ["guest", "unauth", "anonymous"]:
                score += 0.10
            if score > 0.99:
                score = 0.99

            if score < 0.65:
                continue
            findings.append(
                {
                    "title": "Role delta suspicious parity: {} vs {}".format(low_role, high_role),
                    "severity": self._severity_from_score(score),
                    "confidence_score": round(score, 3),
                    "confidence_label": self._score_to_label(score),
                    "invariant": "Low-priv role resembles high-priv behavior",
                    "resource": self._resource_hint_from_path(endpoint_key.split(":", 1)[1] if ":" in endpoint_key else endpoint_key),
                    "endpoint_scope": [endpoint_key],
                    "low_role": self._ascii_safe(low_role),
                    "high_role": self._ascii_safe(high_role),
                    "evidence": [
                        "Success ratio low/high: {:.2f}".format(success_ratio),
                        "Length ratio low/high: {:.2f}".format(len_ratio),
                        "Status overlap ratio: {:.2f}".format(overlap_ratio),
                    ],
                    "suggested_checks": [
                        "Replay with guest/user/admin and compare object-level authorization and redaction behavior."
                    ],
                }
            )

    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
        )
    )
    ledger = self._build_simple_ledger(findings)
    ledger["analysis_type"] = "role_delta_engine"
    return {
        "generated_at": self._ascii_safe(time.strftime("%Y-%m-%d %H:%M:%S")),
        "finding_count": len(findings),
        "findings": findings,
        "ledger": ledger,
    }


def _build_advanced_logic_packages(
    self,
    data_snapshot,
    sequence_package=None,
    golden_package=None,
    state_package=None,
):
    abuse_chains = self._build_abuse_chain_package(data_snapshot)
    proof_mode = self._build_proof_mode_packet_sets(
        data_snapshot,
        sequence_package=sequence_package,
        golden_package=golden_package,
        state_package=state_package,
        abuse_chain_package=abuse_chains,
    )
    spec_guardrails = self._build_spec_guardrail_package(
        data_snapshot, state_package=state_package
    )
    role_delta = self._build_role_delta_package(data_snapshot)
    return {
        "abuse_chains": abuse_chains,
        "proof_mode": proof_mode,
        "spec_guardrails": spec_guardrails,
        "role_delta": role_delta,
    }


def _store_advanced_logic_packages(
    self,
    packages_map,
    source_label="passive_run",
    scope_label="Filtered Scope",
    target_count=None,
):
    timestamp = self._ascii_safe(time.strftime("%Y-%m-%d %H:%M:%S"))
    count_value = int(target_count) if isinstance(target_count, int) and target_count >= 0 else None
    with self.advanced_logic_lock:
        self.advanced_logic_packages = {
            "generated_at": timestamp,
            "source": self._ascii_safe(source_label),
            "scope": self._ascii_safe(scope_label),
            "target_count": count_value,
            "abuse_chains": dict((packages_map or {}).get("abuse_chains", {}) or {}),
            "proof_mode": dict((packages_map or {}).get("proof_mode", {}) or {}),
            "spec_guardrails": dict((packages_map or {}).get("spec_guardrails", {}) or {}),
            "role_delta": dict((packages_map or {}).get("role_delta", {}) or {}),
        }


def _format_abuse_chain_output(self, package):
    findings = list((package or {}).get("findings", []) or [])
    ledger = dict((package or {}).get("ledger", {}) or {})
    sev = dict(ledger.get("severity_distribution", {}) or {})
    conf = dict(ledger.get("confidence_distribution", {}) or {})
    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("ABUSE CHAIN BUILDER (GRAPH TO REPLAY)")
    lines.append("=" * 80)
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(sev.get("critical", 0) or 0),
            int(sev.get("high", 0) or 0),
            int(sev.get("medium", 0) or 0),
            int(sev.get("info", 0) or 0),
        )
    )
    lines.append(
        "[*] Confidence: High={} Medium={} Low={}".format(
            int(conf.get("high", 0) or 0),
            int(conf.get("medium", 0) or 0),
            int(conf.get("low", 0) or 0),
        )
    )
    lines.append("")
    if not findings:
        lines.append("[+] No high-signal abuse chains found in current scope.")
        return "\n".join(lines) + "\n"
    lines.append("TOP CHAINS")
    lines.append("-" * 80)
    for finding in findings[:30]:
        sev_label = self._ascii_safe(finding.get("severity", "info"), lower=True).upper()
        conf_score = float(finding.get("confidence_score", 0.0) or 0.0)
        conf_label = self._ascii_safe(finding.get("confidence_label", ""))
        lines.append(
            "[{}][{} {:.2f}] {}".format(
                sev_label,
                conf_label.upper(),
                conf_score,
                self._ascii_safe(finding.get("title")),
            )
        )
        for step in list(finding.get("chain_steps", []) or [])[:3]:
            lines.append(
                "  {} -> {}".format(
                    self._ascii_safe(step.get("stage"), lower=True).upper(),
                    self._ascii_safe(step.get("endpoint")),
                )
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_proof_mode_output(self, package):
    packet_sets = list((package or {}).get("packet_sets", []) or [])
    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("PROOF MODE (AUTO-POC PACKET SET)")
    lines.append("=" * 80)
    lines.append("[*] Source Findings Considered: {}".format(int((package or {}).get("source_finding_count", 0) or 0)))
    lines.append("[*] Packet Sets: {}".format(len(packet_sets)))
    lines.append("")
    if not packet_sets:
        lines.append("[+] No strong findings available for packet-set generation.")
        return "\n".join(lines) + "\n"
    lines.append("TOP PACKET SETS")
    lines.append("-" * 80)
    for item in packet_sets[:20]:
        lines.append(
            "[{}][{:.2f}] {} ({})".format(
                self._ascii_safe(item.get("severity"), lower=True).upper(),
                float(item.get("confidence_score", 0.0) or 0.0),
                self._ascii_safe(item.get("title")),
                self._ascii_safe(item.get("source_analysis")),
            )
        )
        for packet in list(item.get("packets", []) or [])[:3]:
            lines.append(
                "  Step {}: {} {}".format(
                    int(packet.get("step", 0) or 0),
                    self._ascii_safe(packet.get("method")),
                    self._ascii_safe(packet.get("endpoint")),
                )
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_spec_guardrail_output(self, package):
    rules = list((package or {}).get("rules", []) or [])
    violations = list((package or {}).get("violations", []) or [])
    ledger = dict((package or {}).get("ledger", {}) or {})
    sev = dict(ledger.get("severity_distribution", {}) or {})
    conf = dict(ledger.get("confidence_distribution", {}) or {})
    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("SPEC GUARDRAILS FROM REALITY")
    lines.append("=" * 80)
    lines.append("[*] Derived Rules: {}".format(len(rules)))
    lines.append("[*] Violations: {}".format(len(violations)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(sev.get("critical", 0) or 0),
            int(sev.get("high", 0) or 0),
            int(sev.get("medium", 0) or 0),
            int(sev.get("info", 0) or 0),
        )
    )
    lines.append(
        "[*] Confidence: High={} Medium={} Low={}".format(
            int(conf.get("high", 0) or 0),
            int(conf.get("medium", 0) or 0),
            int(conf.get("low", 0) or 0),
        )
    )
    lines.append("")
    if not violations:
        lines.append("[+] No guardrail violations found for current snapshot baseline.")
        return "\n".join(lines) + "\n"
    lines.append("TOP VIOLATIONS")
    lines.append("-" * 80)
    for finding in violations[:40]:
        lines.append(
            "[{}][{:.2f}] {} | {}".format(
                self._ascii_safe(finding.get("severity"), lower=True).upper(),
                float(finding.get("confidence_score", 0.0) or 0.0),
                self._ascii_safe(finding.get("title")),
                self._ascii_safe((finding.get("endpoint_scope") or [""])[0]),
            )
        )
        evidence = list(finding.get("evidence", []) or [])
        if evidence:
            lines.append("  Evidence: {}".format(self._ascii_safe(evidence[0])))
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_role_delta_output(self, package):
    findings = list((package or {}).get("findings", []) or [])
    ledger = dict((package or {}).get("ledger", {}) or {})
    sev = dict(ledger.get("severity_distribution", {}) or {})
    conf = dict(ledger.get("confidence_distribution", {}) or {})
    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("ROLE DELTA ENGINE")
    lines.append("=" * 80)
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(sev.get("critical", 0) or 0),
            int(sev.get("high", 0) or 0),
            int(sev.get("medium", 0) or 0),
            int(sev.get("info", 0) or 0),
        )
    )
    lines.append(
        "[*] Confidence: High={} Medium={} Low={}".format(
            int(conf.get("high", 0) or 0),
            int(conf.get("medium", 0) or 0),
            int(conf.get("low", 0) or 0),
        )
    )
    lines.append("")
    if not findings:
        lines.append("[+] No suspicious role deltas detected in current scope.")
        return "\n".join(lines) + "\n"
    lines.append("TOP ROLE DELTAS")
    lines.append("-" * 80)
    for finding in findings[:40]:
        lines.append(
            "[{}][{:.2f}] {} -> {} | {}".format(
                self._ascii_safe(finding.get("severity"), lower=True).upper(),
                float(finding.get("confidence_score", 0.0) or 0.0),
                self._ascii_safe(finding.get("low_role")),
                self._ascii_safe(finding.get("high_role")),
                self._ascii_safe((finding.get("endpoint_scope") or [""])[0]),
            )
        )
        evidence = list(finding.get("evidence", []) or [])
        if evidence:
            lines.append("  Evidence: {}".format(self._ascii_safe(evidence[0])))
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_advanced_logic_output(self, packages_map, mode="all"):
    mode_key = self._ascii_safe(mode or "all", lower=True)
    parts = []
    if mode_key in ["all", "abuse", "abuse_chains"]:
        parts.append(self._format_abuse_chain_output((packages_map or {}).get("abuse_chains", {})))
    if mode_key in ["all", "proof", "proof_mode"]:
        parts.append(self._format_proof_mode_output((packages_map or {}).get("proof_mode", {})))
    if mode_key in ["all", "spec", "guardrails", "spec_guardrails"]:
        parts.append(self._format_spec_guardrail_output((packages_map or {}).get("spec_guardrails", {})))
    if mode_key in ["all", "role", "role_delta"]:
        parts.append(self._format_role_delta_output((packages_map or {}).get("role_delta", {})))
    return "".join(parts)


def _resolve_passive_scope_targets(self):
    if not self.api_data:
        self.passive_area.setText("[!] No endpoints in Recon tab. Capture or import first\n")
        return None
    max_text = self.passive_max_field.getText().strip() or "250"
    try:
        max_count = int(max_text)
        if max_count < 1:
            max_count = 1
        if max_count > 1000:
            max_count = 1000
    except ValueError:
        max_count = 250
    scope = str(self.passive_scope_combo.getSelectedItem())
    endpoint_keys, total_available = self._collect_auth_replay_targets(scope, max_count)
    if not endpoint_keys:
        self.passive_area.setText("[!] No endpoints found for scope '{}'\n".format(scope))
        return None
    return {
        "scope": scope,
        "endpoint_keys": endpoint_keys,
        "total_available": int(total_available),
    }


def _run_advanced_logic_mode(self, mode="all", event=None):
    context = self._resolve_passive_scope_targets()
    if not context:
        return
    scope = context["scope"]
    endpoint_keys = context["endpoint_keys"]
    total_available = context["total_available"]
    mode_key = self._ascii_safe(mode or "all", lower=True)
    self.passive_area.setText("[*] Starting advanced logic analytics ({})...\n".format(mode_key))
    self.passive_area.append(
        "[*] Scope: {} | Targets: {} of {}\n\n".format(
            scope, len(endpoint_keys), total_available
        )
    )

    def run_worker():
        try:
            snapshot = self._collect_passive_snapshot(endpoint_keys)
            sequence_package = self._build_sequence_invariant_package(snapshot)
            golden_package = self._build_golden_ticket_package(snapshot)
            state_package = self._build_state_transition_package(snapshot)
            advanced_packages = self._build_advanced_logic_packages(
                snapshot,
                sequence_package=sequence_package,
                golden_package=golden_package,
                state_package=state_package,
            )
            self._sort_and_store_sequence_invariant_payload(
                sequence_package,
                source_label="advanced_logic",
                scope_label=scope,
                target_count=len(snapshot),
            )
            self._sort_and_store_golden_ticket_payload(
                golden_package,
                source_label="advanced_logic",
                scope_label=scope,
                target_count=len(snapshot),
            )
            self._sort_and_store_state_transition_payload(
                state_package,
                source_label="advanced_logic",
                scope_label=scope,
                target_count=len(snapshot),
            )
            self._store_advanced_logic_packages(
                advanced_packages,
                source_label="advanced_logic",
                scope_label=scope,
                target_count=len(snapshot),
            )
            text = self._format_advanced_logic_output(advanced_packages, mode=mode_key)
            SwingUtilities.invokeLater(lambda t=text: self.passive_area.setText(t))
            summary = []
            if mode_key in ["all", "abuse", "abuse_chains"]:
                summary.append(
                    "chains={}".format(
                        int((advanced_packages.get("abuse_chains", {}) or {}).get("finding_count", 0) or 0)
                    )
                )
            if mode_key in ["all", "proof", "proof_mode"]:
                summary.append(
                    "poc_sets={}".format(
                        int((advanced_packages.get("proof_mode", {}) or {}).get("packet_set_count", 0) or 0)
                    )
                )
            if mode_key in ["all", "spec", "guardrails", "spec_guardrails"]:
                summary.append(
                    "guardrail_violations={}".format(
                        int((advanced_packages.get("spec_guardrails", {}) or {}).get("violation_count", 0) or 0)
                    )
                )
            if mode_key in ["all", "role", "role_delta"]:
                summary.append(
                    "role_deltas={}".format(
                        int((advanced_packages.get("role_delta", {}) or {}).get("finding_count", 0) or 0)
                    )
                )
            SwingUtilities.invokeLater(
                lambda: self.log_to_ui(
                    "[+] Advanced logic complete ({})".format(", ".join(summary))
                )
            )
        except Exception as e:
            err_msg = self._ascii_safe(e)
            err_text = "[!] Advanced logic analysis failed: {}\n".format(err_msg)
            SwingUtilities.invokeLater(lambda t=err_text: self.passive_area.append(t))
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] Advanced logic error: {}".format(m))
            )

    worker = threading.Thread(target=run_worker)
    worker.daemon = True
    worker.start()


def _run_abuse_chain_builder(self, event):
    self._run_advanced_logic_mode(mode="abuse_chains", event=event)


def _run_all_advanced_logic(self, event):
    self._run_advanced_logic_mode(mode="all", event=event)


def _run_proof_mode(self, event):
    self._run_advanced_logic_mode(mode="proof_mode", event=event)


def _run_spec_guardrails(self, event):
    self._run_advanced_logic_mode(mode="spec_guardrails", event=event)


def _run_role_delta_engine(self, event):
    self._run_advanced_logic_mode(mode="role_delta", event=event)


__all__ = [
    "_normalize_endpoint_key",
    "_flatten_snapshot_entries",
    "_entry_has_auth",
    "_resource_hint_from_path",
    "_is_auth_surface",
    "_is_object_access_surface",
    "_is_state_change_surface",
    "_score_to_label",
    "_severity_from_score",
    "_build_simple_ledger",
    "_build_abuse_chain_package",
    "_collect_strong_findings_for_proof_mode",
    "_redact_header_for_packet",
    "_packet_from_entry",
    "_build_proof_mode_packet_sets",
    "_build_spec_guardrail_package",
    "_infer_role_label_from_entry",
    "_role_rank",
    "_build_role_delta_package",
    "_build_advanced_logic_packages",
    "_store_advanced_logic_packages",
    "_format_abuse_chain_output",
    "_format_proof_mode_output",
    "_format_spec_guardrail_output",
    "_format_role_delta_output",
    "_format_advanced_logic_output",
    "_resolve_passive_scope_targets",
    "_run_advanced_logic_mode",
    "_run_abuse_chain_builder",
    "_run_all_advanced_logic",
    "_run_proof_mode",
    "_run_spec_guardrails",
    "_run_role_delta_engine",
]
