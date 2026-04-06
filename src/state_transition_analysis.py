# -*- coding: utf-8 -*-
"""State Transition Matrix analysis for hidden workflow/state drift issues."""

import re
import time


WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
READ_METHODS = ("GET", "HEAD")


def _text(value, lower=False):
    if value is None:
        value = ""
    try:
        text_type = unicode  # noqa: F821 (Python2/Jython)
    except NameError:
        text_type = str
    text = value if isinstance(value, text_type) else text_type(value)
    if lower:
        text = text.lower()
    return text


def _safe_int(value):
    try:
        return int(value)
    except Exception as _err:
        return None


def _first_entry(entries):
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict):
                return item
        return {}
    if isinstance(entries, dict):
        return entries
    return {}


def _iter_entries(entries):
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(entries, dict):
        yield entries


def _path_to_resource(path):
    cleaned = _text(path or "/", lower=True).strip()
    if not cleaned:
        return "root"
    cleaned = cleaned.split("?", 1)[0]
    cleaned = re.sub(r"/\d+(?=/|$)", "/{id}", cleaned)
    cleaned = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
        "/{uuid}",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"/+", "/", cleaned)
    parts = [p for p in cleaned.strip("/").split("/") if p]
    if not parts:
        return "root"
    return parts[0]


def _auth_fingerprint(sample):
    auth_detected = sample.get("auth_detected", []) or []
    normalized = sorted(
        list(
            set(
                [
                    _text(item, lower=True).strip()
                    for item in auth_detected
                    if _text(item).strip()
                ]
            )
        )
    )
    if normalized and not (len(normalized) == 1 and normalized[0] == "none"):
        return "auth:" + ",".join(normalized[:3])

    headers = sample.get("headers", {}) or {}
    lowered = {}
    for key, value in headers.items():
        lowered[_text(key, lower=True)] = _text(value)

    authz = _text(lowered.get("authorization", "")).strip()
    if authz:
        if _text(authz, lower=True).startswith("bearer "):
            return "bearer"
        return "authorization"
    if _text(lowered.get("x-api-key", "")).strip():
        return "x-api-key"
    if _text(lowered.get("cookie", "")).strip():
        return "cookie"
    return "none"


def _confidence_label(score):
    if score >= 0.8:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def _make_finding(
    findings,
    invariant_name,
    title,
    severity,
    score,
    resource,
    endpoints,
    evidence,
    suggested_checks,
):
    finding = {
        "id": "stm-{0:03d}".format(len(findings) + 1),
        "category": "STATE_MATRIX",
        "invariant": _text(invariant_name),
        "title": _text(title),
        "severity": _text(severity, lower=True),
        "confidence_score": round(float(score), 2),
        "confidence_label": _confidence_label(float(score)),
        "resource": _text(resource),
        "endpoint_scope": sorted(list(set([_text(x) for x in endpoints if _text(x).strip()])))[:20],
        "evidence": [_text(x) for x in (evidence or []) if _text(x).strip()][:12],
        "suggested_checks": [
            _text(x) for x in (suggested_checks or []) if _text(x).strip()
        ][:10],
        "non_destructive": True,
    }
    findings.append(finding)


def _collect_transition_profiles(data_snapshot, get_entry=None):
    get_entry_fn = get_entry if callable(get_entry) else _first_entry
    grouped = {}
    transition_edges = 0

    for endpoint_key, entries in (data_snapshot or {}).items():
        canonical = get_entry_fn(entries)
        fallback_method = _text(canonical.get("method") or "").upper()
        fallback_path = _text(canonical.get("normalized_path") or canonical.get("path") or "/")
        fallback_resource = _path_to_resource(fallback_path)

        for sample in _iter_entries(entries):
            method = _text(sample.get("method") or fallback_method).upper()
            path = _text(sample.get("normalized_path") or sample.get("path") or fallback_path)
            resource = _path_to_resource(path) or fallback_resource
            status = _safe_int(sample.get("response_status", 0) or 0) or 0
            auth = _auth_fingerprint(sample)

            if resource not in grouped:
                grouped[resource] = {}
            if method not in grouped[resource]:
                grouped[resource][method] = {
                    "resource": resource,
                    "method": method,
                    "endpoints": set(),
                    "auth_contexts": set(),
                    "status_codes": set(),
                    "status_classes": set(),
                    "sample_count": 0,
                    "success_count": 0,
                }
            profile = grouped[resource][method]
            profile["endpoints"].add(_text(endpoint_key))
            profile["auth_contexts"].add(_text(auth, lower=True))
            profile["sample_count"] += 1
            if status:
                profile["status_codes"].add(status)
                profile["status_classes"].add(int(status / 100))
                if 200 <= status < 300:
                    profile["success_count"] += 1
            transition_edges += 1

    return grouped, transition_edges


def _build_evidence_ledger(findings):
    items = list(findings or [])
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    conf_counts = {"high": 0, "medium": 0, "low": 0}
    for finding in items:
        sev = _text(finding.get("severity"), lower=True)
        if sev in sev_counts:
            sev_counts[sev] += 1
        conf = _text(finding.get("confidence_label"), lower=True)
        if conf in conf_counts:
            conf_counts[conf] += 1

    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_findings": len(items),
        "severity_distribution": sev_counts,
        "confidence_distribution": conf_counts,
        "analyst_guidance": [
            "Use matrix findings to choose replay sequences, not as auto-confirmed vulnerabilities.",
            "Focus first on high-confidence transitions that involve write + public read overlap.",
            "Keep medium/low findings for AI/human triage to avoid missing edge-case logic bugs.",
        ],
        "findings": items,
    }


def build_state_transition_findings(data_snapshot, get_entry=None):
    """Detect workflow/state drift using a non-destructive transition matrix view."""
    grouped, _ = _collect_transition_profiles(data_snapshot, get_entry=get_entry)
    findings = []

    for resource in sorted(grouped.keys()):
        profiles = grouped.get(resource, {})
        methods = sorted(list(profiles.keys()))
        write_profiles = [profiles[m] for m in methods if m in WRITE_METHODS]
        read_profiles = [profiles[m] for m in methods if m in READ_METHODS]
        endpoints = []
        for profile in profiles.values():
            endpoints.extend(list(profile.get("endpoints", set())))
        endpoints = sorted(list(set(endpoints)))

        if write_profiles and read_profiles:
            public_read = any(
                ("none" in p.get("auth_contexts", set())) and (p.get("success_count", 0) > 0)
                for p in read_profiles
            )
            auth_write = any(
                (
                    any(ctx != "none" for ctx in p.get("auth_contexts", set()))
                    and (p.get("success_count", 0) > 0)
                )
                for p in write_profiles
            )
            if public_read and auth_write:
                _make_finding(
                    findings,
                    "state_transition_public_read_after_authenticated_write",
                    "Writes appear authenticated but resulting resource reads may be publicly accessible",
                    "high",
                    0.82,
                    resource,
                    endpoints,
                    [
                        "methods={}".format(",".join(methods[:8])),
                        "public_read=True",
                        "authenticated_write=True",
                    ],
                    [
                        "Replay write->read sequence with and without authentication.",
                        "Validate object-level authorization on read endpoints after state changes.",
                    ],
                )

        for profile in write_profiles:
            auth_contexts = sorted(list(profile.get("auth_contexts", set())))
            if profile.get("success_count", 0) > 0 and len(auth_contexts) >= 2:
                includes_public = "none" in auth_contexts
                _make_finding(
                    findings,
                    "state_transition_write_auth_variance",
                    "Same write operation succeeds under multiple auth contexts",
                    "high" if includes_public else "medium",
                    0.79 if includes_public else 0.67,
                    resource,
                    endpoints,
                    [
                        "method={}".format(profile.get("method", "")),
                        "auth_contexts={}".format(",".join(auth_contexts[:8])),
                        "write_success_samples={}".format(profile.get("success_count", 0)),
                    ],
                    [
                        "Replay same write payload across guest/user/admin contexts.",
                        "Enforce strict role checks for state-changing operations.",
                    ],
                )

        for profile in profiles.values():
            status_classes = set(profile.get("status_classes", set()))
            sample_count = int(profile.get("sample_count", 0) or 0)
            if sample_count >= 3 and (2 in status_classes) and (4 in status_classes):
                _make_finding(
                    findings,
                    "state_transition_policy_drift",
                    "Transition outcomes vary between success and denial for same operation",
                    "medium",
                    0.63,
                    resource,
                    endpoints,
                    [
                        "method={}".format(profile.get("method", "")),
                        "status_classes={}".format(",".join([str(x) for x in sorted(list(status_classes))])),
                        "sample_count={}".format(sample_count),
                    ],
                    [
                        "Diff successful vs denied requests to isolate hidden policy branch.",
                        "Check role/object ownership controls for inconsistent transition handling.",
                    ],
                )

        if ("DELETE" in profiles) and ("GET" in profiles):
            delete_success = int(profiles.get("DELETE", {}).get("success_count", 0) or 0)
            get_success = int(profiles.get("GET", {}).get("success_count", 0) or 0)
            if delete_success > 0 and get_success > 0:
                _make_finding(
                    findings,
                    "state_transition_delete_read_overlap",
                    "Delete and read transitions both succeed for same resource family",
                    "medium",
                    0.7,
                    resource,
                    endpoints,
                    [
                        "delete_success_samples={}".format(delete_success),
                        "get_success_samples={}".format(get_success),
                    ],
                    [
                        "Run delete->immediate read->delayed read for same object id.",
                        "Check cache/replica lag and tombstone enforcement behavior.",
                    ],
                )

    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0)),
            _text(item.get("severity"), lower=True),
            _text(item.get("resource"), lower=True),
            _text(item.get("id"), lower=True),
        )
    )
    return findings[:320]


def build_state_transition_package(data_snapshot, get_entry=None):
    """Build state transition matrix package with findings + ledger."""
    grouped, transition_edges = _collect_transition_profiles(
        data_snapshot, get_entry=get_entry
    )
    findings = build_state_transition_findings(data_snapshot, get_entry=get_entry)
    ledger = _build_evidence_ledger(findings)
    ledger["analysis_type"] = "state_transition_matrix"
    ledger["coverage"] = {
        "resources_analyzed": len(grouped),
        "transition_edges_observed": int(transition_edges or 0),
    }
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finding_count": len(findings),
        "resource_count": len(grouped),
        "transition_edge_count": int(transition_edges or 0),
        "findings": findings,
        "ledger": ledger,
    }
