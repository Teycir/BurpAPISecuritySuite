# -*- coding: utf-8 -*-
"""Behavior-level sequence invariant checks and evidence ledger generation."""

import re
import time


WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
SENSITIVE_PARAM_TOKENS = (
    "role",
    "admin",
    "is_admin",
    "permission",
    "scope",
    "status",
    "price",
    "amount",
    "balance",
    "credit",
    "limit",
)
CALLBACK_PARAM_TOKENS = (
    "callback",
    "redirect",
    "return_url",
    "target",
    "url",
    "uri",
    "webhook",
)
IDEMPOTENCY_HINTS = ("idempotency", "idempotency_key", "request_id", "nonce")


def _text(value, lower=False, max_len=None):
    if value is None:
        value = ""
    try:
        text_type = unicode  # noqa: F821 (Python2/Jython)
    except NameError:
        text_type = str
    text = value if isinstance(value, text_type) else text_type(value)
    if lower:
        text = text.lower()
    if max_len is not None and len(text) > max_len:
        text = text[:max_len]
    return text


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
    # Normalize dynamic IDs to keep resource grouping stable.
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


def _extract_param_names_default(entry):
    params = entry.get("parameters", {}) or {}
    names = []
    if isinstance(params, dict):
        for value in params.values():
            if isinstance(value, dict):
                names.extend(value.keys())
            elif isinstance(value, list):
                names.extend(value)
    return sorted(list(set([_text(x, lower=True).strip() for x in names if _text(x).strip()])))


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
        "id": "seqinv-{0:03d}".format(len(findings) + 1),
        "category": "SEQ_INV",
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


def _build_endpoint_records(data_snapshot, get_entry=None, extract_param_names=None):
    get_entry_fn = get_entry if callable(get_entry) else _first_entry
    extract_params_fn = (
        extract_param_names if callable(extract_param_names) else _extract_param_names_default
    )
    records = []
    for endpoint_key, entries in (data_snapshot or {}).items():
        canonical = get_entry_fn(entries)
        method = _text(canonical.get("method") or "").upper()
        path = _text(canonical.get("normalized_path") or canonical.get("path") or "/")
        resource = _path_to_resource(path)

        auth_contexts = set()
        statuses = set()
        success_count = 0
        sample_count = 0
        for sample in _iter_entries(entries):
            sample_count += 1
            status = sample.get("response_status", 0)
            try:
                status_int = int(status or 0)
            except Exception as _err:
                status_int = 0
            if status_int:
                statuses.add(status_int)
            if 200 <= status_int < 300:
                success_count += 1
            auth_contexts.add(_auth_fingerprint(sample))

        params = extract_params_fn(canonical) or []
        param_names = sorted(list(set([_text(x, lower=True).strip() for x in params if _text(x).strip()])))
        records.append(
            {
                "endpoint": _text(endpoint_key),
                "method": method,
                "path": path,
                "resource": resource,
                "auth_contexts": sorted(list(auth_contexts)),
                "status_codes": sorted(list(statuses)),
                "success_count": success_count,
                "sample_count": sample_count,
                "param_names": param_names,
            }
        )
    return records


def _group_by_resource(records):
    grouped = {}
    for record in records:
        resource = _text(record.get("resource") or "root", lower=True)
        if resource not in grouped:
            grouped[resource] = []
        grouped[resource].append(record)
    return grouped


def build_sequence_invariant_findings(data_snapshot, get_entry=None, extract_param_names=None):
    """Detect high-value sequence/state invariant gaps from captured endpoint snapshots."""
    records = _build_endpoint_records(
        data_snapshot, get_entry=get_entry, extract_param_names=extract_param_names
    )
    grouped = _group_by_resource(records)
    findings = []

    for resource, items in sorted(grouped.items()):
        methods = sorted(list(set([_text(x.get("method") or "").upper() for x in items])))
        endpoints = [x.get("endpoint") for x in items]
        auth_contexts = set()
        for item in items:
            for auth in item.get("auth_contexts", []):
                auth_contexts.add(_text(auth, lower=True))

        has_public = "none" in auth_contexts
        has_authenticated = any(ctx != "none" for ctx in auth_contexts)
        write_items = [x for x in items if _text(x.get("method") or "").upper() in WRITE_METHODS]
        read_items = [x for x in items if _text(x.get("method") or "").upper() == "GET"]

        if has_public and has_authenticated and read_items:
            _make_finding(
                findings,
                "auth_boundary_consistency",
                "Public and authenticated surfaces coexist for same resource",
                "high",
                0.83,
                resource,
                endpoints,
                [
                    "auth_contexts={}".format(",".join(sorted(list(auth_contexts))[:6])),
                    "methods={}".format(",".join(methods[:8])),
                    "read_endpoints={}".format(len(read_items)),
                ],
                [
                    "Replay authenticated object IDs as unauthenticated requests.",
                    "Compare field-level response diff between public and authenticated contexts.",
                ],
            )

        if ("DELETE" in methods) and ("GET" in methods):
            delete_success = sum([x.get("success_count", 0) for x in items if x.get("method") == "DELETE"])
            get_success = sum([x.get("success_count", 0) for x in items if x.get("method") == "GET"])
            if delete_success > 0 and get_success > 0:
                _make_finding(
                    findings,
                    "delete_tombstone_consistency",
                    "Delete and subsequent read surface indicates possible stale-object access window",
                    "medium",
                    0.67,
                    resource,
                    endpoints,
                    [
                        "delete_success_samples={}".format(delete_success),
                        "get_success_samples={}".format(get_success),
                    ],
                    [
                        "Perform delete->immediate get->delayed get sequence for same object id.",
                        "Probe replica/cache headers for stale read behavior.",
                    ],
                )

        sensitive_write_items = []
        callback_write_items = []
        idempotency_present = False
        for item in write_items:
            params = item.get("param_names", []) or []
            if any(token in name for name in params for token in SENSITIVE_PARAM_TOKENS):
                sensitive_write_items.append(item)
            if any(token in name for name in params for token in CALLBACK_PARAM_TOKENS):
                callback_write_items.append(item)
            if any(hint in name for name in params for hint in IDEMPOTENCY_HINTS):
                idempotency_present = True

        if sensitive_write_items and read_items:
            _make_finding(
                findings,
                "sensitive_write_field_integrity",
                "Sensitive write parameters appear on mutable endpoints for this resource",
                "high",
                0.78,
                resource,
                [x.get("endpoint") for x in sensitive_write_items] + [x.get("endpoint") for x in read_items],
                [
                    "sensitive_write_endpoints={}".format(len(sensitive_write_items)),
                    "tokens={}".format(",".join(SENSITIVE_PARAM_TOKENS[:6])),
                ],
                [
                    "Attempt role/status/limit tampering across user contexts.",
                    "Validate server-side allowlist for mutable fields.",
                ],
            )

        if callback_write_items:
            _make_finding(
                findings,
                "callback_target_control",
                "Write flow accepts callback/redirect-like parameters that can alter downstream targets",
                "medium",
                0.69,
                resource,
                [x.get("endpoint") for x in callback_write_items],
                [
                    "callback_like_write_endpoints={}".format(len(callback_write_items)),
                    "tokens={}".format(",".join(CALLBACK_PARAM_TOKENS[:6])),
                ],
                [
                    "Test allowlist enforcement for callback destinations.",
                    "Probe internal host/IP callback targets for SSRF-style execution.",
                ],
            )

        if len(write_items) >= 2 and not idempotency_present:
            _make_finding(
                findings,
                "concurrent_write_idempotency",
                "Multiple write methods exist without obvious idempotency controls",
                "medium",
                0.64,
                resource,
                [x.get("endpoint") for x in write_items],
                [
                    "write_methods={}".format(",".join(sorted(list(set([x.get("method") for x in write_items]))))),
                    "idempotency_hints=absent",
                ],
                [
                    "Replay duplicate POST/PATCH requests concurrently with same payload.",
                    "Validate deduplication using request id/idempotency key semantics.",
                ],
            )

    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0)),
            _text(item.get("severity"), lower=True),
            _text(item.get("resource"), lower=True),
        )
    )
    return findings[:400]


def build_evidence_ledger(findings):
    """Build AI/human-friendly confidence ledger from invariant findings."""
    items = list(findings or [])
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    conf_counts = {"high": 0, "medium": 0, "low": 0}
    for finding in items:
        severity = _text(finding.get("severity"), lower=True)
        if severity in sev_counts:
            sev_counts[severity] += 1
        confidence = _text(finding.get("confidence_label"), lower=True)
        if confidence in conf_counts:
            conf_counts[confidence] += 1

    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_findings": len(items),
        "severity_distribution": sev_counts,
        "confidence_distribution": conf_counts,
        "analyst_guidance": [
            "Use confidence as prioritization signal, not as auto-drop gate.",
            "Keep low-confidence entries for AI/human triage to avoid false negatives.",
            "Validate top findings with sequence replay evidence before hard conclusions.",
        ],
        "findings": items,
    }


def build_sequence_invariant_package(data_snapshot, get_entry=None, extract_param_names=None):
    """Build full sequence-invariant package with findings + evidence ledger."""
    findings = build_sequence_invariant_findings(
        data_snapshot,
        get_entry=get_entry,
        extract_param_names=extract_param_names,
    )
    ledger = build_evidence_ledger(findings)
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finding_count": len(findings),
        "findings": findings,
        "ledger": ledger,
    }
