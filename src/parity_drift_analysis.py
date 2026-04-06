# -*- coding: utf-8 -*-
"""Cross-interface parity and drift analysis for high-ROI logic bugs."""

import re
import time


WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
READ_METHODS = ("GET", "HEAD", "OPTIONS")
CACHE_HEADER_HINTS = (
    "cache-control",
    "age",
    "etag",
    "expires",
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "x-served-by",
    "x-cache-key",
)
INTERNAL_PATH_HINTS = (
    "/internal",
    "/private",
    "/hidden",
    "/admin",
    "/_",
    "/ops",
)
TENANT_PARAM_HINTS = (
    "tenant",
    "org",
    "organization",
    "workspace",
    "company",
    "project",
    "account",
    "customer",
    "client",
    "user",
)
STATE_STAGE_TOKENS = {
    "create": ("create", "register", "signup", "open", "init"),
    "pay": ("pay", "payment", "charge", "checkout", "purchase"),
    "refund": ("refund", "reversal", "chargeback"),
    "deactivate": ("deactivate", "disable", "delete", "cancel", "close", "suspend"),
    "activate": ("activate", "enable", "restore"),
}
ERROR_ORACLE_PATTERNS = (
    r"did you mean",
    r"available fields?",
    r"valid states?",
    r"accepted values?",
    r"unknown route",
    r"stack trace",
    r"debug",
    r"feature[_\s-]?flag",
    r"internal",
    r"/api/[a-z0-9/_-]+",
    r"graphql",
)


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


def _safe_int(value):
    try:
        return int(value)
    except Exception as _err:
        return None


def _iter_entries(entries):
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(entries, dict):
        yield entries


def _first_entry(entries):
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict):
                return item
        return {}
    if isinstance(entries, dict):
        return entries
    return {}


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


def _path_without_query(path):
    return _text(path or "/").split("?", 1)[0]


def _collapse_action_path(path):
    cleaned = _text(path or "/", lower=True).strip()
    if not cleaned:
        return "root"
    cleaned = _path_without_query(cleaned)
    cleaned = re.sub(r"/\d+(?=/|$)", "/{id}", cleaned)
    cleaned = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
        "/{uuid}",
        cleaned,
        flags=re.IGNORECASE,
    )
    tokens = []
    for seg in cleaned.strip("/").split("/"):
        if not seg:
            continue
        if re.match(r"^v\d+(?:\.\d+)?$", seg):
            continue
        if seg in ["api", "rest"]:
            continue
        tokens.append(seg)
        if len(tokens) >= 3:
            break
    if not tokens:
        return "root"
    return "/".join(tokens)


def _header_value(headers, wanted_key):
    wanted = _text(wanted_key, lower=True).strip()
    for key, value in (headers or {}).items():
        if _text(key, lower=True).strip() == wanted:
            return _text(value).strip()
    return ""


def _status_class(status):
    value = _safe_int(status)
    if value is None or value <= 0:
        return 0
    return int(value / 100)


def _is_success(status):
    value = _safe_int(status)
    if value is None:
        return False
    return 200 <= value < 300


def _is_public(sample):
    auth = [_text(x, lower=True).strip() for x in (sample.get("auth_detected") or [])]
    if not auth:
        headers = sample.get("headers", {}) or {}
        if _header_value(headers, "authorization"):
            return False
        if _header_value(headers, "cookie"):
            return False
        if _header_value(headers, "x-api-key"):
            return False
        return True
    return all(x in ["none", ""] for x in auth)


def _interface_label(sample, path, host):
    content_type = _text(sample.get("content_type") or "", lower=True)
    api_patterns = [_text(x, lower=True) for x in (sample.get("api_patterns") or [])]
    lowered_path = _text(path, lower=True)
    lowered_host = _text(host, lower=True)
    if "/graphql" in lowered_path or "graphql" in content_type or "graphql" in api_patterns:
        return "graphql"
    if any(marker in lowered_path for marker in INTERNAL_PATH_HINTS):
        return "internal"
    if "internal" in lowered_host:
        return "internal"
    return "rest"


def _request_content_type(sample):
    headers = sample.get("headers", {}) or {}
    header_value = _header_value(headers, "content-type")
    if header_value:
        return _text(header_value.split(";", 1)[0], lower=True).strip()
    body = _text(sample.get("request_body") or "").strip()
    if not body:
        return "none"
    if body.startswith("{") or body.startswith("["):
        return "application/json"
    if body.startswith("<"):
        return "application/xml"
    if "=" in body and "&" in body:
        return "application/x-www-form-urlencoded"
    return "text/plain"


def _extract_tenant_identifiers(sample):
    identifiers = []
    params = sample.get("parameters", {}) or {}
    if not isinstance(params, dict):
        return identifiers
    for bucket in params.values():
        if not isinstance(bucket, dict):
            continue
        for name, value in bucket.items():
            key = _text(name, lower=True).strip()
            if (not key) or (not any(token in key for token in TENANT_PARAM_HINTS)):
                continue
            raw_value = _text(value).strip()
            if not raw_value:
                continue
            normalized = _text(raw_value, lower=True).strip()
            if len(normalized) > 80:
                normalized = normalized[:80]
            identifiers.append((key, normalized))
    return identifiers


def _matched_oracle_pattern(body_text):
    body = _text(body_text or "", lower=True, max_len=2400)
    if not body:
        return ""
    for pattern in ERROR_ORACLE_PATTERNS:
        try:
            if re.search(pattern, body):
                return pattern
        except Exception as _err:
            continue
    return ""


def _infer_state_stages(method, path):
    stages = []
    lowered_method = _text(method, lower=True).strip().upper()
    lowered_path = _text(path, lower=True)
    if lowered_method == "POST":
        stages.append("create")
    if lowered_method == "DELETE":
        stages.append("deactivate")
    for stage, markers in STATE_STAGE_TOKENS.items():
        if any(marker in lowered_path for marker in markers):
            stages.append(stage)
    dedup = []
    seen = set()
    for stage in stages:
        if stage in seen:
            continue
        seen.add(stage)
        dedup.append(stage)
    return dedup


def _confidence_label(score):
    if score >= 0.8:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def _make_finding(
    findings,
    category,
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
        "id": "parity-{0:03d}".format(len(findings) + 1),
        "category": _text(category),
        "invariant": _text(invariant_name),
        "title": _text(title),
        "severity": _text(severity, lower=True),
        "confidence_score": round(float(score), 2),
        "confidence_label": _confidence_label(float(score)),
        "resource": _text(resource),
        "endpoint_scope": sorted(list(set([_text(x) for x in endpoints if _text(x).strip()])))[:20],
        "evidence": [_text(x) for x in (evidence or []) if _text(x).strip()][:12],
        "suggested_checks": [_text(x) for x in (suggested_checks or []) if _text(x).strip()][:10],
        "non_destructive": True,
    }
    findings.append(finding)


def _collect_rows(data_snapshot, get_entry=None):
    get_entry_fn = get_entry if callable(get_entry) else _first_entry
    rows = []
    ordinal = 0
    for endpoint_key, entries in (data_snapshot or {}).items():
        canonical = get_entry_fn(entries)
        fallback_method = _text(canonical.get("method") or "").upper()
        fallback_path = _text(canonical.get("normalized_path") or canonical.get("path") or "/")
        fallback_host = _text(canonical.get("host") or "", lower=True)
        for sample in _iter_entries(entries):
            ordinal += 1
            method = _text(sample.get("method") or fallback_method).upper()
            path = _text(sample.get("normalized_path") or sample.get("path") or fallback_path)
            host = _text(sample.get("host") or fallback_host, lower=True)
            status = _safe_int(sample.get("response_status", 0) or 0) or 0
            response_headers = sample.get("response_headers", {}) or {}
            cached_ts = _safe_int(sample.get("captured_at_epoch_ms"))
            if cached_ts is None:
                cached_ts = ordinal * 1000
            rows.append(
                {
                    "endpoint": _text(endpoint_key),
                    "method": method,
                    "path": path,
                    "host": host,
                    "resource": _path_to_resource(path),
                    "action_key": "{} {}".format(method, _collapse_action_path(path)),
                    "interface": _interface_label(sample, path, host),
                    "status": status,
                    "status_class": _status_class(status),
                    "success": _is_success(status),
                    "is_public": _is_public(sample),
                    "request_content_type": _request_content_type(sample),
                    "response_headers": response_headers,
                    "response_time_ms": _safe_int(sample.get("response_time_ms") or 0) or 0,
                    "captured_at_epoch_ms": cached_ts,
                    "tenant_identifiers": _extract_tenant_identifiers(sample),
                    "response_body": _text(sample.get("response_body") or "", max_len=2600),
                    "state_stages": _infer_state_stages(method, path),
                    "is_read": method in READ_METHODS,
                    "is_write": method in WRITE_METHODS,
                }
            )
    return rows


def _cache_hint_score(row):
    headers = row.get("response_headers", {}) or {}
    score = 0
    normalized = {}
    for key, value in headers.items():
        normalized[_text(key, lower=True)] = _text(value, lower=True)
    for hint in CACHE_HEADER_HINTS:
        if hint in normalized:
            score += 1
    x_cache = _text(normalized.get("x-cache", ""), lower=True)
    cf_cache = _text(normalized.get("cf-cache-status", ""), lower=True)
    if "hit" in x_cache or "hit" in cf_cache:
        score += 2
    cache_control = _text(normalized.get("cache-control", ""), lower=True)
    if cache_control and ("no-store" not in cache_control):
        score += 1
    return score


def _build_evidence_ledger(findings):
    items = list(findings or [])
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    conf_counts = {"high": 0, "medium": 0, "low": 0}
    category_counts = {}
    for finding in items:
        severity = _text(finding.get("severity"), lower=True)
        if severity in sev_counts:
            sev_counts[severity] += 1
        confidence = _text(finding.get("confidence_label"), lower=True)
        if confidence in conf_counts:
            conf_counts[confidence] += 1
        category = _text(finding.get("category"), lower=True)
        category_counts[category] = category_counts.get(category, 0) + 1
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_findings": len(items),
        "severity_distribution": sev_counts,
        "confidence_distribution": conf_counts,
        "category_distribution": category_counts,
        "analyst_guidance": [
            "Prioritize cross-interface and cache/auth drift findings first for high-impact auth bypass classes.",
            "Use time-window and replay-after-delete findings to design delayed replay validation.",
            "Treat findings as strong hypotheses and confirm with controlled role/tenant replay.",
        ],
        "findings": items,
    }


def build_parity_drift_findings(data_snapshot, get_entry=None):
    """Detect advanced parity/drift logic gaps often missed by signature scanners."""
    rows = _collect_rows(data_snapshot, get_entry=get_entry)
    findings = []

    # 1) Cross-Interface Parity Checks
    action_groups = {}
    for row in rows:
        action_groups.setdefault(row.get("action_key"), []).append(row)
    for action_key, group in action_groups.items():
        interface_stats = {}
        for row in group:
            iface = _text(row.get("interface"), lower=True)
            stats = interface_stats.setdefault(
                iface,
                {"public_success": 0, "protected_success": 0, "endpoints": set(), "resource": row.get("resource")},
            )
            if row.get("success"):
                if row.get("is_public"):
                    stats["public_success"] += 1
                else:
                    stats["protected_success"] += 1
            stats["endpoints"].add(_text(row.get("endpoint")))
        if len(interface_stats.keys()) < 2:
            continue
        exposed_ifaces = [
            name
            for name, stats in interface_stats.items()
            if int(stats.get("public_success", 0) or 0) > 0
        ]
        hardened_ifaces = [
            name
            for name, stats in interface_stats.items()
            if int(stats.get("public_success", 0) or 0) <= 0
            and int(stats.get("protected_success", 0) or 0) > 0
        ]
        if exposed_ifaces and hardened_ifaces:
            endpoints = []
            for stats in interface_stats.values():
                endpoints.extend(list(stats.get("endpoints", set())))
            _make_finding(
                findings,
                "CROSS_INTERFACE_PARITY",
                "cross_interface_authorization_parity",
                "Same action appears protected in one interface and exposed in another",
                "high",
                0.86,
                _text(group[0].get("resource") or "resource"),
                endpoints,
                [
                    "action_key={}".format(action_key),
                    "exposed_interfaces={}".format(",".join(sorted(exposed_ifaces))),
                    "hardened_interfaces={}".format(",".join(sorted(hardened_ifaces))),
                ],
                [
                    "Replay identical object/action across REST, GraphQL, and internal variants.",
                    "Enforce one shared authorization policy layer for all interfaces.",
                ],
            )

    # 2) Cache/Auth Drift Detection
    resource_rows = {}
    for row in rows:
        resource_rows.setdefault(row.get("resource"), []).append(row)
    for resource, group in resource_rows.items():
        protected_reads = [
            row for row in group if row.get("is_read") and row.get("success") and (not row.get("is_public"))
        ]
        cached_public_reads = [
            row
            for row in group
            if row.get("is_read")
            and row.get("success")
            and row.get("is_public")
            and _cache_hint_score(row) >= 2
        ]
        if protected_reads and cached_public_reads:
            endpoints = [x.get("endpoint") for x in (cached_public_reads[:4] + protected_reads[:4])]
            _make_finding(
                findings,
                "CACHE_AUTH_DRIFT",
                "cache_path_authorization_drift",
                "Protected data appears readable through cache-influenced public path variants",
                "high",
                0.83,
                resource,
                endpoints,
                [
                    "protected_reads={}".format(len(protected_reads)),
                    "cached_public_reads={}".format(len(cached_public_reads)),
                    "cache_header_hints=present",
                ],
                [
                    "Replay with and without auth across cache-key variants and query permutations.",
                    "Add no-store/private directives for sensitive authenticated resources.",
                ],
            )

    # 3) Time-Window Abuse Testing
    endpoint_groups = {}
    for row in rows:
        key = "{}|{}".format(row.get("endpoint"), "public" if row.get("is_public") else "protected")
        endpoint_groups.setdefault(key, []).append(row)
    for key, group in endpoint_groups.items():
        ordered = sorted(group, key=lambda item: int(item.get("captured_at_epoch_ms", 0) or 0))
        for idx in range(1, len(ordered)):
            prev_row = ordered[idx - 1]
            cur_row = ordered[idx]
            prev_class = int(prev_row.get("status_class", 0) or 0)
            cur_class = int(cur_row.get("status_class", 0) or 0)
            if (prev_class == 4 and cur_class == 2) or (prev_class == 5 and cur_class == 2):
                delta_ms = int(cur_row.get("captured_at_epoch_ms", 0) or 0) - int(
                    prev_row.get("captured_at_epoch_ms", 0) or 0
                )
                if delta_ms < 0:
                    delta_ms = 0
                if delta_ms <= 300000:
                    _make_finding(
                        findings,
                        "TIME_WINDOW_ABUSE",
                        "eventual_consistency_authorization_window",
                        "Same flow flips from deny/error to success in short time window",
                        "medium",
                        0.73,
                        _text(cur_row.get("resource") or "resource"),
                        [_text(cur_row.get("endpoint"))],
                        [
                            "scope={}".format(_text(key)),
                            "status_transition={} -> {}".format(
                                int(prev_row.get("status", 0) or 0),
                                int(cur_row.get("status", 0) or 0),
                            ),
                            "delta_ms={}".format(delta_ms),
                        ],
                        [
                            "Replay immediately and at 5s/30s/120s intervals.",
                            "Check async permission propagation and cache invalidation timing.",
                        ],
                    )
                break

    # 4) Workflow State-Machine Breaking
    stage_by_resource = {}
    for row in rows:
        if not row.get("success"):
            continue
        resource = _text(row.get("resource") or "resource")
        bucket = stage_by_resource.setdefault(resource, {})
        for stage in (row.get("state_stages") or []):
            bucket[stage] = bucket.get(stage, 0) + 1
    for resource, stage_counts in stage_by_resource.items():
        if int(stage_counts.get("refund", 0) or 0) > 0 and int(stage_counts.get("pay", 0) or 0) <= 0:
            _make_finding(
                findings,
                "STATE_MACHINE_BREAK",
                "refund_without_payment_prerequisite",
                "Refund-like transition appears without observed payment prerequisite",
                "high",
                0.81,
                resource,
                [],
                [
                    "refund_success_count={}".format(int(stage_counts.get("refund", 0) or 0)),
                    "payment_success_count={}".format(int(stage_counts.get("pay", 0) or 0)),
                ],
                [
                    "Attempt refund before payment/settlement in controlled replay.",
                    "Enforce explicit state-transition preconditions server-side.",
                ],
            )
        if int(stage_counts.get("deactivate", 0) or 0) > 0 and int(stage_counts.get("create", 0) or 0) <= 0:
            _make_finding(
                findings,
                "STATE_MACHINE_BREAK",
                "deactivate_without_lifecycle_prerequisite",
                "Deactivate/delete transition appears without observed create/activate prerequisite",
                "medium",
                0.67,
                resource,
                [],
                [
                    "deactivate_success_count={}".format(int(stage_counts.get("deactivate", 0) or 0)),
                    "create_success_count={}".format(int(stage_counts.get("create", 0) or 0)),
                ],
                [
                    "Replay impossible transitions out of order (cancel/delete before create/pay).",
                    "Implement finite-state checks that reject impossible stage jumps.",
                ],
            )

    # 5) Cross-Tenant Collision Probes
    tenant_values = {}
    for row in rows:
        for key_name, normalized in (row.get("tenant_identifiers") or []):
            value_key = "{}={}".format(key_name, normalized)
            record = tenant_values.setdefault(
                normalized,
                {
                    "keys": set(),
                    "resources": set(),
                    "public_success": 0,
                    "protected_success": 0,
                    "samples": set(),
                },
            )
            record["keys"].add(_text(key_name))
            record["resources"].add(_text(row.get("resource")))
            record["samples"].add(_text(row.get("endpoint")))
            if row.get("success"):
                if row.get("is_public"):
                    record["public_success"] += 1
                else:
                    record["protected_success"] += 1
    for normalized, record in tenant_values.items():
        if len(record.get("keys", set())) < 2:
            continue
        if len(record.get("resources", set())) < 2:
            continue
        if int(record.get("public_success", 0) or 0) <= 0:
            continue
        _make_finding(
            findings,
            "TENANT_COLLISION",
            "cross_tenant_identifier_collision_surface",
            "Lookalike tenant/user identifiers appear reusable across boundaries",
            "high",
            0.78,
            "multi-tenant",
            list(record.get("samples", set())),
            [
                "identifier={}".format(normalized[:80]),
                "param_keys={}".format(",".join(sorted(list(record.get("keys", set())))[:6])),
                "resource_count={}".format(len(record.get("resources", set()))),
                "public_success_samples={}".format(int(record.get("public_success", 0) or 0)),
            ],
            [
                "Replay same identifier under different tenant/account headers.",
                "Bind tenant scoping to server-side principal, not client-supplied identifiers.",
            ],
        )

    # 6) Policy Drift by Content-Type
    ctype_groups = {}
    for row in rows:
        if not row.get("is_write"):
            continue
        ctype_groups.setdefault(row.get("action_key"), []).append(row)
    for action_key, group in ctype_groups.items():
        by_type = {}
        for row in group:
            ctype = _text(row.get("request_content_type") or "none", lower=True)
            stats = by_type.setdefault(
                ctype,
                {"public_success": 0, "protected_success": 0, "endpoints": set()},
            )
            if row.get("success"):
                if row.get("is_public"):
                    stats["public_success"] += 1
                else:
                    stats["protected_success"] += 1
            stats["endpoints"].add(_text(row.get("endpoint")))
        if len(by_type.keys()) < 2:
            continue
        drift_ctypes = [
            ctype
            for ctype, stats in by_type.items()
            if int(stats.get("public_success", 0) or 0) > 0
        ]
        hardened_ctypes = [
            ctype
            for ctype, stats in by_type.items()
            if int(stats.get("public_success", 0) or 0) <= 0
            and int(stats.get("protected_success", 0) or 0) > 0
        ]
        if drift_ctypes and hardened_ctypes:
            endpoints = []
            for stats in by_type.values():
                endpoints.extend(list(stats.get("endpoints", set())))
            _make_finding(
                findings,
                "CONTENT_TYPE_POLICY_DRIFT",
                "content_type_parser_policy_drift",
                "Logically similar write flow behaves differently across request content-types",
                "high",
                0.8,
                _text(group[0].get("resource") or "resource"),
                endpoints,
                [
                    "action_key={}".format(action_key),
                    "drift_content_types={}".format(",".join(sorted(drift_ctypes))),
                    "hardened_content_types={}".format(",".join(sorted(hardened_ctypes))),
                ],
                [
                    "Replay identical payload as JSON, form, multipart, and XML.",
                    "Centralize authorization before parser-specific request handling.",
                ],
            )

    # 7) Error-Oracle Intelligence
    for row in rows:
        if int(row.get("status_class", 0) or 0) not in [4, 5]:
            continue
        pattern = _matched_oracle_pattern(row.get("response_body"))
        if not pattern:
            continue
        _make_finding(
            findings,
            "ERROR_ORACLE",
            "error_response_oracle_disclosure",
            "Error response leaks actionable internal hints",
            "medium",
            0.62,
            _text(row.get("resource") or "resource"),
            [_text(row.get("endpoint"))],
            [
                "status={}".format(int(row.get("status", 0) or 0)),
                "oracle_pattern={}".format(pattern),
            ],
            [
                "Strip internal route/schema hints from 4xx/5xx responses.",
                "Return generic client-safe errors while logging detailed traces server-side.",
            ],
        )

    # 8) Replay-After-Delete/Deactivate Checks
    by_resource = {}
    for row in rows:
        by_resource.setdefault(row.get("resource"), []).append(row)
    for resource, group in by_resource.items():
        ordered = sorted(group, key=lambda item: int(item.get("captured_at_epoch_ms", 0) or 0))
        saw_delete = False
        delete_endpoint = ""
        for row in ordered:
            stages = list(row.get("state_stages") or [])
            if row.get("success") and ("deactivate" in stages or _text(row.get("method")) == "DELETE"):
                saw_delete = True
                delete_endpoint = _text(row.get("endpoint"))
                continue
            if saw_delete and row.get("is_read") and row.get("success"):
                _make_finding(
                    findings,
                    "REPLAY_AFTER_DELETE",
                    "post_delete_read_access_persistence",
                    "Read access still succeeds after delete/deactivate transition",
                    "high",
                    0.84,
                    resource,
                    [delete_endpoint, _text(row.get("endpoint"))],
                    [
                        "delete_or_deactivate_endpoint={}".format(delete_endpoint),
                        "post_delete_read_endpoint={}".format(_text(row.get("endpoint"))),
                        "post_delete_status={}".format(int(row.get("status", 0) or 0)),
                    ],
                    [
                        "Replay delete/deactivate then immediate+delayed reads for same object.",
                        "Verify replica/cache invalidation and tombstone enforcement.",
                    ],
                )
                break

    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            _text(item.get("severity"), lower=True),
            _text(item.get("resource"), lower=True),
            _text(item.get("id"), lower=True),
        )
    )
    return findings[:320]


def build_parity_drift_package(data_snapshot, get_entry=None):
    """Build full parity/drift package with findings + evidence ledger."""
    rows = _collect_rows(data_snapshot, get_entry=get_entry)
    findings = build_parity_drift_findings(data_snapshot, get_entry=get_entry)
    ledger = _build_evidence_ledger(findings)
    ledger["analysis_type"] = "cross_interface_and_drift"
    ledger["coverage"] = {
        "observed_samples": len(rows),
        "observed_resources": len(set([_text(x.get("resource")) for x in rows])),
        "observed_actions": len(set([_text(x.get("action_key")) for x in rows])),
    }
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finding_count": len(findings),
        "findings": findings,
        "ledger": ledger,
    }
