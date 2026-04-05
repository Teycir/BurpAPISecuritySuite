# -*- coding: utf-8 -*-
"""Golden Ticket analysis for token-overreach/master-key risk patterns."""

import re
import time
import json
import base64
import hashlib


WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
TOKEN_PRIVILEGE_MARKERS = (
    "admin",
    "root",
    "super",
    "owner",
    "system",
    "svc",
    "service",
    "internal",
)
TOKEN_SESSION_MARKERS = (
    "session",
    "token",
    "auth",
    "jwt",
    "sid",
    "access",
)
JWT_SCOPE_KEYS = ("scope", "scp", "role", "roles", "permissions", "perm")


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


def _header_value(headers, wanted_key):
    wanted = _text(wanted_key, lower=True).strip()
    if not wanted:
        return ""
    for key, value in (headers or {}).items():
        if _text(key, lower=True).strip() == wanted:
            return _text(value).strip()
    return ""


def _decode_jwt_claims(token):
    raw = _text(token).strip()
    if raw.count(".") != 2:
        return {}
    payload = raw.split(".", 2)[1].strip()
    if not payload:
        return {}
    padding = len(payload) % 4
    if padding:
        payload = payload + ("=" * (4 - padding))
    try:
        decoded = base64.urlsafe_b64decode(_text(payload))
    except Exception as _err:
        return {}
    if isinstance(decoded, bytes):
        try:
            decoded = decoded.decode("utf-8")
        except Exception as _err:
            decoded = decoded.decode("latin-1", "ignore")
    try:
        claims = json.loads(_text(decoded))
    except Exception as _err:
        return {}
    return claims if isinstance(claims, dict) else {}


def _token_fingerprint(raw_value):
    token_text = _text(raw_value).strip()
    if not token_text:
        return ""
    encoded = token_text.encode("utf-8")
    digest = hashlib.sha1(encoded).hexdigest()[:12]
    return "tok-{}".format(digest)


def _extract_auth_tokens(sample):
    headers = sample.get("headers", {}) or {}
    extracted = []

    authz = _header_value(headers, "authorization")
    lower_authz = _text(authz, lower=True)
    if lower_authz.startswith("bearer "):
        bearer_value = _text(authz)[7:].strip()
        if bearer_value:
            extracted.append(
                {
                    "scheme": "bearer",
                    "token": bearer_value,
                    "jwt_claims": _decode_jwt_claims(bearer_value),
                }
            )

    api_key = _header_value(headers, "x-api-key")
    if api_key:
        extracted.append({"scheme": "x-api-key", "token": api_key, "jwt_claims": {}})

    cookie = _header_value(headers, "cookie")
    if cookie:
        for chunk in _text(cookie).split(";")[:12]:
            part = chunk.strip()
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key_norm = _text(key, lower=True).strip()
            val_norm = _text(value).strip()
            if not key_norm or not val_norm:
                continue
            if not any(marker in key_norm for marker in TOKEN_SESSION_MARKERS):
                continue
            extracted.append(
                {
                    "scheme": "cookie:{}".format(key_norm[:24]),
                    "token": val_norm,
                    "jwt_claims": _decode_jwt_claims(val_norm),
                }
            )
    return extracted[:8]


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
        "id": "gticket-{0:03d}".format(len(findings) + 1),
        "category": "GOLDEN_TICKET",
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


def _collect_token_observations(data_snapshot, get_entry=None):
    get_entry_fn = get_entry if callable(get_entry) else _first_entry
    observations = {}

    for endpoint_key, entries in (data_snapshot or {}).items():
        canonical = get_entry_fn(entries)
        fallback_method = _text(canonical.get("method") or "").upper()
        fallback_path = _text(canonical.get("normalized_path") or canonical.get("path") or "/")

        for sample in _iter_entries(entries):
            sample_method = _text(sample.get("method") or fallback_method).upper()
            sample_path = _text(
                sample.get("normalized_path") or sample.get("path") or fallback_path
            )
            resource = _path_to_resource(sample_path)

            status = _safe_int(sample.get("response_status", 0) or 0) or 0
            success = 200 <= status < 300
            token_items = _extract_auth_tokens(sample)

            for token_item in token_items:
                scheme = _text(token_item.get("scheme") or "", lower=True)
                raw_token = _text(token_item.get("token") or "")
                fingerprint = _token_fingerprint(raw_token)
                if not scheme or not fingerprint:
                    continue
                token_id = "{}:{}".format(scheme, fingerprint)

                if token_id not in observations:
                    observations[token_id] = {
                        "token_id": token_id,
                        "scheme": scheme,
                        "resources": set(),
                        "write_resources": set(),
                        "methods": set(),
                        "endpoints": set(),
                        "sample_count": 0,
                        "success_count": 0,
                        "write_success_count": 0,
                        "markers": set(),
                        "jwt_claims": {},
                    }
                record = observations[token_id]

                record["resources"].add(resource)
                record["methods"].add(sample_method)
                record["endpoints"].add(_text(endpoint_key))
                record["sample_count"] += 1
                if success:
                    record["success_count"] += 1
                if sample_method in WRITE_METHODS:
                    record["write_resources"].add(resource)
                    if success:
                        record["write_success_count"] += 1

                token_lower = _text(raw_token, lower=True)
                for marker in TOKEN_PRIVILEGE_MARKERS:
                    if marker in token_lower:
                        record["markers"].add(marker)

                claims = token_item.get("jwt_claims", {}) or {}
                if claims and not record.get("jwt_claims"):
                    record["jwt_claims"] = claims

    return observations


def _build_evidence_ledger(findings):
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
            "Treat token fingerprints as correlation handles; never as proof of exploitability.",
        ],
        "findings": items,
    }


def build_golden_ticket_findings(data_snapshot, get_entry=None):
    """Detect token overreach patterns from captured traffic without active probing."""
    observations = _collect_token_observations(data_snapshot, get_entry=get_entry)
    findings = []

    for token_id in sorted(observations.keys()):
        item = observations[token_id]
        resources = sorted(list(item.get("resources", set())))
        write_resources = sorted(list(item.get("write_resources", set())))
        methods = sorted(list(item.get("methods", set())))
        endpoints = sorted(list(item.get("endpoints", set())))
        success_count = int(item.get("success_count", 0) or 0)
        write_success = int(item.get("write_success_count", 0) or 0)
        scheme = _text(item.get("scheme") or "", lower=True)
        jwt_claims = dict(item.get("jwt_claims", {}) or {})
        markers = sorted(list(item.get("markers", set())))

        if success_count >= 3 and len(resources) >= 2 and len(methods) >= 3:
            score = min(
                0.89,
                0.62
                + (0.04 * min(len(resources), 5))
                + (0.03 * min(len(write_resources), 4)),
            )
            severity = "high" if len(write_resources) >= 2 else "medium"
            _make_finding(
                findings,
                "golden_ticket_cross_resource_reuse",
                "Same credential succeeds across multiple resources and methods",
                severity,
                score,
                "multi-resource",
                endpoints,
                [
                    "token={}".format(token_id),
                    "resources={}".format(",".join(resources[:8])),
                    "methods={}".format(",".join(methods[:8])),
                    "success_samples={}".format(success_count),
                ],
                [
                    "Replay object-level requests with same token across unrelated resources.",
                    "Validate token binding per audience/resource boundary server-side.",
                ],
            )

        if markers and write_success >= 1:
            score = 0.77 + (0.03 if len(resources) >= 2 else 0.0)
            severity = "critical" if len(resources) >= 3 else "high"
            _make_finding(
                findings,
                "golden_ticket_privileged_token_overreach",
                "Privileged-looking token appears reusable beyond a narrow workflow",
                severity,
                min(score, 0.91),
                "multi-resource" if len(resources) >= 2 else (resources[0] if resources else "unknown"),
                endpoints,
                [
                    "token={}".format(token_id),
                    "markers={}".format(",".join(markers[:6])),
                    "write_success_samples={}".format(write_success),
                    "resource_count={}".format(len(resources)),
                ],
                [
                    "Try least-privilege token substitution for same write endpoints.",
                    "Confirm role/scope checks at object-level authorization gates.",
                ],
            )

        if scheme.startswith("bearer") and jwt_claims:
            exp = _safe_int(jwt_claims.get("exp"))
            iat = _safe_int(jwt_claims.get("iat"))
            ttl_seconds = None
            if exp is not None and iat is not None and exp > iat:
                ttl_seconds = exp - iat

            if exp is None:
                _make_finding(
                    findings,
                    "golden_ticket_missing_expiry_claim",
                    "Bearer token lacks explicit expiry claim (exp)",
                    "medium",
                    0.66,
                    "multi-resource" if len(resources) >= 2 else (resources[0] if resources else "unknown"),
                    endpoints,
                    [
                        "token={}".format(token_id),
                        "jwt_claims=exp_missing",
                        "resource_count={}".format(len(resources)),
                    ],
                    [
                        "Enforce short-lived access tokens with required exp claim.",
                        "Verify server rejects stale tokens without relying on client logout only.",
                    ],
                )
            elif ttl_seconds is not None and ttl_seconds >= 86400 * 30:
                severity = "high" if ttl_seconds >= 86400 * 90 else "medium"
                _make_finding(
                    findings,
                    "golden_ticket_long_lived_token_window",
                    "Bearer token lifetime appears long for security-sensitive API access",
                    severity,
                    0.74 if severity == "high" else 0.69,
                    "multi-resource" if len(resources) >= 2 else (resources[0] if resources else "unknown"),
                    endpoints,
                    [
                        "token={}".format(token_id),
                        "jwt_ttl_seconds={}".format(ttl_seconds),
                        "resource_count={}".format(len(resources)),
                    ],
                    [
                        "Reduce token TTL and require refresh-token rotation controls.",
                        "Test whether revoked sessions can continue with old bearer token.",
                    ],
                )

            aud_claim = jwt_claims.get("aud")
            has_scope_claim = False
            for key in JWT_SCOPE_KEYS:
                value = jwt_claims.get(key)
                if value not in [None, "", [], {}]:
                    has_scope_claim = True
                    break
            if (not aud_claim) and (not has_scope_claim) and success_count >= 2 and len(resources) >= 2:
                _make_finding(
                    findings,
                    "golden_ticket_unbound_jwt_claims",
                    "Bearer token observed without clear audience/scope binding across resources",
                    "medium",
                    0.68,
                    "multi-resource",
                    endpoints,
                    [
                        "token={}".format(token_id),
                        "aud_missing=True",
                        "scope_missing=True",
                        "resource_count={}".format(len(resources)),
                    ],
                    [
                        "Bind token validation to explicit audience + scope requirements.",
                        "Verify one token cannot authorize unrelated service/domain actions.",
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
    return findings[:300]


def build_golden_ticket_package(data_snapshot, get_entry=None):
    """Build Golden Ticket package from captured token behavior."""
    observations = _collect_token_observations(data_snapshot, get_entry=get_entry)
    findings = build_golden_ticket_findings(data_snapshot, get_entry=get_entry)
    ledger = _build_evidence_ledger(findings)
    ledger["analysis_type"] = "golden_ticket"
    ledger["coverage"] = {
        "observed_tokens": len(observations),
        "tokens_with_write_activity": len(
            [x for x in observations.values() if x.get("write_success_count", 0) > 0]
        ),
    }
    ledger["analyst_guidance"] = list(ledger.get("analyst_guidance", []) or []) + [
        "Prioritize tokens that cross resource boundaries with successful write behavior.",
    ]
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finding_count": len(findings),
        "observed_token_count": len(observations),
        "findings": findings,
        "ledger": ledger,
    }
