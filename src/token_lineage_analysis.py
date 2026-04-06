# -*- coding: utf-8 -*-
"""Token Lineage analysis for session/revocation/rotation drift patterns."""

import base64
import hashlib
import json
import re
import time


WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
TERMINATION_PATH_MARKERS = (
    "/logout",
    "/signout",
    "/revoke",
    "/invalidate",
    "/session/end",
    "/session/kill",
)
REFRESH_PATH_MARKERS = (
    "/refresh",
    "/token/refresh",
    "/session/refresh",
    "/renew",
)
PROTECTED_PATH_HINTS = (
    "/api/",
    "/graphql",
    "/admin",
    "/account",
    "/profile",
    "/billing",
    "/payment",
    "/order",
    "/transfer",
    "/wallet",
)
SESSION_COOKIE_HINTS = ("session", "token", "auth", "jwt", "sid", "access")
SUBJECT_CLAIM_KEYS = ("sub", "user_id", "uid", "account_id", "tenant", "session_id")


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


def _subject_fingerprint(claims, scheme, token_fingerprint):
    claims_obj = claims if isinstance(claims, dict) else {}
    for key in SUBJECT_CLAIM_KEYS:
        value = claims_obj.get(key)
        if value is None:
            continue
        text = _text(value, lower=True).strip()
        if text:
            return "{}:{}".format(key, text[:48])
    return "{}:{}".format(_text(scheme, lower=True), _text(token_fingerprint))


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
            if not any(marker in key_norm for marker in SESSION_COOKIE_HINTS):
                continue
            extracted.append(
                {
                    "scheme": "cookie:{}".format(key_norm[:24]),
                    "token": val_norm,
                    "jwt_claims": _decode_jwt_claims(val_norm),
                }
            )
    return extracted[:8]


def _is_success(status_code):
    value = int(status_code or 0)
    return 200 <= value < 300


def _is_termination_surface(path_text, method_text):
    path = _text(path_text, lower=True)
    method = _text(method_text).upper()
    if method not in ["POST", "DELETE", "PATCH", "PUT"]:
        return False
    return any(marker in path for marker in TERMINATION_PATH_MARKERS)


def _is_refresh_surface(path_text, method_text):
    path = _text(path_text, lower=True)
    method = _text(method_text).upper()
    if method not in ["POST", "PATCH", "PUT"]:
        return False
    return any(marker in path for marker in REFRESH_PATH_MARKERS)


def _is_protected_surface(path_text, method_text):
    path = _text(path_text, lower=True)
    method = _text(method_text).upper()
    if method in WRITE_METHODS:
        return True
    return any(marker in path for marker in PROTECTED_PATH_HINTS)


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
    subject,
    endpoints,
    evidence,
    suggested_checks,
):
    finding = {
        "id": "tlineage-{0:03d}".format(len(findings) + 1),
        "category": "TOKEN_LINEAGE",
        "invariant": _text(invariant_name),
        "title": _text(title),
        "severity": _text(severity, lower=True),
        "confidence_score": round(float(score), 2),
        "confidence_label": _confidence_label(float(score)),
        "subject": _text(subject),
        "endpoint_scope": sorted(
            list(set([_text(x) for x in endpoints if _text(x).strip()]))
        )[:20],
        "evidence": [_text(x) for x in (evidence or []) if _text(x).strip()][:12],
        "suggested_checks": [
            _text(x) for x in (suggested_checks or []) if _text(x).strip()
        ][:10],
        "non_destructive": True,
    }
    findings.append(finding)


def _collect_token_lineage(data_snapshot, get_entry=None):
    get_entry_fn = get_entry if callable(get_entry) else _first_entry
    tokens = {}
    subjects = {}

    for endpoint_key, entries in (data_snapshot or {}).items():
        canonical = get_entry_fn(entries)
        fallback_method = _text(canonical.get("method") or "").upper()
        fallback_path = _text(
            canonical.get("normalized_path") or canonical.get("path") or "/"
        )

        for sample in _iter_entries(entries):
            method = _text(sample.get("method") or fallback_method).upper()
            path = _text(sample.get("normalized_path") or sample.get("path") or fallback_path)
            status = _safe_int(sample.get("response_status", 0) or 0) or 0
            success = _is_success(status)
            resource = _path_to_resource(path)
            termination = _is_termination_surface(path, method) and success
            refresh = _is_refresh_surface(path, method) and success
            protected_success = _is_protected_surface(path, method) and success

            token_items = _extract_auth_tokens(sample)
            for token_item in token_items:
                scheme = _text(token_item.get("scheme"), lower=True)
                raw_token = _text(token_item.get("token"))
                fingerprint = _token_fingerprint(raw_token)
                if not scheme or not fingerprint:
                    continue
                token_id = "{}:{}".format(scheme, fingerprint)
                claims = token_item.get("jwt_claims", {}) or {}
                subject = _subject_fingerprint(claims, scheme, fingerprint)

                if token_id not in tokens:
                    tokens[token_id] = {
                        "token_id": token_id,
                        "scheme": scheme,
                        "subject": subject,
                        "resources": set(),
                        "endpoints": set(),
                        "methods": set(),
                        "sample_count": 0,
                        "success_count": 0,
                        "protected_success_count": 0,
                        "termination_success_count": 0,
                        "refresh_success_count": 0,
                        "write_success_count": 0,
                    }
                token = tokens[token_id]
                token["resources"].add(resource)
                token["endpoints"].add(_text(endpoint_key))
                token["methods"].add(method)
                token["sample_count"] += 1
                if success:
                    token["success_count"] += 1
                if protected_success:
                    token["protected_success_count"] += 1
                if termination:
                    token["termination_success_count"] += 1
                if refresh:
                    token["refresh_success_count"] += 1
                if success and method in WRITE_METHODS:
                    token["write_success_count"] += 1

                if subject not in subjects:
                    subjects[subject] = {
                        "token_ids": set(),
                        "resources": {},
                        "termination_success_count": 0,
                        "refresh_success_count": 0,
                    }
                subject_record = subjects[subject]
                subject_record["token_ids"].add(token_id)
                if resource not in subject_record["resources"]:
                    subject_record["resources"][resource] = set()
                if protected_success:
                    subject_record["resources"][resource].add(token_id)
                if termination:
                    subject_record["termination_success_count"] += 1
                if refresh:
                    subject_record["refresh_success_count"] += 1

    return tokens, subjects


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
            "Prioritize findings where logout/revoke and protected access both succeed for same token lineage.",
            "Use token lineage as hypothesis evidence, then validate with controlled replay.",
            "Treat token fingerprints as correlation handles, not exploit proof.",
        ],
        "findings": items,
    }


def build_token_lineage_findings(data_snapshot, get_entry=None):
    """Detect token/session lineage drift patterns from captured traffic."""
    tokens, subjects = _collect_token_lineage(data_snapshot, get_entry=get_entry)
    findings = []

    for token_id in sorted(tokens.keys()):
        item = tokens[token_id]
        if (
            int(item.get("termination_success_count", 0) or 0) > 0
            and int(item.get("protected_success_count", 0) or 0) > 0
        ):
            _make_finding(
                findings,
                "token_termination_should_end_authorized_access",
                "Token observed on successful termination and successful protected access",
                "high",
                0.84,
                item.get("subject"),
                list(item.get("endpoints", set())),
                [
                    "token={}".format(token_id),
                    "termination_success_samples={}".format(
                        int(item.get("termination_success_count", 0) or 0)
                    ),
                    "protected_success_samples={}".format(
                        int(item.get("protected_success_count", 0) or 0)
                    ),
                ],
                [
                    "Replay protected request with token before/after logout-revoke flow.",
                    "Verify server-side session invalidation and cache eviction on termination.",
                ],
            )

    for subject in sorted(subjects.keys()):
        subject_item = subjects[subject]
        token_ids = set(subject_item.get("token_ids", set()))
        if len(token_ids) < 2:
            continue

        overlapping_resources = []
        for resource, resource_tokens in (subject_item.get("resources", {}) or {}).items():
            if len(resource_tokens) >= 2:
                overlapping_resources.append(resource)

        if (
            int(subject_item.get("refresh_success_count", 0) or 0) > 0
            and len(overlapping_resources) > 0
            and len(token_ids) >= 2
        ):
            _make_finding(
                findings,
                "refresh_rotation_should_sunset_older_tokens",
                "Refresh flow observed with overlapping protected access across multiple tokens",
                "high",
                0.79,
                subject,
                [],
                [
                    "subject_token_count={}".format(len(token_ids)),
                    "refresh_success_samples={}".format(
                        int(subject_item.get("refresh_success_count", 0) or 0)
                    ),
                    "overlap_resources={}".format(",".join(overlapping_resources[:6])),
                ],
                [
                    "Validate old access token rejection after refresh rotation.",
                    "Enforce one-time refresh semantics and token family revocation.",
                ],
            )

        if len(token_ids) >= 3 and len(overlapping_resources) >= 1:
            _make_finding(
                findings,
                "subject_token_sprawl_should_not_enable_parallel_privileged_access",
                "Multiple active token fingerprints map to same subject/resource surfaces",
                "medium",
                0.66,
                subject,
                [],
                [
                    "subject_token_count={}".format(len(token_ids)),
                    "resource_overlap_count={}".format(len(overlapping_resources)),
                    "overlap_resources={}".format(",".join(overlapping_resources[:6])),
                ],
                [
                    "Check whether stale or parallel sessions should be auto-revoked.",
                    "Apply token family limits and concurrent session controls per subject.",
                ],
            )

    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0)),
            _text(item.get("severity"), lower=True),
            _text(item.get("subject"), lower=True),
        )
    )
    return findings[:250]


def build_token_lineage_package(data_snapshot, get_entry=None):
    """Build Token Lineage package from captured traffic."""
    tokens, subjects = _collect_token_lineage(data_snapshot, get_entry=get_entry)
    findings = build_token_lineage_findings(data_snapshot, get_entry=get_entry)
    ledger = _build_evidence_ledger(findings)
    ledger["analysis_type"] = "token_lineage"
    ledger["observation_summary"] = {
        "observed_token_count": len(tokens),
        "observed_subject_count": len(subjects),
        "subjects_with_termination_events": len(
            [
                1
                for item in subjects.values()
                if int(item.get("termination_success_count", 0) or 0) > 0
            ]
        ),
        "subjects_with_refresh_events": len(
            [
                1
                for item in subjects.values()
                if int(item.get("refresh_success_count", 0) or 0) > 0
            ]
        ),
    }
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "observed_token_count": len(tokens),
        "observed_subject_count": len(subjects),
        "finding_count": len(findings),
        "findings": findings,
        "ledger": ledger,
    }
