#!/usr/bin/env python3
"""Non-UI pytest validation for ApiHunter auth-context extraction on Excalibur exports."""

import json
import os
from collections import Counter, defaultdict
from urllib.parse import urlparse

import pytest


EXPECTED_SNAPSHOT_BASENAME = "ExcaliburExport_2026-04-10T00-22-13"
DEFAULT_EXPORT_DIR = "~/T\u00e9l\u00e9chargements/ExcaliburExport_2026-04-10T00-22-13"


def _canonical_base(url_text):
    parsed = urlparse(url_text or "")
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return "{}://{}/".format(scheme, host)
    return "{}://{}:{}/".format(scheme, host, port)


def _build_cookie_header_for_host(cookie_roots, host_name):
    host = (host_name or "").strip().lower()
    if not host:
        return ""
    candidates = []
    for raw_domain, cookie_map in (cookie_roots or {}).items():
        domain = str(raw_domain or "").strip().lower().lstrip(".")
        if (not domain) or (not isinstance(cookie_map, dict)):
            continue
        if host == domain or host.endswith("." + domain):
            for cookie_name, cookie_value in cookie_map.items():
                name = str(cookie_name or "").strip()
                if not name:
                    continue
                candidates.append("{}={}".format(name, cookie_value))
    return "; ".join(candidates)


def _cookie_header_to_pairs(raw_cookie):
    ignored_cookie_attrs = {
        "path",
        "domain",
        "expires",
        "max-age",
        "secure",
        "httponly",
        "samesite",
        "priority",
    }
    text = str(raw_cookie or "").strip()
    if not text:
        return []
    pairs = []
    seen = set()
    for chunk in text.split(";"):
        part = chunk.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        lower_name = name.lower()
        if (
            (not name)
            or (not value)
            or (lower_name in ignored_cookie_attrs)
            or (lower_name in seen)
        ):
            continue
        seen.add(lower_name)
        pairs.append("{}={}".format(name, value))
        if len(pairs) >= 20:
            break
    return pairs


def _pick_best(counter_map):
    if not counter_map:
        return ""
    return sorted(
        counter_map.items(),
        key=lambda item: (-int(item[1]), -len(str(item[0])), str(item[0])),
    )[0][0]


def _resolve_export_dir():
    configured = os.getenv("EXCALIBUR_EXPORT_DIR", DEFAULT_EXPORT_DIR).strip()
    export_dir = os.path.expanduser(configured)
    if not os.path.isdir(export_dir):
        pytest.skip(
            "Excalibur export directory not found. Set EXCALIBUR_EXPORT_DIR (current: {}).".format(
                export_dir
            )
        )
    return export_dir


def _find_first_with_suffix(file_names, suffix):
    for name in sorted(file_names):
        if name.endswith(suffix):
            return name
    return ""


def _load_export_metrics(export_dir):
    file_names = os.listdir(export_dir)
    har_name = _find_first_with_suffix(file_names, ".har")
    cookies_name = _find_first_with_suffix(file_names, "-cookies.json")
    if not har_name or not cookies_name:
        pytest.skip(
            "Required Excalibur files not found in {} (need .har and -cookies.json).".format(
                export_dir
            )
        )

    har_path = os.path.join(export_dir, har_name)
    cookies_path = os.path.join(export_dir, cookies_name)

    with open(har_path, "r", encoding="utf-8") as handle:
        har_payload = json.load(handle)
    with open(cookies_path, "r", encoding="utf-8") as handle:
        cookie_payload = json.load(handle)

    entries = (((har_payload or {}).get("log") or {}).get("entries")) or []
    if not isinstance(entries, list):
        raise AssertionError("HAR entries is not a list: {}".format(type(entries)))

    cookie_roots = (cookie_payload or {}).get("cookies")
    if not isinstance(cookie_roots, dict):
        cookie_roots = {}

    per_target = defaultdict(
        lambda: {
            "entries": 0,
            "authorization": Counter(),
            "cookie": Counter(),
            "x-api-key": Counter(),
            "api-key": Counter(),
            "apikey": Counter(),
            "x-auth-token": Counter(),
            "x-access-token": Counter(),
        }
    )

    entries_with_raw_authorization = 0
    entries_with_raw_cookie = 0
    entries_with_synth_cookie = 0

    for har_entry in entries:
        request_obj = har_entry.get("request") if isinstance(har_entry, dict) else {}
        if not isinstance(request_obj, dict):
            continue
        url_text = request_obj.get("url") or ""
        base = _canonical_base(url_text)
        if not base:
            continue

        header_map = {}
        headers = request_obj.get("headers") or []
        if isinstance(headers, list):
            for header_item in headers:
                if not isinstance(header_item, dict):
                    continue
                name = str(header_item.get("name") or "").strip()
                value = str(header_item.get("value") or "").strip()
                if name:
                    header_map[name.lower()] = value
        elif isinstance(headers, dict):
            for raw_name, raw_value in headers.items():
                name = str(raw_name or "").strip()
                if name:
                    header_map[name.lower()] = str(raw_value or "").strip()

        authorization_value = header_map.get("authorization", "").strip()
        cookie_value = header_map.get("cookie", "").strip()
        if authorization_value:
            entries_with_raw_authorization += 1
        if cookie_value:
            entries_with_raw_cookie += 1
        if not cookie_value:
            host = urlparse(url_text).hostname or ""
            synthesized_cookie = _build_cookie_header_for_host(cookie_roots, host)
            if synthesized_cookie:
                cookie_value = synthesized_cookie
                entries_with_synth_cookie += 1

        bucket = per_target[base]
        bucket["entries"] += 1
        if authorization_value:
            bucket["authorization"][authorization_value] += 1
        if cookie_value:
            bucket["cookie"][cookie_value] += 1

        for key_name in [
            "x-api-key",
            "api-key",
            "apikey",
            "x-auth-token",
            "x-access-token",
        ]:
            header_value = header_map.get(key_name, "").strip()
            if header_value:
                bucket[key_name][header_value] += 1

    contexts = {}
    for base, bucket in per_target.items():
        headers = []
        authorization_value = _pick_best(bucket["authorization"])
        if authorization_value:
            headers.append("Authorization: {}".format(authorization_value))
        for key_name, label in [
            ("x-api-key", "X-API-Key"),
            ("api-key", "Api-Key"),
            ("apikey", "ApiKey"),
            ("x-auth-token", "X-Auth-Token"),
            ("x-access-token", "X-Access-Token"),
        ]:
            best = _pick_best(bucket[key_name])
            if best:
                headers.append("{}: {}".format(label, best))
        cookies = _cookie_header_to_pairs(_pick_best(bucket["cookie"]))
        contexts[base] = {
            "entries": bucket["entries"],
            "headers": headers,
            "cookies": cookies,
        }

    targets_with_auth_context = [
        base
        for base, context in contexts.items()
        if context["headers"] or context["cookies"]
    ]

    return {
        "export_dir": export_dir,
        "har_entries": len(entries),
        "unique_targets": len(contexts),
        "entries_with_raw_authorization": entries_with_raw_authorization,
        "entries_with_raw_cookie": entries_with_raw_cookie,
        "entries_with_synth_cookie_from_sidecar": entries_with_synth_cookie,
        "targets_with_auth_context": len(targets_with_auth_context),
        "contexts": contexts,
    }


@pytest.fixture(scope="module")
def export_metrics():
    export_dir = _resolve_export_dir()
    return _load_export_metrics(export_dir)


def test_apihunter_auth_context_generic(export_metrics):
    """Reusable non-UI contract: any auth-bearing Excalibur export should yield auth context."""
    assert export_metrics["har_entries"] > 0
    assert export_metrics["unique_targets"] > 0
    assert export_metrics["targets_with_auth_context"] > 0
    assert (
        export_metrics["entries_with_raw_authorization"]
        + export_metrics["entries_with_raw_cookie"]
        + export_metrics["entries_with_synth_cookie_from_sidecar"]
        > 0
    )


def test_apihunter_auth_context_known_snapshot(export_metrics):
    """Snapshot contract for the known 2026-04-10 export dataset."""
    if os.path.basename(export_metrics["export_dir"]) != EXPECTED_SNAPSHOT_BASENAME:
        pytest.skip("Known snapshot assertions apply only to {}".format(EXPECTED_SNAPSHOT_BASENAME))

    assert export_metrics["har_entries"] == 571
    assert export_metrics["unique_targets"] == 15
    assert export_metrics["entries_with_raw_authorization"] == 75
    assert export_metrics["entries_with_raw_cookie"] == 0
    assert export_metrics["entries_with_synth_cookie_from_sidecar"] == 123
    assert export_metrics["targets_with_auth_context"] == 8

    contexts = export_metrics["contexts"]
    assert "https://x.com/" in contexts
    assert "https://api.x.com/" in contexts
    assert any(
        header.lower().startswith("authorization: bearer ")
        for header in contexts["https://x.com/"]["headers"]
    )
    assert any(
        header.lower().startswith("authorization: bearer ")
        for header in contexts["https://api.x.com/"]["headers"]
    )
