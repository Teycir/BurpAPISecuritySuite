# -*- coding: utf-8 -*-
import json
import re

from java.io import FileWriter
from java.text import SimpleDateFormat
from java.util import Date


RECON_HIDDEN_PARAM_SEEDS = (
    "admin",
    "is_admin",
    "role",
    "roles",
    "permission",
    "permissions",
    "scope",
    "scopes",
    "access",
    "access_token",
    "api_key",
    "apikey",
    "token",
    "refresh_token",
    "secret",
    "client_id",
    "client_secret",
    "tenant",
    "tenant_id",
    "org_id",
    "user_id",
    "account_id",
    "owner_id",
    "debug",
    "verbose",
    "trace",
    "internal",
    "test",
    "dev_mode",
    "callback",
    "redirect",
    "return_url",
    "next",
    "dest",
    "destination",
    "limit",
    "offset",
    "page",
    "sort",
    "filter",
    "fields",
    "include",
    "expand",
    "format",
    "lang",
    "locale",
    "status",
    "active",
    "enabled",
    "price",
    "amount",
    "quantity",
    "coupon",
    "discount",
    "currency",
)

RECON_PARAM_WORD_STOPLIST = (
    "api",
    "rest",
    "graphql",
    "http",
    "https",
    "json",
    "xml",
    "www",
    "com",
    "net",
    "org",
    "path",
    "query",
    "body",
    "header",
    "cookie",
    "request",
    "response",
    "value",
    "true",
    "false",
    "null",
    "this",
    "that",
    "from",
    "with",
    "without",
    "items",
    "item",
    "list",
    "data",
)


def iter_recon_param_items(extender, entry):
    """Yield normalized (source, name, value_preview) tuples from one entry."""
    param_block = entry.get("parameters", {}) or {}
    for source_name in ["url", "body", "json", "cookie"]:
        raw_items = param_block.get(source_name, {})
        if isinstance(raw_items, dict):
            iterator = raw_items.items()
        elif isinstance(raw_items, list):
            iterator = [(name, "") for name in raw_items]
        else:
            iterator = []

        for raw_name, raw_value in iterator:
            name = extender._ascii_safe(raw_name, lower=True).strip()
            if not name:
                continue
            if len(name) > 64:
                name = name[:64]
            value = extender._ascii_safe(raw_value, max_len=180).strip()
            yield source_name, name, value


def tokenize_recon_words(extender, text, max_terms=200):
    """Extract candidate parameter words from free text safely."""
    stop_words = set([extender._ascii_safe(x, lower=True) for x in RECON_PARAM_WORD_STOPLIST])
    words = set()
    body = extender._ascii_safe(text or "", lower=True)
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,32}", body):
        clean = extender._ascii_safe(token, lower=True).strip()
        if not clean:
            continue
        if clean in stop_words:
            continue
        if clean.startswith("http"):
            continue
        if clean.isdigit():
            continue
        words.add(clean)
        if len(words) >= int(max_terms):
            break
    return words


def collect_hidden_param_candidates(extender, data_to_scan):
    """Build candidate hidden parameter name pool from seeds + observed traffic words."""
    stop_words = set([extender._ascii_safe(x, lower=True) for x in RECON_PARAM_WORD_STOPLIST])
    candidates = set([extender._ascii_safe(x, lower=True) for x in RECON_HIDDEN_PARAM_SEEDS])

    for endpoint_key, entries in data_to_scan.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        entry = extender._get_entry(entries_list)
        normalized = extender._normalize_endpoint_data(entry)
        path = extender._ascii_safe(normalized.get("path") or "/", lower=True)
        query = extender._ascii_safe(entry.get("query_string") or "", lower=True)
        endpoint_text = "{} {} {}".format(extender._ascii_safe(endpoint_key, lower=True), path, query)
        candidates.update(tokenize_recon_words(extender, endpoint_text, max_terms=120))

        for sample in entries_list[:5]:
            for _src, name, _value in iter_recon_param_items(extender, sample):
                candidates.add(name)

            request_body = extender._ascii_safe(sample.get("request_body") or "", lower=True)
            candidates.update(tokenize_recon_words(extender, request_body, max_terms=120))

            parsed_body = extender._parse_json_loose(sample.get("request_body", ""))
            if parsed_body is not None:
                json_paths = set()
                extender._flatten_json_paths(parsed_body, "", json_paths, 0)
                for path_text in list(json_paths)[:200]:
                    cleaned_path = re.sub(
                        r"[^a-z0-9_.]", "", extender._ascii_safe(path_text, lower=True)
                    )
                    if not cleaned_path:
                        continue
                    for piece in cleaned_path.split("."):
                        token = extender._ascii_safe(piece, lower=True).strip()
                        token = re.sub(r"[^a-z0-9_]", "", token)
                        if len(token) < 3:
                            continue
                        if token in stop_words:
                            continue
                        candidates.add(token)

    ordered = []
    seen = set()
    for raw_name in sorted(candidates):
        name = re.sub(r"[^a-z0-9_]", "", extender._ascii_safe(raw_name, lower=True))
        if not name:
            continue
        if len(name) < 3 or len(name) > 40:
            continue
        if name in stop_words:
            continue
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return ordered


def score_hidden_param_candidate(extender, normalized_entry, candidate):
    """Score one candidate parameter against endpoint context."""
    name = extender._ascii_safe(candidate, lower=True).strip()
    path = extender._ascii_safe(normalized_entry.get("path") or "/", lower=True)
    method = extender._ascii_safe(normalized_entry.get("method") or "GET").upper()
    score = 0
    reasons = []

    if any(
        marker in name
        for marker in ["admin", "role", "permission", "scope", "privilege"]
    ):
        score += 4
        reasons.append("access-control keyword")

    if any(
        marker in name for marker in ["token", "secret", "key", "password", "jwt"]
    ):
        score += 4
        reasons.append("credential-like keyword")

    if any(marker in name for marker in ["debug", "verbose", "trace", "internal", "dev", "test"]):
        score += 3
        reasons.append("debug/internal keyword")

    if method in ["POST", "PUT", "PATCH", "DELETE"]:
        score += 1
        if name in ["_method", "override", "is_admin", "role", "permissions"]:
            score += 2
            reasons.append("write-operation sensitive field")

    if re.search(r"/{id}|/{uuid}|/{objectid}", path) and any(
        marker in name for marker in ["id", "owner", "user", "account", "tenant"]
    ):
        score += 2
        reasons.append("identifier-oriented route")

    if any(marker in path for marker in ["/auth", "/login", "/token", "/oauth"]) and any(
        marker in name for marker in ["client", "secret", "scope", "redirect", "code", "state"]
    ):
        score += 2
        reasons.append("auth-flow alignment")

    if any(marker in path for marker in ["/user", "/account", "/profile", "/admin"]) and any(
        marker in name for marker in ["role", "admin", "permission", "user_id", "account_id"]
    ):
        score += 2
        reasons.append("identity endpoint alignment")

    if any(marker in path for marker in ["/payment", "/order", "/checkout", "/invoice"]) and any(
        marker in name for marker in ["price", "amount", "discount", "coupon", "currency"]
    ):
        score += 2
        reasons.append("transaction endpoint alignment")

    if name.endswith("_id") or name in ["id", "uuid", "objectid"]:
        score += 1
        reasons.append("identifier pattern")

    return score, reasons


def run_recon_hidden_params_for_scope(extender, scope_label, data_to_scan):
    """Run Param Miner-style hidden parameter candidate generation for scoped data."""
    if not data_to_scan:
        extender.log_to_ui("[!] Hidden Params: no endpoints in selected scope")
        return

    candidate_pool = collect_hidden_param_candidates(extender, data_to_scan)
    if not candidate_pool:
        extender.log_to_ui("[!] Hidden Params: candidate pool is empty")
        return

    findings = []
    lines = []
    lines.append("RECON HIDDEN PARAMS")
    lines.append("=" * 80)
    lines.append("[*] Scope: {}".format(extender._ascii_safe(scope_label)))
    lines.append("[*] Endpoints in scope: {}".format(len(data_to_scan)))
    lines.append("[*] Candidate pool: {}".format(len(candidate_pool)))
    lines.append("")

    max_per_endpoint = 8
    for endpoint_key in sorted(data_to_scan.keys()):
        entries = data_to_scan.get(endpoint_key, [])
        entries_list = entries if isinstance(entries, list) else [entries]
        entry = extender._get_entry(entries_list)
        normalized = extender._normalize_endpoint_data(entry)

        existing = set()
        params = normalized.get("params", {}) or {}
        for source_name in ["url", "body", "json", "cookie"]:
            for param_name in params.get(source_name, []) or []:
                safe_name = extender._ascii_safe(param_name, lower=True).strip()
                if safe_name:
                    existing.add(safe_name)

        ranked = []
        for candidate in candidate_pool:
            if candidate in existing:
                continue
            score, reasons = score_hidden_param_candidate(extender, normalized, candidate)
            if score < 3:
                continue
            ranked.append((-score, candidate, reasons))

        ranked.sort(key=lambda item: (item[0], item[1]))
        top_ranked = ranked[:max_per_endpoint]
        if not top_ranked:
            continue

        candidate_rows = []
        for neg_score, candidate, reasons in top_ranked:
            candidate_rows.append(
                {
                    "name": candidate,
                    "score": int(-neg_score),
                    "reasons": list(reasons[:3]),
                }
            )

        findings.append(
            {
                "endpoint": extender._ascii_safe(endpoint_key),
                "method": extender._ascii_safe(normalized.get("method") or "GET").upper(),
                "path": extender._ascii_safe(normalized.get("path") or "/"),
                "existing_params": sorted(list(existing))[:20],
                "candidates": candidate_rows,
            }
        )

        lines.append("[ENDPOINT] {}".format(extender._ascii_safe(endpoint_key)))
        if existing:
            lines.append("  existing: {}".format(", ".join(sorted(list(existing))[:10])))
        else:
            lines.append("  existing: <none>")
        for row in candidate_rows:
            reason_text = ", ".join(row.get("reasons") or [])
            lines.append(
                "  suggest: {} (score={}){}".format(
                    row.get("name"),
                    row.get("score"),
                    " [{}]".format(reason_text) if reason_text else "",
                )
            )
        lines.append("")

        if len(lines) > 1000:
            lines.append("[*] Output truncated for readability")
            break

    extender.recon_hidden_param_results = list(findings)
    if not findings:
        lines.append("[+] No high-confidence hidden-parameter candidates found in scope.")
        extender.log_to_ui("[+] Hidden Params complete: no high-confidence candidates")
    else:
        lines.append("=" * 80)
        lines.append("[*] Endpoints with suggestions: {}".format(len(findings)))
        extender.log_to_ui(
            "[+] Hidden Params complete: {} endpoints with candidate parameters".format(
                len(findings)
            )
        )
    extender._show_text_dialog("Recon Hidden Params", "\n".join(lines))


def run_recon_hidden_params(extender):
    """Run hidden parameter candidate discovery from chosen Recon scope."""
    if not extender.api_data:
        extender.log_to_ui("[!] Hidden Params: no captured endpoints")
        return
    scope_label, data_to_scan = extender._select_export_scope_data("Hidden Params")
    if not data_to_scan:
        return
    run_recon_hidden_params_for_scope(extender, scope_label, data_to_scan)


def run_recon_hidden_params_selected(extender, endpoint_key):
    """Run hidden parameter candidate discovery for one selected endpoint."""
    with extender.lock:
        entries = extender.api_data.get(endpoint_key)
        if not entries:
            extender.log_to_ui("[!] Hidden Params: selected endpoint not found")
            return
        dataset = {endpoint_key: list(entries if isinstance(entries, list) else [entries])}
    run_recon_hidden_params_for_scope(extender, "Selected Endpoint", dataset)


def param_risk_hint(extender, param_name):
    """Return a simple risk hint label for a parameter name."""
    name = extender._ascii_safe(param_name, lower=True)
    if any(token in name for token in ["admin", "role", "permission", "scope", "privilege"]):
        return "authz-control"
    if any(token in name for token in ["token", "secret", "api_key", "apikey", "password", "jwt"]):
        return "credential"
    if any(token in name for token in ["debug", "verbose", "trace", "internal", "test", "dev"]):
        return "debug-surface"
    if any(token in name for token in ["redirect", "callback", "return_url", "next", "dest"]):
        return "redirect-flow"
    if any(token in name for token in ["price", "amount", "discount", "coupon", "currency"]):
        return "business-logic"
    return ""


def collect_recon_param_intelligence(extender, data_to_scan):
    """Build GAP-style parameter intelligence summary from scoped Recon data."""
    intel_map = {}
    total_observations = 0

    for endpoint_key, entries in data_to_scan.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        base_entry = extender._get_entry(entries_list)
        host = extender._ascii_safe(base_entry.get("host") or "", lower=True).strip()
        for sample in entries_list:
            for source_name, name, value in iter_recon_param_items(extender, sample):
                total_observations += 1
                if name not in intel_map:
                    intel_map[name] = {
                        "total_seen": 0,
                        "sources": set(),
                        "endpoints": set(),
                        "hosts": set(),
                        "examples": [],
                    }
                slot = intel_map[name]
                slot["total_seen"] += 1
                slot["sources"].add(source_name)
                slot["endpoints"].add(endpoint_key)
                if host:
                    slot["hosts"].add(host)
                if value and value not in slot["examples"] and len(slot["examples"]) < 4:
                    slot["examples"].append(value[:100])

    rows = []
    for name, slot in intel_map.items():
        sources = sorted(list(slot["sources"]))
        endpoint_samples = sorted([extender._ascii_safe(x) for x in slot["endpoints"]])[:8]
        host_samples = sorted([extender._ascii_safe(x) for x in slot["hosts"]])[:8]
        rows.append(
            {
                "name": extender._ascii_safe(name, lower=True),
                "total_seen": int(slot["total_seen"]),
                "endpoint_count": len(slot["endpoints"]),
                "host_count": len(slot["hosts"]),
                "sources": sources,
                "sample_endpoints": endpoint_samples,
                "sample_hosts": host_samples,
                "examples": list(slot["examples"]),
                "risk_hint": param_risk_hint(extender, name),
            }
        )

    rows.sort(
        key=lambda row: (
            -int(row.get("endpoint_count", 0)),
            -int(row.get("total_seen", 0)),
            extender._ascii_safe(row.get("name") or ""),
        )
    )
    multi_source = len([row for row in rows if len(row.get("sources", [])) > 1])
    risky = len([row for row in rows if row.get("risk_hint")])

    return {
        "generated_at": SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date()),
        "total_unique_names": len(rows),
        "total_observations": int(total_observations),
        "multi_source_names": int(multi_source),
        "risk_hint_names": int(risky),
        "parameters": rows,
    }


def build_recon_param_intel_report(extender, scope_label, intel_payload):
    """Render human-readable GAP-like parameter intelligence report."""
    rows = intel_payload.get("parameters", []) or []
    lines = []
    lines.append("RECON PARAM INTEL")
    lines.append("=" * 80)
    lines.append("[*] Scope: {}".format(extender._ascii_safe(scope_label)))
    lines.append("[*] Generated: {}".format(extender._ascii_safe(intel_payload.get("generated_at"))))
    lines.append("[*] Unique Names: {}".format(int(intel_payload.get("total_unique_names", 0) or 0)))
    lines.append(
        "[*] Observations: {} | Multi-Source: {} | Risk-Hinted: {}".format(
            int(intel_payload.get("total_observations", 0) or 0),
            int(intel_payload.get("multi_source_names", 0) or 0),
            int(intel_payload.get("risk_hint_names", 0) or 0),
        )
    )
    lines.append("")

    if not rows:
        lines.append("[+] No parameter intelligence found in selected scope.")
        return "\n".join(lines)

    lines.append("Top Parameters")
    lines.append("-" * 80)
    for idx, row in enumerate(rows[:120]):
        lines.append(
            "{:03d}. {} | hits={} endpoints={} hosts={} sources={}".format(
                idx + 1,
                extender._ascii_safe(row.get("name")),
                int(row.get("total_seen", 0) or 0),
                int(row.get("endpoint_count", 0) or 0),
                int(row.get("host_count", 0) or 0),
                ",".join([extender._ascii_safe(x) for x in (row.get("sources") or [])]),
            )
        )
        if row.get("risk_hint"):
            lines.append("     risk: {}".format(extender._ascii_safe(row.get("risk_hint"))))
        examples = row.get("examples") or []
        if examples:
            lines.append(
                "     examples: {}".format(
                    ", ".join([extender._ascii_safe(x, max_len=40) for x in examples[:3]])
                )
            )
    return "\n".join(lines)


def run_recon_param_intel(extender):
    """Build and display GAP-style parameter intelligence from Recon scope."""
    if not extender.api_data:
        extender.log_to_ui("[!] Param Intel: no captured endpoints")
        return
    scope_label, data_to_scan = extender._select_export_scope_data("Param Intel")
    if not data_to_scan:
        return

    intel_payload = collect_recon_param_intelligence(extender, data_to_scan)
    report_text = build_recon_param_intel_report(extender, scope_label, intel_payload)
    extender.recon_param_intel_snapshot = {
        "scope": extender._ascii_safe(scope_label),
        "intel": intel_payload,
        "report": report_text,
    }
    extender._show_text_dialog("Recon Param Intel", report_text)
    extender.log_to_ui(
        "[+] Param Intel complete: {} unique parameters".format(
            int(intel_payload.get("total_unique_names", 0) or 0)
        )
    )


def export_recon_param_intel(extender):
    """Export the last GAP-style parameter intelligence snapshot."""
    snapshot = extender.recon_param_intel_snapshot
    if not snapshot:
        extender.log_to_ui("[!] Export Param Intel: run Param Intel first")
        return

    export_dir = extender._get_export_dir("Recon_ParamIntel")
    if not export_dir:
        extender.log_to_ui("[!] Export Param Intel: cannot create export directory")
        return

    import os

    files_to_write = {
        os.path.join(export_dir, "param_intel.json"): json.dumps(snapshot, indent=2),
        os.path.join(export_dir, "param_intel_report.txt"): extender._ascii_safe(
            snapshot.get("report") or ""
        ),
    }

    for filepath, content in files_to_write.items():
        writer = None
        try:
            writer = FileWriter(filepath)
            writer.write(content)
        except Exception as e:
            extender._callbacks.printError(
                "Param Intel export write failed ({}): {}".format(filepath, str(e))
            )
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    extender._callbacks.printError(
                        "Param Intel export close failed ({}): {}".format(
                            filepath, str(e)
                        )
                    )

    extender.log_to_ui("[+] Param Intel export complete")
    extender.log_to_ui("[+] Folder: {}".format(export_dir))
