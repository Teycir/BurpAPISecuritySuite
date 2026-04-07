# -*- coding: utf-8 -*-
"""Additive AI prep artifacts for post-collection triage."""

import time

AI_PREP_MAX_HINTS = 300
AI_PREP_MAX_SEQUENCE_CANDIDATES = 220
AI_PREP_MAX_GRAPH_NODES = 900
AI_PREP_MAX_GRAPH_EDGES = 2400


def build_ai_prep_layer(extender, data_snapshot, attacks_snapshot):
    """Build non-destructive AI prep artifacts for post-collection triage."""
    invariant_hints = build_ai_prep_invariant_hints(extender, data_snapshot)
    sequence_candidates = build_ai_prep_sequence_candidates(extender, data_snapshot)
    evidence_graph = build_ai_prep_evidence_graph(
        extender, data_snapshot, attacks_snapshot
    )
    payload = {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "notes": [
            "Additive export-only layer.",
            "No endpoint filtering or suppression is applied in runtime scanning.",
            "Use these artifacts for AI/human prioritization, not as hard exclusion gates.",
        ],
        "invariant_hints": invariant_hints,
        "sequence_candidates": sequence_candidates,
        "evidence_graph": evidence_graph,
        "truncation": {
            "hints": int(invariant_hints.get("truncated_hints", 0) or 0),
            "sequence_candidates": int(
                sequence_candidates.get("truncated_candidates", 0) or 0
            ),
            "graph_nodes": int(evidence_graph.get("truncated_nodes", 0) or 0),
            "graph_edges": int(evidence_graph.get("truncated_edges", 0) or 0),
        },
    }
    payload["truncation"]["total_truncated"] = (
        int(payload["truncation"].get("hints", 0) or 0)
        + int(payload["truncation"].get("sequence_candidates", 0) or 0)
        + int(payload["truncation"].get("graph_nodes", 0) or 0)
        + int(payload["truncation"].get("graph_edges", 0) or 0)
    )
    return extender._sanitize_for_ai_payload(payload)


def build_ai_prep_invariant_hints(extender, data_snapshot):
    """Infer business/workflow invariants auditors often miss in request-level review."""
    hints = []
    seen = set()

    def add_hint(hint_type, resource, statement, signals, endpoints):
        key = "{}|{}|{}".format(
            extender._ascii_safe(hint_type, lower=True),
            extender._ascii_safe(resource, lower=True),
            extender._ascii_safe(statement, lower=True),
        )
        if key in seen:
            return
        seen.add(key)
        hints.append(
            {
                "id": "inv-{:03d}".format(len(hints) + 1),
                "type": extender._ascii_safe(hint_type),
                "resource": extender._ascii_safe(resource),
                "statement": extender._ascii_safe(statement),
                "signals": extender._sanitize_for_ai_payload(signals or []),
                "endpoint_samples": extender._sanitize_for_ai_payload(
                    (endpoints or [])[:8]
                ),
            }
        )

    transitions = extender._analyze_state_transitions(data_snapshot)
    auth_matrix = extender._build_authz_matrix(data_snapshot)
    auth_by_endpoint = {
        extender._ascii_safe(item.get("endpoint")): list(item.get("auth_contexts", []) or [])
        for item in auth_matrix
        if isinstance(item, dict)
    }

    for item in transitions[:180]:
        resource = extender._ascii_safe(item.get("resource") or "resource")
        methods = [
            extender._ascii_safe(x).upper() for x in (item.get("methods", []) or [])
        ]
        endpoint_samples = item.get("sample_endpoints", []) or []
        write_methods = [
            x for x in methods if x in ["POST", "PUT", "PATCH", "DELETE"]
        ]
        if "GET" in methods and write_methods:
            add_hint(
                "state_consistency",
                resource,
                "Read-after-write should reflect consistent state for this resource.",
                ["methods={}".format(",".join(methods))],
                endpoint_samples,
            )
        if "DELETE" in methods and "GET" in methods:
            add_hint(
                "tombstone_access",
                resource,
                "Deleted objects should not remain readable across cache/replica delay.",
                ["delete+read path pair observed"],
                endpoint_samples,
            )
        if len(write_methods) >= 2:
            add_hint(
                "race_safety",
                resource,
                "Concurrent writes should preserve idempotency and monotonic state transitions.",
                ["multiple write methods: {}".format(",".join(write_methods))],
                endpoint_samples,
            )

    finance_tokens = [
        "amount",
        "price",
        "quantity",
        "total",
        "balance",
        "wallet",
        "credit",
        "debit",
        "refund",
        "discount",
        "coupon",
    ]
    lifecycle_tokens = [
        "status",
        "state",
        "approve",
        "cancel",
        "checkout",
        "payment",
        "transfer",
        "withdraw",
        "order",
        "subscription",
    ]
    resource_auth_modes = {}
    for endpoint_key, entries in data_snapshot.items():
        entry = extender._get_entry(entries)
        path = extender._ascii_safe(
            entry.get("normalized_path") or entry.get("path") or "/", lower=True
        )
        method = extender._ascii_safe(entry.get("method")).upper()
        resource = extender._split_path_segments(path)
        resource_name = resource[0] if resource else "root"
        params_lower = [
            extender._ascii_safe(x, lower=True)
            for x in extender._extract_param_names(entry)
        ]
        joined = " ".join([path] + params_lower)
        auth_contexts = [
            extender._ascii_safe(x, lower=True)
            for x in (auth_by_endpoint.get(extender._ascii_safe(endpoint_key), []) or [])
        ]
        mode = "protected"
        if (not auth_contexts) or ("none" in auth_contexts):
            mode = "public"
        if resource_name not in resource_auth_modes:
            resource_auth_modes[resource_name] = set()
        resource_auth_modes[resource_name].add(mode)

        if any(token in joined for token in finance_tokens):
            add_hint(
                "financial_integrity",
                resource_name,
                "Amount/quantity related changes should preserve business invariants (no negative or drifted totals).",
                ["method={}".format(method)],
                [endpoint_key],
            )
        if any(token in joined for token in lifecycle_tokens) and method in [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]:
            add_hint(
                "lifecycle_integrity",
                resource_name,
                "State transitions should only allow valid next-state moves and role-appropriate actions.",
                ["lifecycle token + write method"],
                [endpoint_key],
            )

    for resource_name, modes in resource_auth_modes.items():
        if "public" in modes and "protected" in modes:
            add_hint(
                "auth_boundary",
                resource_name,
                "Public and protected variants for this resource should not leak cross-context data.",
                ["mixed auth surface detected"],
                [],
            )

    hints_total = len(hints)
    hints_trimmed = max(0, hints_total - AI_PREP_MAX_HINTS)
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_hints": hints_total,
        "max_hints": AI_PREP_MAX_HINTS,
        "truncated_hints": hints_trimmed,
        "hints": hints[:AI_PREP_MAX_HINTS],
    }


def build_ai_prep_sequence_candidates(extender, data_snapshot):
    """Generate adversarial multi-step sequences for deep logic abuse testing."""
    candidates = []
    transitions = extender._analyze_state_transitions(data_snapshot)
    auth_matrix = extender._build_authz_matrix(data_snapshot)
    auth_by_endpoint = {
        extender._ascii_safe(item.get("endpoint")): list(item.get("auth_contexts", []) or [])
        for item in auth_matrix
        if isinstance(item, dict)
    }

    for item in transitions[:140]:
        resource = extender._ascii_safe(item.get("resource") or "resource")
        methods = [
            extender._ascii_safe(x).upper() for x in (item.get("methods", []) or [])
        ]
        samples = list(item.get("sample_endpoints", []) or [])[:8]

        if "POST" in methods and "GET" in methods:
            candidates.append(
                {
                    "id": "seq-{:03d}".format(len(candidates) + 1),
                    "resource": resource,
                    "name": "Create-then-read consistency",
                    "steps": [
                        "Create object via POST endpoint",
                        "Read object via GET endpoint under same identity",
                        "Read object under alternate auth context",
                    ],
                    "expected_invariants": [
                        "owner-scoped visibility",
                        "stable object state after creation",
                    ],
                    "endpoint_samples": samples,
                }
            )
        if ("GET" in methods) and any(x in methods for x in ["PUT", "PATCH"]):
            candidates.append(
                {
                    "id": "seq-{:03d}".format(len(candidates) + 1),
                    "resource": resource,
                    "name": "Read-modify-read authorization",
                    "steps": [
                        "Read existing object",
                        "Modify object fields via PUT/PATCH",
                        "Re-read as owner and non-owner",
                    ],
                    "expected_invariants": [
                        "only authorized identities can mutate",
                        "unauthorized updates do not persist",
                    ],
                    "endpoint_samples": samples,
                }
            )
        if "DELETE" in methods and "GET" in methods:
            candidates.append(
                {
                    "id": "seq-{:03d}".format(len(candidates) + 1),
                    "resource": resource,
                    "name": "Delete-orphan access check",
                    "steps": [
                        "Delete object",
                        "Immediate re-fetch attempts",
                        "Delayed re-fetch attempts after cache interval",
                    ],
                    "expected_invariants": [
                        "deleted object remains inaccessible",
                        "no stale replica resurrection",
                    ],
                    "endpoint_samples": samples,
                }
            )
        if int(item.get("write_method_count", 0) or 0) >= 2:
            candidates.append(
                {
                    "id": "seq-{:03d}".format(len(candidates) + 1),
                    "resource": resource,
                    "name": "Concurrent write race probe",
                    "steps": [
                        "Issue parallel write requests with conflicting values",
                        "Replay stale update after newer state",
                        "Verify final state and audit trail fields",
                    ],
                    "expected_invariants": [
                        "deterministic final state",
                        "idempotency/replay protections hold",
                    ],
                    "endpoint_samples": samples,
                }
            )

        mixed_auth = False
        auth_values = set()
        for endpoint_key in samples:
            for auth_type in auth_by_endpoint.get(extender._ascii_safe(endpoint_key), []):
                auth_values.add(extender._ascii_safe(auth_type, lower=True))
        if auth_values and ("none" in auth_values) and (len(auth_values) >= 2):
            mixed_auth = True
        if mixed_auth:
            candidates.append(
                {
                    "id": "seq-{:03d}".format(len(candidates) + 1),
                    "resource": resource,
                    "name": "Cross-context replay and escalation",
                    "steps": [
                        "Capture request in stronger auth context",
                        "Replay same request with weaker/guest context",
                        "Swap object identifiers and compare response deltas",
                    ],
                    "expected_invariants": [
                        "privilege boundaries remain enforced",
                        "cross-account identifiers do not bypass checks",
                    ],
                    "endpoint_samples": samples,
                }
            )

    candidate_count = len(candidates)
    candidate_trimmed = max(0, candidate_count - AI_PREP_MAX_SEQUENCE_CANDIDATES)
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "candidate_count": candidate_count,
        "max_candidates": AI_PREP_MAX_SEQUENCE_CANDIDATES,
        "truncated_candidates": candidate_trimmed,
        "candidates": candidates[:AI_PREP_MAX_SEQUENCE_CANDIDATES],
    }


def build_ai_prep_evidence_graph(extender, data_snapshot, attacks_snapshot):
    """Build graph links between endpoints, params, auth context, and findings."""
    nodes = []
    edges = []
    node_seen = set()
    edge_seen = set()
    attack_map = {}

    for endpoint_key, attack in attacks_snapshot:
        endpoint = extender._ascii_safe(endpoint_key)
        attack_type = extender._ascii_safe((attack or {}).get("type") or "Unknown")
        if endpoint not in attack_map:
            attack_map[endpoint] = set()
        attack_map[endpoint].add(attack_type)

    def add_node(node_id, node_type, label, attrs=None):
        safe_id = extender._ascii_safe(node_id)
        if safe_id in node_seen:
            return
        node_seen.add(safe_id)
        nodes.append(
            {
                "id": safe_id,
                "type": extender._ascii_safe(node_type),
                "label": extender._ascii_safe(label),
                "attrs": extender._sanitize_for_ai_payload(attrs or {}),
            }
        )

    def add_edge(source, target, relation):
        src = extender._ascii_safe(source)
        dst = extender._ascii_safe(target)
        rel = extender._ascii_safe(relation)
        key = "{}|{}|{}".format(src, dst, rel)
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append({"source": src, "target": dst, "relation": rel})

    sorted_items = sorted(data_snapshot.items(), key=lambda item: item[0])[:260]
    for endpoint_key, entries in sorted_items:
        entry = extender._get_entry(entries)
        endpoint_text = extender._ascii_safe(endpoint_key)
        endpoint_node = "ep:{}".format(endpoint_text)
        method = extender._ascii_safe(entry.get("method")).upper()
        path = extender._ascii_safe(
            entry.get("normalized_path") or entry.get("path") or "/"
        )
        add_node(
            endpoint_node,
            "endpoint",
            endpoint_text,
            {
                "method": method,
                "path": path,
                "status": int(entry.get("response_status", 0) or 0),
            },
        )

        for param_name in extender._extract_param_names(entry)[:40]:
            safe_param = extender._ascii_safe(param_name)
            if not safe_param:
                continue
            param_node = "param:{}".format(extender._ascii_safe(safe_param, lower=True))
            add_node(param_node, "parameter", safe_param, {})
            add_edge(endpoint_node, param_node, "has_param")

        auth_values = entry.get("auth_detected", []) or []
        for auth_type in auth_values[:8]:
            safe_auth = extender._ascii_safe(auth_type or "None")
            auth_node = "auth:{}".format(extender._ascii_safe(safe_auth, lower=True))
            add_node(auth_node, "auth_context", safe_auth, {})
            add_edge(endpoint_node, auth_node, "uses_auth")

        for attack_type in sorted(list(attack_map.get(endpoint_text, set())))[:8]:
            attack_node = "attack:{}".format(
                extender._ascii_safe(attack_type, lower=True).replace(" ", "_")
            )
            add_node(attack_node, "attack_candidate", attack_type, {})
            add_edge(endpoint_node, attack_node, "flagged_as")

    node_count = len(nodes)
    edge_count = len(edges)
    node_trimmed = max(0, node_count - AI_PREP_MAX_GRAPH_NODES)
    edge_trimmed = max(0, edge_count - AI_PREP_MAX_GRAPH_EDGES)
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "node_count": node_count,
        "edge_count": edge_count,
        "max_nodes": AI_PREP_MAX_GRAPH_NODES,
        "max_edges": AI_PREP_MAX_GRAPH_EDGES,
        "truncated_nodes": node_trimmed,
        "truncated_edges": edge_trimmed,
        "nodes": nodes[:AI_PREP_MAX_GRAPH_NODES],
        "edges": edges[:AI_PREP_MAX_GRAPH_EDGES],
    }
