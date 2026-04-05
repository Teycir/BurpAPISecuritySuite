#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Golden replay corpus tests for behavior-level invariant coverage."""

import json
import os

import behavior_analysis


def _fixture_payload():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    fixture_path = os.path.join(base_dir, "fixtures", "golden_replay_sequence.json")
    with open(fixture_path, "r") as handle:
        return json.load(handle)


def test_golden_replay_detects_sequence_invariants():
    payload = _fixture_payload()
    package = behavior_analysis.build_sequence_invariant_package(payload)
    findings = list(package.get("findings", []) or [])
    assert findings, "Expected invariant findings from golden replay corpus"

    names = set([str(item.get("invariant")) for item in findings])
    expected = set(
        [
            "auth_boundary_consistency",
            "delete_tombstone_consistency",
            "sensitive_write_field_integrity",
            "callback_target_control",
        ]
    )
    assert names.intersection(expected), "Missing expected invariant families"
    assert package.get("finding_count", 0) >= 3

    for finding in findings:
        assert "confidence_score" in finding
        assert "confidence_label" in finding
        assert "evidence" in finding
        assert finding.get("non_destructive") is True

    print("[PASS] test_golden_replay_detects_sequence_invariants")


def test_golden_replay_builds_confidence_ledger():
    payload = _fixture_payload()
    package = behavior_analysis.build_sequence_invariant_package(payload)
    ledger = dict(package.get("ledger", {}) or {})
    assert ledger.get("total_findings", 0) >= 1
    assert "severity_distribution" in ledger
    assert "confidence_distribution" in ledger
    assert "analyst_guidance" in ledger
    assert isinstance(ledger.get("findings", []), list)
    assert len(ledger.get("findings", [])) == package.get("finding_count", -1)
    print("[PASS] test_golden_replay_builds_confidence_ledger")


def test_golden_replay_detects_golden_ticket_patterns():
    payload = _fixture_payload()
    package = behavior_analysis.build_golden_ticket_package(payload)
    findings = list(package.get("findings", []) or [])
    assert package.get("observed_token_count", 0) >= 1
    assert findings, "Expected Golden Ticket findings from replay corpus"

    names = set([str(item.get("invariant")) for item in findings])
    expected = set(
        [
            "golden_ticket_cross_resource_reuse",
            "golden_ticket_privileged_token_overreach",
        ]
    )
    assert names.intersection(expected), "Missing expected Golden Ticket invariant families"
    assert package.get("finding_count", 0) >= 1
    ledger = dict(package.get("ledger", {}) or {})
    assert ledger.get("analysis_type") == "golden_ticket"
    assert "coverage" in ledger
    assert isinstance(ledger.get("findings", []), list)
    print("[PASS] test_golden_replay_detects_golden_ticket_patterns")
