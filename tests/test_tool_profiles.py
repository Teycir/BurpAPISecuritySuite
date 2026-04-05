#!/usr/bin/env python3
"""
Unit tests for tool_profiles helpers.
These tests validate profile normalization, command construction, and local help probes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tool_profiles


def test_profile_normalization_and_labels():
    labels = tool_profiles.profile_labels()
    assert labels == ["Fast", "Balanced", "Deep"]
    assert tool_profiles.normalize_profile("fast") == "fast"
    assert tool_profiles.normalize_profile("quick") == "fast"
    assert tool_profiles.normalize_profile("deep") == "deep"
    assert tool_profiles.normalize_profile("maximum") == "deep"
    assert tool_profiles.normalize_profile("unknown") == "balanced"
    print("[PASS] test_profile_normalization_and_labels")


def test_sqlmap_command_builder():
    target = {
        "url": "https://www.allocine.fr/recherche/?q=test",
        "method": "GET",
        "params": ["q", "locale", "foo", "bar", "x", "y", "z"],
    }
    cmd, cfg = tool_profiles.build_sqlmap_command("/usr/bin/sqlmap", target, "balanced")
    assert cmd[0] == "/usr/bin/sqlmap"
    assert "-u" in cmd and target["url"] in cmd
    assert "--batch" in cmd
    assert "--flush-session" in cmd
    assert "--level" in cmd and cfg["level"] in cmd
    assert "--risk" in cmd and cfg["risk"] in cmd
    assert "-p" in cmd
    assert "q,locale,foo,bar,x,y" in cmd
    print("[PASS] test_sqlmap_command_builder")


def test_dalfox_command_builder():
    target = {
        "url": "https://www.allocine.fr/recherche/?q=test",
        "method": "POST",
        "params": ["q", "target"],
        "data": "q=test&target=allocine",
    }
    cmd, cfg = tool_profiles.build_dalfox_command(
        "/usr/bin/dalfox", target, "/tmp/out.jsonl", "fast"
    )
    assert cmd[0] == "/usr/bin/dalfox"
    assert cmd[1] == "url"
    assert "--format" in cmd and "jsonl" in cmd
    assert "-o" in cmd and "/tmp/out.jsonl" in cmd
    assert "-X" in cmd and "POST" in cmd
    assert "-d" in cmd and "q=test&target=allocine" in cmd
    assert cfg["profile"] == "fast"
    assert "--skip-mining-all" in cmd
    print("[PASS] test_dalfox_command_builder")


def test_asset_stage_command_builder():
    stages, cfg = tool_profiles.build_asset_stage_commands(
        "/usr/bin/subfinder",
        "/usr/bin/dnsx",
        "/usr/bin/httpx",
        "/tmp/domains.txt",
        "/tmp/subfinder.txt",
        "/tmp/dnsx.txt",
        "/tmp/httpx.txt",
        "deep",
    )
    assert cfg["profile"] == "deep"
    assert len(stages) == 3
    assert stages[0][0] == "Subfinder"
    assert stages[1][0] == "DNSX"
    assert stages[2][0] == "HTTPX"
    assert "-title" in stages[2][1]
    assert "-tech-detect" in stages[2][1]
    print("[PASS] test_asset_stage_command_builder")


def test_nuclei_profile_settings():
    fast = tool_profiles.nuclei_profile_settings("fast")
    deep = tool_profiles.nuclei_profile_settings("deep")
    assert fast["profile"] == "fast"
    assert deep["profile"] == "deep"
    assert fast["rate_limit"] > deep["rate_limit"]
    assert deep["request_timeout"] >= fast["request_timeout"]
    assert "api" in fast["include_tags"]
    print("[PASS] test_nuclei_profile_settings")


def test_help_evaluator():
    text = "Usage: nuclei [flags]\nFlags:\n  -list string\n  -tags string\n"
    check = tool_profiles.evaluate_help_text(
        text,
        required_tokens=["-list", "-tags"],
        forbidden_tokens=["--bad-flag"],
    )
    assert check["healthy"] is True
    assert check["missing"] == []
    assert check["forbidden_found"] == []
    print("[PASS] test_help_evaluator")


def test_probe_binary_help_python():
    probe = tool_profiles.probe_binary_help("python3", ["--help"], timeout_seconds=5)
    assert probe["ok"] is True
    assert "usage" in (probe.get("help_text") or "").lower()
    print("[PASS] test_probe_binary_help_python")


def test_probe_optional_local_security_binaries():
    checks = [
        ("nuclei", os.path.expanduser("~/go/bin/nuclei"), ["-list", "-tags"]),
        ("httpx", os.path.expanduser("~/go/bin/httpx"), ["-l", "-silent"]),
        ("subfinder", os.path.expanduser("~/go/bin/subfinder"), ["-d", "-silent"]),
        ("dnsx", os.path.expanduser("~/go/bin/dnsx"), ["-l", "-silent"]),
        ("sqlmap", os.path.expanduser("~/.local/bin/sqlmap"), ["-u", "--batch"]),
        ("dalfox", os.path.expanduser("~/go/bin/dalfox"), ["url", "--format"]),
    ]

    available = 0
    for name, path, required in checks:
        if not os.path.exists(path):
            print("[SKIP] {} not found at {}".format(name, path))
            continue
        available += 1
        probe = tool_profiles.probe_binary_help(path, timeout_seconds=6)
        assert probe["ok"] is True, "{} probe failed: {}".format(
            name, probe.get("error")
        )
        eval_result = tool_profiles.evaluate_help_text(
            probe.get("help_text", ""),
            required_tokens=required,
            forbidden_tokens=[],
        )
        assert eval_result["healthy"] is True, "{} missing {}".format(
            name, eval_result["missing"]
        )
        print("[PASS] {} probe + signature".format(name))

    if available == 0:
        print("[SKIP] No optional security binaries available for probe checks")
    else:
        print("[PASS] test_probe_optional_local_security_binaries")

