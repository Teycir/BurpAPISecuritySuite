#!/usr/bin/env python3
"""
Lightweight source-level contract tests for recently added coverage features.
These checks avoid Burp/Jython runtime dependencies and validate wiring.
"""

import os


def _source_text():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    source_path = os.path.join(base_dir, "BurpAPISecuritySuite.py")
    with open(source_path, "r") as handle:
        return handle.read()


def test_fuzzer_dropdown_includes_extended_modes():
    text = _source_text()
    required = [
        '"NoSQL"',
        '"Path Traversal"',
        '"Mass Assignment"',
        '"Race Condition"',
        '"GraphQL"',
        '"JWT"',
        '"SSTI"',
        '"Deserialization"',
        '"Business Logic"',
        '"SSRF"',
        '"XXE"',
    ]
    for value in required:
        assert value in text, "Missing fuzzer mode: {}".format(value)
    print("[PASS] test_fuzzer_dropdown_includes_extended_modes")


def test_ssrf_xxe_wired_into_generation():
    text = _source_text()
    assert "def _check_ssrf(" in text
    assert "def _check_xxe(" in text
    assert "self._check_ssrf(normalized, attack_type)" in text
    assert "self._check_xxe(normalized, attack_type)" in text
    print("[PASS] test_ssrf_xxe_wired_into_generation")


def test_hidden_attack_checks_now_selectable():
    text = _source_text()
    checks = [
        "_check_nosqli",
        "_check_path_traversal",
        "_check_mass_assignment",
        "_check_race_condition",
        "_check_graphql",
        "_check_jwt",
        "_check_ssti",
        "_check_deserialization",
        "_check_business_logic",
    ]
    for check_name in checks:
        marker = "def {}(".format(check_name)
        assert marker in text, "Missing function {}".format(check_name)
    # Guard that selection helper is used by these checks instead of All-only gating.
    assert "if not self._attack_selected(attack_type, [\"NoSQL\", \"NoSQL Injection\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"Path Traversal\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"Mass Assignment\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"Race Condition\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"GraphQL\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"JWT\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"SSTI\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"Deserialization\"]):" in text
    assert "if not self._attack_selected(attack_type, [\"Business Logic\"]):" in text
    print("[PASS] test_hidden_attack_checks_now_selectable")


def test_passive_modes_and_dispatch_include_new_apis():
    text = _source_text()
    mode_values = [
        '"API4 (Resource)"',
        '"API6 (Flows)"',
        '"API10 (Consumption)"',
    ]
    for value in mode_values:
        assert value in text, "Missing passive mode: {}".format(value)

    assert "def _passive_discover_api4(" in text
    assert "def _passive_discover_api6(" in text
    assert "def _passive_discover_api10(" in text
    assert "(\"API4 (Resource)\", self._passive_discover_api4)" in text
    assert "(\"API6 (Flows)\", self._passive_discover_api6)" in text
    assert "(\"API10 (Consumption)\", self._passive_discover_api10)" in text
    print("[PASS] test_passive_modes_and_dispatch_include_new_apis")


def test_passive_scope_defaults_to_all_endpoints():
    text = _source_text()
    assert 'self.passive_scope_combo = JComboBox(' in text
    assert 'self.passive_scope_combo.setSelectedItem("All Endpoints")' in text
    print("[PASS] test_passive_scope_defaults_to_all_endpoints")


def test_passive_output_category_summary_updated():
    text = _source_text()
    required_tokens = [
        '"API3": 0',
        '"API4": 0',
        '"API5": 0',
        '"API6": 0',
        '"API9": 0',
        '"API10": 0',
    ]
    for token in required_tokens:
        assert token in text, "Missing passive category token: {}".format(token)
    print("[PASS] test_passive_output_category_summary_updated")


def test_no_bare_except_exception_blocks():
    text = _source_text()
    assert "except Exception:" not in text, "Found bare except Exception block"
    print("[PASS] test_no_bare_except_exception_blocks")


def test_passive_discovery_flow_is_split_into_helpers():
    text = _source_text()
    assert "def _collect_passive_snapshot(" in text
    assert "def _run_passive_mode_handlers(" in text
    assert "def _sort_and_store_passive_findings(" in text
    assert "snapshot = self._collect_passive_snapshot(endpoint_keys)" in text
    assert "findings = self._run_passive_mode_handlers(mode, snapshot)" in text
    assert "findings = self._sort_and_store_passive_findings(findings)" in text
    print("[PASS] test_passive_discovery_flow_is_split_into_helpers")


def test_ascii_safe_helper_used_in_passive_paths():
    text = _source_text()
    assert "def _ascii_safe(" in text
    assert "self._ascii_safe(key, lower=True)" in text
    assert "self._ascii_safe(value)" in text
    assert "safe_name = self._ascii_safe(name, lower=True).strip()" in text
    assert "key_str = self._ascii_safe(key)" in text
    print("[PASS] test_ascii_safe_helper_used_in_passive_paths")


def test_passive_sorting_and_output_use_ascii_safe_text():
    text = _source_text()
    required_tokens = [
        'self._ascii_safe(x.get("severity", "info"), lower=True)',
        'self._ascii_safe(x.get("category", ""), lower=True)',
        'self._ascii_safe(x.get("endpoint", ""), lower=True)',
        'sev = self._ascii_safe(finding.get("severity", "info"), lower=True)',
        'lines.append("[*] Mode: {}".format(self._ascii_safe(mode)))',
        'issue = self._ascii_safe(finding.get("issue", ""))',
        'endpoint = self._ascii_safe(finding.get("endpoint", ""))',
        'evidence = self._ascii_safe(finding.get("evidence", ""))',
    ]
    for token in required_tokens:
        assert token in text, "Missing ASCII-safe passive token: {}".format(token)
    print("[PASS] test_passive_sorting_and_output_use_ascii_safe_text")


def test_passive_internal_heuristics_use_ascii_safe_text():
    text = _source_text()
    required_tokens = [
        'path = self._ascii_safe(entry.get("normalized_path", "") or "", lower=True)',
        'method = self._ascii_safe(entry.get("method", "") or "").upper()',
        'query = self._ascii_safe(entry.get("query_string", "") or "", lower=True)',
        'body = self._ascii_safe(sample.get("response_body", "") or "", lower=True)',
        'body = self._ascii_safe(body_text or "", lower=True)',
        "auth_types = [",
        "self._ascii_safe(x, lower=True)",
    ]
    for token in required_tokens:
        assert token in text, "Missing passive internal ASCII-safe token: {}".format(token)
    print("[PASS] test_passive_internal_heuristics_use_ascii_safe_text")


def test_passive_snapshot_filters_noise_to_api_like_scope():
    text = _source_text()
    required_tokens = [
        "PASSIVE_STATIC_EXTENSIONS",
        "PASSIVE_STATIC_PATH_PARTS",
        "PASSIVE_API_PATTERN_HINTS",
        "def _build_passive_filter_config(",
        "def _passive_entry_is_api_like(",
        "def _passive_entry_allowed(",
        "filter_cfg = self._build_passive_filter_config(raw_snapshot)",
        "if self._passive_entry_allowed(entry, filter_cfg):",
        "self._is_wayback_noise_host(host)",
        "return self._passive_entry_is_api_like(entry)",
    ]
    for token in required_tokens:
        assert token in text, "Missing passive noise-filter token: {}".format(token)
    print("[PASS] test_passive_snapshot_filters_noise_to_api_like_scope")


def test_fuzzer_uses_api_like_scope_noise_filtering():
    text = _source_text()
    required_tokens = [
        "FUZZER_STATIC_PATH_PARTS = PASSIVE_STATIC_PATH_PARTS + (",
        "def _fuzzer_endpoint_is_api_like(",
        "def _collect_fuzzer_targets(",
        "if not self._passive_entry_allowed(entry, filter_cfg):",
        "if not self._fuzzer_endpoint_is_api_like(normalized):",
        "api_endpoints, filter_meta = self._collect_fuzzer_targets()",
        '"[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(',
    ]
    for token in required_tokens:
        assert token in text, "Missing fuzzer scope/noise filter token: {}".format(token)
    print("[PASS] test_fuzzer_uses_api_like_scope_noise_filtering")


def test_param_and_version_collectors_scope_out_noise():
    text = _source_text()
    required_tokens = [
        "PARAM_MINER_NOISE_PATH_MARKERS = (",
        "def _collect_param_targets(",
        "def _collect_version_targets(",
        "api_endpoints, filter_meta = self._collect_param_targets()",
        "api_endpoints, filter_meta = self._collect_version_targets()",
        '"[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(',
        "if (not has_auth_context) and self._path_contains_noise_marker(",
        "if (not api_marker) and method not in [\"POST\", \"PUT\", \"PATCH\", \"DELETE\"]:",
    ]
    for token in required_tokens:
        assert token in text, "Missing param/version scope token: {}".format(token)
    print("[PASS] test_param_and_version_collectors_scope_out_noise")


def test_ffuf_target_filtering_hardening_present():
    text = _source_text()
    assert "FFUF_NOISE_HOST_PATTERNS" in text
    assert "FFUF_NOISE_PATH_PARTS" in text
    assert "FFUF_MAX_TARGETS" in text
    assert "FFUF_TARGET_TIMEOUT_SECONDS" in text
    assert "def _collect_ffuf_targets(" in text
    assert "targets, target_meta = self._collect_ffuf_targets()" in text
    assert "timeout = self.FFUF_TARGET_TIMEOUT_SECONDS" in text
    print("[PASS] test_ffuf_target_filtering_hardening_present")


def test_external_tool_scope_collectors_present():
    text = _source_text()
    assert "def _collect_nuclei_targets(" in text
    assert "def _collect_katana_seed_urls(" in text
    assert "def _collect_wayback_queries(" in text
    assert "targets, target_meta = self._collect_nuclei_targets()" in text
    assert "seed_urls, target_meta = self._collect_katana_seed_urls()" in text
    assert "queries, query_meta = self._collect_wayback_queries()" in text
    print("[PASS] test_external_tool_scope_collectors_present")


def test_balanced_runtime_defaults_and_safe_pipe_read_present():
    text = _source_text()
    required_tokens = [
        "FFUF_THREADS",
        "FFUF_REQUEST_TIMEOUT_SECONDS",
        "FFUF_RATE_LIMIT",
        "NUCLEI_REQUEST_TIMEOUT_SECONDS",
        "NUCLEI_RETRIES",
        "NUCLEI_RATE_LIMIT",
        "NUCLEI_CONCURRENCY",
        "NUCLEI_MAX_SCAN_SECONDS",
        "KATANA_MAX_TARGETS",
        "WAYBACK_MAX_QUERIES",
        "def _safe_pipe_read(",
        "self._safe_pipe_read(process.stdout, \"Nuclei stdout\")",
        "self._safe_pipe_read(process.stderr, \"Nuclei stderr\")",
    ]
    for token in required_tokens:
        assert token in text, "Missing runtime hardening token: {}".format(token)
    print("[PASS] test_balanced_runtime_defaults_and_safe_pipe_read_present")


def test_nuclei_uses_correct_json_export_and_parse_fallback():
    text = _source_text()
    required_tokens = [
        "supports_jsonl_export = bool(",
        '"-jsonl-export" in (help_text or "").lower()',
        'cmd.extend(["-jsonl-export", json_file])',
        'parse_file = json_file',
        'parse_file = output_file',
        'with open(parse_file, "r") as f:',
        'result.append("[*] Parsed results file: {}".format(parse_file))',
        "Example: {nuclei_path} -list {targets_file} -jsonl-export {json_file} -silent",
    ]
    for token in required_tokens:
        assert token in text, "Missing Nuclei JSON export token: {}".format(token)

    forbidden_tokens = [
        "Example: {nuclei_path} -list {targets_file} -jsonl {json_file} -silent",
        '-jsonl {json_file}',
    ]
    for token in forbidden_tokens:
        assert token not in text, "Found legacy Nuclei JSON flag token: {}".format(token)
    print("[PASS] test_nuclei_uses_correct_json_export_and_parse_fallback")


def test_nuclei_timeout_uses_partial_parse_and_speed_flags():
    text = _source_text()
    required_tokens = [
        "supports_max_host_error = bool(",
        "supports_bulk_size = bool(",
        "supports_scan_strategy = bool(",
        "supports_no_httpx = bool(",
        "supports_project_mode = bool(",
        'cmd.extend(["-bs", str(self.NUCLEI_BULK_SIZE)])',
        'cmd.extend(["-mhe", str(self.NUCLEI_MAX_HOST_ERROR)])',
        'cmd.extend(["-ss", self.NUCLEI_SCAN_STRATEGY])',
        'cmd.append("-no-httpx")',
        'cmd.extend(["-project", "-project-path", temp_dir])',
        "adaptive_timeout = max(360, target_count * 30)",
        "can_parse_partial = bool(",
        "partial_results_mode = True",
        '"[*] Run status: partial results (process exited {})".format(',
    ]
    for token in required_tokens:
        assert token in text, "Missing Nuclei timeout resilience token: {}".format(token)
    print("[PASS] test_nuclei_timeout_uses_partial_parse_and_speed_flags")


def test_help_probe_uses_file_capture_to_avoid_pipe_deadlock():
    text = _source_text()
    required_tokens = [
        "def _probe_binary_help(",
        "tempfile.mkstemp(",
        'prefix="burp_help_probe_"',
        "stderr=subprocess.STDOUT",
        'with open(capture_path, "rb") as reader:',
    ]
    for token in required_tokens:
        assert token in text, "Missing help-probe hardening token: {}".format(token)
    print("[PASS] test_help_probe_uses_file_capture_to_avoid_pipe_deadlock")


def test_target_base_scope_popup_and_enforcement_present():
    text = _source_text()
    required_tokens = [
        'def _open_target_base_scope_popup(',
        'def _parse_target_base_scope_text(',
        'def _get_target_scope_override(',
        'def _host_matches_target_scope(',
        '"Target Bases..."',
        '"Only Base+Derivatives"',
        "manual_scope_enabled",
        'if target_meta.get("manual_scope_enabled")',
        'if query_meta.get("manual_scope_enabled")',
    ]
    for token in required_tokens:
        assert token in text, "Missing target base scope token: {}".format(token)
    assert text.count("scope_override = self._get_target_scope_override()") >= 4
    print("[PASS] test_target_base_scope_popup_and_enforcement_present")


def test_wayback_uses_dedicated_noise_host_filter():
    text = _source_text()
    assert "WAYBACK_NOISE_HOST_PATTERNS" in text
    assert "WAYBACK_NOISE_LABELS" in text
    assert "def _is_wayback_noise_host(" in text
    assert "self._is_wayback_noise_host(host)" in text
    print("[PASS] test_wayback_uses_dedicated_noise_host_filter")


def test_emergency_pkill_button_and_handler_present():
    text = _source_text()
    required_tokens = [
        'def _pkill_external_tools(',
        'def _add_force_kill_button(',
        '"PKill Tools"',
        'self._add_force_kill_button(controls, lambda: getattr(self, "nuclei_area", None))',
        'self._add_force_kill_button(controls, lambda: getattr(self, "httpx_area", None))',
        'self._add_force_kill_button(controls, lambda: getattr(self, "katana_area", None))',
        'self._add_force_kill_button(controls, lambda: getattr(self, "ffuf_area", None))',
        'self._add_force_kill_button(controls, lambda: getattr(self, "wayback_area", None))',
        '["pkill", "-TERM", "-f", pattern]',
        '["killall", "-q", pattern]',
        '["taskkill", "/IM", name, "/F", "/T"]',
    ]
    for token in required_tokens:
        assert token in text, "Missing emergency kill token: {}".format(token)
    print("[PASS] test_emergency_pkill_button_and_handler_present")


def test_external_tool_commands_are_cross_platform_safe():
    text = _source_text()
    required_tokens = [
        "def _build_shell_command(",
        'return ["cmd", "/c", command_text]',
        'return ["/bin/bash", "-lc", command_text]',
        "cmd = self._build_shell_command(custom_nuclei_command)",
        "cmd = self._build_shell_command(custom_httpx_command)",
        "cmd = self._build_shell_command(custom_katana_command)",
        "cmd = self._build_shell_command(custom_wayback_command)",
        '"{httpx_path} -l {urls_file} -status-code -nc -silent"',
        '"{katana_path} -list {urls_file} -d 1 -jc -silent"',
        'stdin_prefix = "type" if os.name == "nt" else "cat"',
        'os.path.expanduser("~/go/bin/nuclei.exe")',
        'os.path.expanduser("~/go/bin/httpx.exe")',
        'os.path.expanduser("~/go/bin/katana.exe")',
        'os.path.expanduser("~/go/bin/ffuf.exe")',
        '"-l",',
        '"-list",',
    ]
    for token in required_tokens:
        assert token in text, "Missing cross-platform command token: {}".format(token)

    forbidden_tokens = [
        '["bash", "-c", custom_nuclei_command]',
        '["bash", "-c", custom_httpx_command]',
        '["bash", "-c", custom_katana_command]',
        '["bash", "-c", custom_wayback_command]',
        '"cat {urls_file} | {httpx_path}',
        '"cat {urls_file} | {katana_path}',
    ]
    for token in forbidden_tokens:
        assert token not in text, "Found non-portable command token: {}".format(token)
    print("[PASS] test_external_tool_commands_are_cross_platform_safe")


def test_runtime_helpers_cover_python3_and_windows_edge_cases():
    text = _source_text()
    required_tokens = [
        "integer_types = (int, long)",
        "except NameError:",
        'shlex.split(rendered_command, posix=(os.name != "nt"))',
        'shlex.split(command_text, posix=(os.name != "nt"))',
    ]
    for token in required_tokens:
        assert token in text, "Missing runtime compatibility token: {}".format(token)

    forbidden_tokens = [
        'lambda: self.log_to_ui("[!] Error: {}".format(str(e)))',
        'lambda: self.log_to_ui("[!] Auth Replay error: {}".format(str(e)))',
        'lambda: self.log_to_ui("[!] Passive discovery error: {}".format(str(e)))',
        'lambda: self.log_to_ui("[!] HTTPX error: {}".format(str(e)))',
        'lambda: self.log_to_ui("[!] Katana error: {}".format(str(e)))',
        'lambda: self.log_to_ui("[!] FFUF error: {}".format(str(e)))',
        'lambda: self.log_to_ui("[!] Wayback error: {}".format(str(e)))',
    ]
    for token in forbidden_tokens:
        assert token not in text, "Found unsafe exception lambda capture: {}".format(token)
    print("[PASS] test_runtime_helpers_cover_python3_and_windows_edge_cases")


def test_custom_command_labels_are_concise_and_opt_in():
    text = _source_text()
    assert 'JCheckBox("Use Custom Cmd", False)' not in text
    assert (
        'self.nuclei_custom_cmd_checkbox = JCheckBox("Enable Custom", False)' in text
    )
    assert 'self.httpx_custom_cmd_checkbox = JCheckBox("Enable Custom", False)' in text
    assert (
        'self.katana_custom_cmd_checkbox = JCheckBox("Enable Custom", False)' in text
    )
    assert (
        'self.wayback_custom_cmd_checkbox = JCheckBox("Enable Custom", False)' in text
    )
    assert text.count('controls.add(JLabel("Command:"))') >= 4
    print("[PASS] test_custom_command_labels_are_concise_and_opt_in")


def test_preset_selection_no_longer_forces_custom_enable():
    text = _source_text()
    assert "auto_enable=False" in text
    assert "if auto_enable:" in text
    assert "checkbox.setSelected(True)" in text
    assert "auto_enable=True" not in text
    assert (
        "Preset dropdown fills Command text only; override stays opt-in." in text
    )
    print("[PASS] test_preset_selection_no_longer_forces_custom_enable")
