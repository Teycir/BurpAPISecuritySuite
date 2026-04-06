#!/usr/bin/env python3
"""
Lightweight source-level contract tests for recently added coverage features.
These checks avoid Burp/Jython runtime dependencies and validate wiring.
"""

import os


def _source_text():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_dir = os.path.join(base_dir, "src")
    def _pick_path(filename):
        src_path = os.path.join(src_dir, filename)
        if os.path.exists(src_path):
            return src_path
        return os.path.join(base_dir, filename)
    source_paths = [
        os.path.join(base_dir, "BurpAPISecuritySuite.py"),
        _pick_path("burp_core_ui_and_fuzz_methods.py"),
        _pick_path("burp_recon_logger_sync_methods.py"),
        _pick_path("burp_fuzz_detection_and_capture_methods.py"),
        _pick_path("burp_capture_export_and_tooling_methods.py"),
        _pick_path("burp_auth_passive_and_scanner_methods.py"),
        _pick_path("burp_wayback_import_and_logging_methods.py"),
        _pick_path("burp_advanced_logic_methods.py"),
        _pick_path("burp_counterfactual_methods.py"),
        _pick_path("heavy_runners.py"),
        _pick_path("jython_size_helpers.py"),
        _pick_path("ai_prep_layer.py"),
        _pick_path("behavior_analysis.py"),
        _pick_path("recon_param_intel.py"),
        _pick_path("golden_ticket_analysis.py"),
        _pick_path("state_transition_analysis.py"),
    ]
    chunks = []
    for source_path in source_paths:
        if not os.path.exists(source_path):
            continue
        with open(source_path, "r") as handle:
            chunks.append(handle.read())
    return "\n".join(chunks)


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


def test_auth_replay_scope_defaults_to_all_endpoints():
    text = _source_text()
    assert "self.auth_replay_scope_combo = JComboBox(" in text
    assert 'self.auth_replay_scope_combo.setSelectedItem("All Endpoints")' in text
    print("[PASS] test_auth_replay_scope_defaults_to_all_endpoints")


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
        'self.fuzzer_lenient_checkbox = JCheckBox("Lenient JSON GET", True)',
        "FUZZER_STATIC_PATH_PARTS = PASSIVE_STATIC_PATH_PARTS + (",
        "FUZZER_STRICT_NOISE_PATH_MARKERS = (",
        "def _fuzzer_endpoint_is_api_like(",
        "def _fuzzer_sparse_candidate_score(",
        "def _augment_fuzzer_targets_sparse(",
        "def _fuzzer_has_api_signal(",
        "def _fuzzer_has_object_target(",
        "def _collect_fuzzer_targets(",
        "lenient_mode = bool(",
        "api_endpoints, filter_meta = self._collect_fuzzer_targets(strict=not lenient_mode)",
        "if strict and self._path_contains_noise_marker(",
        "path, self.FUZZER_STRICT_NOISE_PATH_MARKERS",
        "if not self._passive_entry_allowed(entry, filter_cfg):",
        "if not self._fuzzer_endpoint_is_api_like(normalized, strict=strict):",
        "candidate_score = self._fuzzer_sparse_candidate_score(",
        "sparse_added = self._augment_fuzzer_targets_sparse(",
        '"sparse_fallback_added": sparse_added,',
        "if not self._fuzzer_has_api_signal(normalized):",
        "if not self._fuzzer_has_object_target(normalized):",
        "FUZZER_SQLI_PARAM_KEYWORDS",
        "FUZZER_SSRF_PARAM_KEYWORDS",
        "FUZZER_SSTI_PARAM_KEYWORDS",
        '"[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")',
        '"[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(',
        '"[*] Sparse fallback: +{} heuristic endpoints from {} candidates".format(',
    ]
    for token in required_tokens:
        assert token in text, "Missing fuzzer scope/noise filter token: {}".format(token)
    print("[PASS] test_fuzzer_uses_api_like_scope_noise_filtering")


def test_param_and_version_collectors_scope_out_noise():
    text = _source_text()
    required_tokens = [
        'self.param_lenient_checkbox = JCheckBox("Lenient JSON GET", True)',
        'self.version_lenient_checkbox = JCheckBox("Lenient JSON GET", True)',
        "lenient_mode = bool(",
        "api_endpoints, filter_meta = self._collect_param_targets(",
        "strict_base=not lenient_mode",
        '"[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")',
        "api_endpoints, filter_meta = self._collect_version_targets(lenient=lenient_mode)",
        '"[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")',
        "PARAM_MINER_NOISE_PATH_MARKERS = (",
        "PARAM_MINER_STRICT_NOISE_PATH_MARKERS = (",
        "VERSION_SCANNER_NOISE_PATH_MARKERS = (",
        "def _collect_param_targets(",
        "def _collect_version_targets(",
        "base_targets, base_meta = self._collect_fuzzer_targets(strict=strict_base)",
        "param_targets, param_meta = self._collect_param_targets(",
        "strict_base=not bool(lenient)",
        "def _build_version_test_path(",
        "api_endpoints, filter_meta = self._collect_version_targets(",
        '"[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(',
        "if self._path_contains_noise_marker(",
        "path, self.PARAM_MINER_STRICT_NOISE_PATH_MARKERS",
        "if (not has_auth_context) and self._path_contains_noise_marker(",
        "path, self.VERSION_SCANNER_NOISE_PATH_MARKERS",
        "if method == \"GET\" and (not has_api_marker) and (not has_structured_content):",
        "if lenient and has_structured_content:",
        "if self._is_frontend_route(path, content_type):",
        "already_versioned = bool(self._extract_version_segment(path))",
        "if (not already_versioned) and (not api_marker) and method not in [",
        "excluded_missing_host = 0",
        "excluded_missing_host += 1",
        "test_path = self._build_version_test_path(path, ver)",
    ]
    for token in required_tokens:
        assert token in text, "Missing param/version scope token: {}".format(token)
    print("[PASS] test_param_and_version_collectors_scope_out_noise")


def test_openapi_drift_autodetects_spec_from_proxy_history():
    text = _source_text()
    required_tokens = [
        '"Detect",',
        "lambda e: self._detect_openapi_spec_from_history(e),",
        "def _openapi_spec_candidate_score(",
        "def _collect_openapi_spec_candidates(",
        "def _autoselect_openapi_spec_from_history(",
        "def _detect_openapi_spec_from_history(",
        "selected = self._autoselect_openapi_spec_from_history(",
        "Auto-selected OpenAPI target from proxy history",
    ]
    for token in required_tokens:
        assert token in text, "Missing OpenAPI autodetect token: {}".format(token)
    print("[PASS] test_openapi_drift_autodetects_spec_from_proxy_history")

def test_openapi_one_click_generation_wired_from_recon():
    text = _source_text()
    required_tokens = [
        '"Generate OpenAPI"',
        "lambda e: self._generate_openapi_from_capture(e)",
        "def _generate_openapi_from_capture(",
        "def _build_openapi_spec_from_capture(",
        "openapi_generated.json",
    ]
    for token in required_tokens:
        assert token in text, "Missing OpenAPI generation token: {}".format(token)
    print("[PASS] test_openapi_one_click_generation_wired_from_recon")

def test_ai_bundle_schema_validation_wired_into_export():
    text = _source_text()
    required_tokens = [
        "def _build_ai_bundle_schema_contract(",
        "def _validate_ai_bundle_schema(",
        "bundle, schema_validation = self._validate_ai_bundle_schema(bundle)",
        '"ai_bundle_schema_contract.json"',
        '"ai_bundle_schema_validation.json"',
    ]
    for token in required_tokens:
        assert token in text, "Missing AI schema validation token: {}".format(token)
    print("[PASS] test_ai_bundle_schema_validation_wired_into_export")


def test_api_asset_results_include_copy_ready_urls_block():
    text = _source_text()
    required_tokens = [
        '"Run Subfinder",',
        '"Subfinder Path:"',
        "COPY-READY ASSET DOMAINS",
        "COPY-READY ASSET URLS",
        "Fallback: using input domains as seed assets",
        "self._resolve_custom_command(",
        '"Subfinder",',
    ]
    for token in required_tokens:
        assert token in text, "Missing API assets copy/fallback token: {}".format(token)
    print("[PASS] test_api_asset_results_include_copy_ready_urls_block")


def test_recon_exports_include_postman_and_insomnia():
    text = _source_text()
    required_tokens = [
        'postman_btn = JButton("Postman")',
        'insomnia_btn = JButton("Insomnia")',
        'ai_export_btn = JButton("Export AI Bundle")',
        'help_btn = JButton("Button Help")',
        "ai_export_btn.addActionListener(lambda e: self._export_ai_context())",
        "help_btn.addActionListener(lambda e: self._show_recon_button_help(e))",
        "postman_btn.addActionListener(lambda e: self._export_postman_collection())",
        "insomnia_btn.addActionListener(lambda e: self._export_insomnia_collection())",
        "def _show_recon_button_help(",
        "Tip: hover any Recon button to see a quick tooltip.",
        "Export AI Bundle:",
        "def _export_postman_collection(",
        "def _export_insomnia_collection(",
        "def _build_postman_collection(",
        "def _build_insomnia_export(",
        "def _select_export_scope_data(",
        "collection/v2.1.0/collection.json",
        "postman_collection.json",
        "insomnia_collection.json",
        '"__export_format": 4',
    ]
    for token in required_tokens:
        assert token in text, "Missing Postman/Insomnia export token: {}".format(token)
    assert '"AI Payloads"' not in text
    print("[PASS] test_recon_exports_include_postman_and_insomnia")


def test_recon_logger_and_turbo_intruder_features_are_wired():
    text = _source_text()
    required_tokens = [
        'self.tag_filter = JComboBox(["All"])',
        'self.tool_filter = JComboBox(["All"])',
        "self.recon_regex_field = JTextField(12)",
        'self.recon_regex_scope_combo = JComboBox(["Any", "Request", "Response", "Req+Resp"])',
        'grep_btn = JButton("Grep")',
        'turbo_pack_btn = JButton("Turbo Pack")',
        "grep_btn.addActionListener(lambda e: self._run_recon_grep())",
        "turbo_pack_btn.addActionListener(lambda e: self._export_recon_turbo_pack())",
        "def _run_recon_grep(",
        "def _collect_recon_grep_targets(",
        "def _export_recon_turbo_pack(",
        "def _export_recon_turbo_pack_selected(",
        "def _build_recon_turbo_request_template(",
        "def _build_recon_turbo_basic_script(",
        "def _build_recon_turbo_race_script(",
        '"Export Turbo Pack (Selected Endpoint)"',
        "def _resolve_tool_name(",
        '"source_tool": self._ascii_safe(source_tool),',
        "def _update_tool_filter(",
        "def _update_tag_filter(",
        'tags.add("api_endpoint")',
        'tags.add("idor_risk")',
        'tags.add("admin_debug")',
    ]
    for token in required_tokens:
        assert token in text, "Missing Recon Logger++/Turbo token: {}".format(token)
    print("[PASS] test_recon_logger_and_turbo_intruder_features_are_wired")


def test_recon_autopopulate_and_layout_wiring():
    text = _source_text()
    required_tokens = [
        'self.recon_autopopulate_checkbox = JCheckBox(',
        '"Autopopulate",',
        'self.recon_noise_filter_checkbox = JCheckBox(',
        '"Filter Noise", bool(getattr(self, "recon_noise_filter_enabled", True))',
        "self.recon_noise_filter_checkbox.addActionListener(lambda e: self._on_filter_change())",
        "self.recon_autopopulate_checkbox.addActionListener(",
        "def _refresh_recon_and_logger_views(",
        "refresh_btn.addActionListener(lambda e: self._refresh_recon_and_logger_views())",
        "def _backfill_recon_and_logger(",
        "self._run_recon_logger_backfill_pipeline(force=force)",
        "def _run_recon_logger_backfill_pipeline(",
        "def _clear_and_refill_recon_logger(",
        "self.clear_data()",
        "def _on_recon_autopopulate_toggle(",
        "self._backfill_recon_and_logger(force=False)",
        "self._backfill_recon_and_logger(force=True)",
        "def _recon_backfill_history(",
        'backfill_now_btn = JButton("Clear + Refill")',
        "backfill_now_btn.addActionListener(",
        "backfill_now_btn: \"Clear current Recon/Logger data, then refill both from Burp Proxy history\"",
        'btn_panel = JPanel(GridLayout(2, 0, 5, 5))',
        "self.endpoint_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)",
        "self.recon_view_keys = []",
        "def _get_recon_view_key(self, index):",
        "def _recon_selected_indices(self):",
        "def _extract_endpoint_key_from_recon_value(self, raw_value):",
        "def _get_recon_selected_index(self, event=None):",
        "def _recon_show_selected_endpoint_detail(self):",
        "def _show_selected_recon_endpoint_details(self, event=None):",
        "self._recon_selected_endpoint_key = endpoint_key",
        "rows_to_add = []",
        "self.recon_view_keys = list(view_keys)",
        "endpoint_key = self.extender._get_recon_view_key(index)",
        "self.extender._recon_show_selected_endpoint_detail()",
        "self.extender._show_selected_recon_endpoint_details(event=event)",
    ]
    for token in required_tokens:
        assert token in text, "Missing Recon autopopulate/layout token: {}".format(token)

    recon_idx = text.index('self.tabbed_pane.addTab("Recon", recon_panel)')
    logger_idx = text.index('self.tabbed_pane.addTab("Logger", logger_panel)')
    diff_idx = text.index('self.tabbed_pane.addTab("Diff", diff_panel)')
    assert recon_idx < logger_idx < diff_idx, "Expected Logger tab immediately after Recon"
    print("[PASS] test_recon_autopopulate_and_layout_wiring")


def test_backfill_uses_memory_safe_proxy_history_window():
    text = _source_text()
    required_tokens = [
        "def _proxy_history_tail_window(",
        "messages = self._proxy_history_tail_window(max_seed)",
    ]
    for token in required_tokens:
        assert token in text, "Missing memory-safe backfill token: {}".format(token)
    print("[PASS] test_backfill_uses_memory_safe_proxy_history_window")

def test_import_syncs_recon_and_logger_views():
    text = _source_text()
    required_tokens = [
        "def _sync_logger_from_recon_snapshot(",
        "logger_added = int(",
        "self._sync_logger_from_recon_snapshot(",
        '"[+] Logger sync from import: {} rows added".format(logger_added)',
    ]
    for token in required_tokens:
        assert token in text, "Missing Recon/Logger import sync token: {}".format(token)
    print("[PASS] test_import_syncs_recon_and_logger_views")


def test_logger_rules_can_enrich_recon_endpoint_tags():
    text = _source_text()
    required_tokens = [
        "endpoint_tag_map = {}",
        "endpoint_key = self._ascii_safe(event_view.get(\"endpoint_key\") or \"\").strip()",
        "with self.lock:",
        "self.endpoint_tags[endpoint_key] = sorted(merged)",
        "if recon_tags_changed:",
        "self._schedule_capture_ui_refresh()",
    ]
    for token in required_tokens:
        assert token in text, "Missing logger-to-recon tag inheritance token: {}".format(token)
    print("[PASS] test_logger_rules_can_enrich_recon_endpoint_tags")


def test_logger_table_renderer_supports_colorized_tags_and_rows():
    text = _source_text()
    required_tokens = [
        "class _LoggerTableCellRenderer(DefaultTableCellRenderer):",
        "TAG_PRIORITY = [",
        "TAG_COLORS = {",
        "def _resolve_palette(self, tags, style_map):",
        "is_tag_column = int(column) == 12",
        "Tags: {} | Primary: {}",
        "logger_renderer = _LoggerTableCellRenderer(self)",
        "column_model.getColumn(col_idx).setCellRenderer(logger_renderer)",
        "column.setPreferredWidth(safe_width)",
        "column.setMinWidth(300)",
    ]
    for token in required_tokens:
        assert token in text, "Missing logger color renderer token: {}".format(token)
    print("[PASS] test_logger_table_renderer_supports_colorized_tags_and_rows")


def test_loggerplusplus_tab_long_session_controls_are_wired():
    text = _source_text()
    required_tokens = [
        "self.logger_events = []",
        "self.logger_max_rows = 5000",
        "self.logger_trim_batch = 500",
        "self._logger_refresh_min_interval_ms = 450",
        "self.logger_active_regex = \"\"",
        "self.logger_filter_library = []",
        "self.logger_tag_rules = []",
        "self._ensure_logger_default_tag_rules(force=False)",
        "def _create_logger_tab(",
        'self.tabbed_pane.addTab("Logger", logger_panel)',
        "self.logger_table_model = _LoggerTableModel(columns, 0)",
        "self.logger_row_sorter = TableRowSorter(self.logger_table_model)",
        "self.logger_table.setRowSorter(self.logger_row_sorter)",
        "Shift+click adds a second sort key.",
        'self.logger_max_rows_combo = JComboBox(["2000", "5000", "10000", "20000"])',
        'self.logger_auto_prune_checkbox = JCheckBox("Auto Prune", True)',
        'self.logger_logging_off_checkbox = JCheckBox("Logging Off", False)',
        'self.logger_import_on_open_checkbox = JCheckBox("Import on Open", True)',
        'self.logger_export_format_combo = JComboBox(["JSONL", "JSON", "CSV"])',
        'self.logger_regex_field = JTextField("", 14)',
        'self.logger_search_req_checkbox = JCheckBox("Req", True)',
        'self.logger_search_resp_checkbox = JCheckBox("Resp", True)',
        'self.logger_in_scope_checkbox = JCheckBox("In Scope", False)',
        'self.logger_noise_filter_checkbox = JCheckBox(',
        '"Filter Noise", bool(getattr(self, "logger_noise_filter_enabled", True))',
        'self.logger_len_min_field = JTextField("", 6)',
        'self.logger_len_max_field = JTextField("", 6)',
        "self.logger_filter_library_combo = JComboBox([\"(No Saved Filters)\"])",
        '"Grep Values..."',
        '"Tag Rules..."',
        'lambda e: self._show_logger_help_popup()',
        '"Pick FG"',
        '"Pick BG"',
        '"Auto Style"',
        '"Preview Rule"',
        '"Rule Lab"',
        '"Backfill History"',
        '"Select All Rows"',
        '"Copy Selected Rows"',
        '"Send Selected To Repeater"',
        '"Tag Rules (Regex)..."',
        '"Save Filter"',
        '"Apply Filter"',
        '"Remove Filter"',
        '"Search"',
        '"Reset"',
        '"Clear"',
        '"Endpoint Detail"',
        "def _logger_apply_runtime_settings(",
        "def _show_logger_help_popup(",
        "class _LoggerSelectionListener(ListSelectionListener):",
        "class _LoggerRowActionMouseListener(MouseAdapter):",
        "self.logger_table.addMouseListener(_LoggerRowActionMouseListener(self))",
        "selection_model.addListSelectionListener(_LoggerSelectionListener(self))",
        "def _logger_trim_if_needed(",
        "def _sync_recon_entry_from_logger(",
        "def _logger_capture_event(",
        "self._sync_recon_entry_from_logger(endpoint_key, entry, tags=tag_values)",
        "def _logger_count_default_request_markers(",
        "def _logger_count_default_response_markers(",
        "def _run_logger_regex_search(",
        "def _logger_collect_grep_popup_matches(",
        "def _open_logger_grep_popup(",
        "def _reset_logger_regex_search(",
        "def _save_logger_filter(",
        "def _apply_logger_filter(",
        "def _remove_logger_filter(",
        "def _open_logger_tag_rules_popup(",
        "def _compile_logger_tag_rules(",
        "def _logger_pick_color(",
        "def _logger_suggest_tag_palette(",
        "def _logger_builtin_tag_rules(",
        "def _ensure_logger_default_tag_rules(",
        '"tag": "api_endpoint",',
        '"tag": "auth",',
        '"tag": "sensitive",',
        '"tag": "idor_risk",',
        '"tag": "write_ops",',
        '"tag": "jwt",',
        "def _logger_preview_rule_matches(",
        "JColorChooser",
        "def _logger_rule_scope_text(",
        "def _logger_apply_tag_rules(",
        "tag|scope|regex|fg|bg|enabled",
        '"fg": fg_text,',
        '"bg": bg_text,',
        '"enabled": enabled,',
        "def _logger_event_matches_filters(",
        "noise_filter_enabled=False,",
        "if noise_filter_enabled and self._logger_event_is_noise(event):",
        "event[\"_grep_req\"] = self._logger_count_default_request_markers(event)",
        "event[\"_grep_resp\"] = self._logger_count_default_response_markers(event)",
        "min_len=None,",
        "max_len=None,",
        'len_text = " | Len: {}..{}".format(',
        'noise_text = " | Noise: on" if noise_filter_enabled else " | Noise: off"',
        "def _logger_event_in_scope(",
        "def _schedule_logger_ui_refresh(",
        "def _run_logger_ui_refresh(",
        "def _refresh_logger_view(",
        "def _logger_show_selected(",
        "table.convertRowIndexToModel(",
        "def _logger_select_all_rows(",
        "def _logger_copy_selected_rows(",
        "def _resolve_recon_endpoint_key(",
        "candidate_key = self._resolve_recon_endpoint_key(",
        "def _logger_show_endpoint_detail(",
        "recovered = self._sync_recon_entry_from_logger(",
        "def _show_recon_missing_detail_message(",
        "Recon does not currently have cached data for this endpoint.",
        "Recon Endpoint Details Unavailable",
        "Requested endpoint key is not present in Recon cache.",
        "def _logger_send_selected_to_repeater(",
        "def _clear_logger_logs(",
        "def _export_logger_view(",
        "def _logger_backfill_history(",
        "self._logger_backfill_history(force=False)",
        'if self.logger_import_on_open_checkbox.isSelected():',
        "bypass_capture=True",
        'selected_method = "ALL"',
        'selected_method != "ALL"',
        "self._logger_capture_event(endpoint_key, api_entry, logger_tags)",
        '" | Logging: on"',
    ]
    for token in required_tokens:
        assert token in text, "Missing Logger++ token: {}".format(token)
    print("[PASS] test_loggerplusplus_tab_long_session_controls_are_wired")


def test_shared_noise_filter_helpers_are_wired_for_recon_and_logger():
    text = _source_text()
    required_tokens = [
        "self.recon_noise_filter_enabled = True",
        "self.logger_noise_filter_enabled = True",
        "def _has_high_signal_tags(",
        "def _recon_entry_is_noise(",
        "def _endpoint_is_recon_noise(",
        "def _logger_event_is_noise(",
        "noise_filter_enabled = bool(getattr(self, \"recon_noise_filter_enabled\", True))",
        "noise_box = getattr(self, \"recon_noise_filter_checkbox\", None)",
        "if noise_filter_enabled and self._endpoint_is_recon_noise(key, entries):",
        "noise_filter_enabled = bool(getattr(self, \"logger_noise_filter_enabled\", True))",
        "noise_box = getattr(self, \"logger_noise_filter_checkbox\", None)",
        "- Filter Noise: hide noisy ad-tech/CDN/static traffic rows.",
    ]
    for token in required_tokens:
        assert token in text, "Missing shared noise-filter token: {}".format(token)
    print("[PASS] test_shared_noise_filter_helpers_are_wired_for_recon_and_logger")


def test_logger_noise_filter_keeps_noisy_write_api_hosts_filtered():
    text = _source_text()
    required_tokens = [
        "if api_signal and method in [\"POST\", \"PUT\", \"PATCH\", \"DELETE\"] and (not host_noise):",
        "extra_noise_host_markers = (",
        "\"googletagmanager.com\",",
        "\"doubleclick.net\",",
        "\"onetag-sys.com\",",
    ]
    for token in required_tokens:
        assert token in text, "Missing noisy-write-host logger filter token: {}".format(token)
    print("[PASS] test_logger_noise_filter_keeps_noisy_write_api_hosts_filtered")


def test_logger_tag_ingestion_canonicalizes_legacy_markup_tokens():
    text = _source_text()
    required_tokens = [
        "def _logger_extract_tag_tokens(self, raw_text):",
        "text = re.sub(r\"(?i)\\b(tags|primary)\\s*:\\s*\", \" \", text)",
        "text = re.sub(r\"[^a-z0-9_-]+\", \" \", text)",
        "if re.match(r\"^[0-9a-f]{3,8}$\", token):",
        "for raw_tag in list(tags or []):",
        "for clean_tag in self._logger_extract_tag_tokens(raw_tag):",
        "for raw_tag in list(self.endpoint_tags.get(endpoint_key, []) or []):",
        "tag_text = \",\".join(tag_values[:8])",
    ]
    for token in required_tokens:
        assert token in text, "Missing logger tag canonicalization token: {}".format(token)
    print("[PASS] test_logger_tag_ingestion_canonicalizes_legacy_markup_tokens")


def test_clear_data_clears_recon_and_logger_tabs():
    text = _source_text()
    required_tokens = [
        "logger_cleared = int(self._clear_logger_logs(emit_log=False) or 0)",
        "\"[+] Cleared {} endpoints and {} logger events\".format(count, logger_cleared)",
        "def _clear_logger_logs(self, emit_log=True):",
        "if emit_log:",
        '"Clear Data"',
        "lambda e: self.clear_data()",
        '"clear data": "Clear Recon + Logger captured data and reset both views"',
    ]
    for token in required_tokens:
        assert token in text, "Missing shared clear-data token: {}".format(token)
    print("[PASS] test_clear_data_clears_recon_and_logger_tabs")


def test_recon_param_miner_and_gap_features_are_wired():
    text = _source_text()
    required_tokens = [
        'hidden_params_btn = JButton("Hidden Params")',
        'param_intel_btn = JButton("Param Intel")',
        'export_param_intel_btn = JButton("Export Param Intel")',
        "hidden_params_btn.addActionListener(lambda e: self._run_recon_hidden_params())",
        "param_intel_btn.addActionListener(lambda e: self._run_recon_param_intel())",
        "export_param_intel_btn.addActionListener(lambda e: self._export_recon_param_intel())",
        "self.recon_hidden_param_results = []",
        "self.recon_param_intel_snapshot = None",
        "def _iter_recon_param_items(",
        "def _collect_hidden_param_candidates(",
        "def _score_hidden_param_candidate(",
        "def _run_recon_hidden_params(",
        "def _run_recon_hidden_params_selected(",
        "def _collect_recon_param_intelligence(",
        "def _build_recon_param_intel_report(",
        "def _run_recon_param_intel(",
        "def _export_recon_param_intel(",
        "param_intel.json",
        "param_intel_report.txt",
        '"Hidden Params (Selected Endpoint)"',
    ]
    for token in required_tokens:
        assert token in text, "Missing Recon Param Miner/GAP token: {}".format(token)
    print("[PASS] test_recon_param_miner_and_gap_features_are_wired")


def test_autorize_and_inql_features_are_wired():
    text = _source_text()
    required_tokens = [
        'self.auth_replay_check_unauth_checkbox = JCheckBox("Check Unauth", True)',
        "self.auth_replay_include_regex_field = JTextField(",
        "self.auth_replay_exclude_regex_field = JTextField(",
        "self.auth_replay_enforced_status_field = JTextField(",
        "self.auth_replay_enforced_regex_field = JTextField(",
        "self.auth_replay_methods_field = JTextField(",
        "self.auth_replay_guest_status_field = JTextField(",
        "self.auth_replay_guest_regex_field = JTextField(",
        "self.auth_replay_user_status_field = JTextField(",
        "self.auth_replay_user_regex_field = JTextField(",
        "self.auth_replay_unauth_status_field = JTextField(",
        "self.auth_replay_unauth_regex_field = JTextField(",
        "def _parse_auth_replay_status_codes(",
        "def _compile_optional_regex(",
        "def _auth_replay_detector_for_role(",
        "def _auth_replay_response_is_enforced(",
        '"by_role": by_role_detector_cfg,',
        "by_role_detector_cfg[\"guest\"]",
        "by_role_detector_cfg[\"user\"]",
        "by_role_detector_cfg[\"unauth\"]",
        "detector_cfg = {",
        "enforced_statuses",
        "include_regex=include_regex",
        "exclude_regex=exclude_regex",
        "method_allowlist=method_allowlist",
        "detector_cfg=detector_cfg",
        "compare_roles = [role for role in [\"unauth\", \"guest\", \"user\"] if role in role_results]",
        'self.graphql_schema_file_field = JTextField("", 24)',
        'lambda e: self._browse_graphql_schema_file(e),',
        'lambda e: self._generate_graphql_raider_operations(e),',
        'lambda e: self._apply_graphql_profile(e),',
        'lambda e: self._analyze_graphql_schema_file(e),',
        'lambda e: self._export_graphql_batch_queries(),',
        'lambda e: self._send_graphql_operations_to_repeater(),',
        'lambda e: self._send_graphql_operations_to_intruder(),',
        'self.graphql_raider_introspection_checkbox = JCheckBox("Introspection", True)',
        'self.graphql_raider_batching_checkbox = JCheckBox("Batching", True)',
        'self.graphql_raider_alias_checkbox = JCheckBox("Aliases", True)',
        'self.graphql_raider_depth_checkbox = JCheckBox("Depth", False)',
        'self.graphql_raider_mutation_checkbox = JCheckBox("Mutations", False)',
        'self.graphql_raider_include_schema_ops_checkbox = JCheckBox("Include Schema Ops", True)',
        'self.graphql_profile_combo = JComboBox(',
        '"Safe Recon", "Aggressive Raider"',
        'self.graphql_request_mode_combo = JComboBox(["POST JSON", "GET Query"])',
        'self.graphql_headers_field = JTextField("", 28)',
        "self.graphql_profile_combo.addActionListener(",
        "def _collect_graphql_generated_operations(",
        "def _graphql_profile_presets(",
        "def _apply_graphql_profile(",
        "def _graphql_attack_family_selection(",
        "def _collect_graphql_raider_operations(",
        "def _generate_graphql_raider_operations(",
        "def _parse_graphql_custom_headers(",
        "def _collect_graphql_delivery_operations(",
        "def _graphql_build_http_request(",
        "def _send_graphql_operations_to_repeater(",
        "def _send_graphql_operations_to_intruder(",
        'if request_mode == "get query":',
        '"[+] Sent {} generated operations to Repeater using target {}\\n"',
        '"[+] Sent {} generated operations to Intruder using target {}\\n"',
        '"[!] No GraphQL operations available. Run Analyze Schema or Generate Raider first.\\n"',
        "self.graphql_generated_operations = []",
        'self.graphql_active_profile = "Balanced"',
        'self._apply_graphql_profile(profile_name="Balanced", log_output=False)',
        "def _browse_graphql_schema_file(",
        "def _extract_graphql_schema_root(",
        "def _graphql_generate_operations_from_schema(",
        "def _graphql_schema_points_of_interest(",
        "def _graphql_detect_circular_references(",
        "def _analyze_graphql_schema_file(",
        "def _export_graphql_batch_queries(",
        "GRAPHQL SCHEMA ANALYSIS (INQL-LIKE)",
        "graphql_batch_payload.json",
    ]
    for token in required_tokens:
        assert token in text, "Missing Autorize/InQL token: {}".format(token)
    print("[PASS] test_autorize_and_inql_features_are_wired")


def test_tooltip_wiring_is_generalized():
    text = _source_text()
    required_tokens = [
        "self._configure_tooltips()",
        "def _configure_tooltips(",
        "self._apply_default_tooltips_recursively(self._panel)",
        "ToolTipManager.sharedInstance()",
        "def _set_component_tooltip(",
        "def _apply_component_tooltips(",
        "def _apply_default_tooltips_recursively(",
        "def _resolve_action_button_tooltip(",
        "def _resolve_checkbox_tooltip(",
        "self._set_component_tooltip(",
        "self._resolve_action_button_tooltip(text, tooltip)",
        "self._apply_component_tooltips(",
        "\"copy\": \"Copy this tab output text to your system clipboard for AI/reports\"",
        "\"clear\": \"Clear this tab output panel only (does not delete Recon capture data)\"",
        "\"run verify\": \"Run verifier against ranked candidates and keep evidence in this tab output\"",
        "if lower_label.startswith(\"run \"):",
        "if lower_label.startswith(\"stop \"):",
        "if lower_label.startswith(\"export \"):",
        "return \"Run '{}' using current tab context and controls\".format(normalized)",
        "tooltip_text = text if isinstance(text, text_type) else text_type(text)",
        "component.setToolTipText(tooltip_text if tooltip_text else None)",
        "help_btn: \"Show what each Recon button does\"",
        "refresh_btn: \"Refresh both Recon and Logger views from current in-memory data\"",
    ]
    for token in required_tokens:
        assert token in text, "Missing generalized tooltip token: {}".format(token)
    print("[PASS] test_tooltip_wiring_is_generalized")


def test_new_verification_and_discovery_tabs_are_wired():
    text = _source_text()
    required_tokens = [
        'self.tabbed_pane.addTab("Sqlmap", sqlmap_verify_panel)',
        'self.tabbed_pane.addTab("Dalfox", dalfox_verify_panel)',
        'self.tabbed_pane.addTab("Subfinder", asset_discovery_panel)',
        'self.tabbed_pane.addTab("OpenAPI Drift", openapi_drift_panel)',
        'self.tabbed_pane.addTab("GraphQL", graphql_panel)',
        "def _create_sqlmap_verify_tab(",
        "def _create_dalfox_verify_tab(",
        "def _create_api_asset_discovery_tab(",
        "def _create_openapi_drift_tab(",
        "def _create_graphql_tab(",
        "def _run_sqlmap_verify(",
        "def _run_dalfox_verify(",
        "def _run_api_asset_discovery(",
        "def _run_openapi_drift(",
        "def _run_graphql_analysis(",
        "def _send_sqlmap_to_recon(",
        "def _send_dalfox_to_recon(",
        "def _send_asset_discovery_to_recon(",
        "def _send_openapi_to_recon(",
        "def _send_graphql_to_recon(",
        "def _export_sqlmap_results(",
        "def _export_dalfox_results(",
        "def _export_asset_discovery_results(",
        "def _export_openapi_drift_results(",
        "def _export_graphql_results(",
        "[MISSING] {}",
        "[*] Tool: ",
        "[*] CMD: ",
    ]
    for token in required_tokens:
        assert token in text, "Missing new tab wiring token: {}".format(token)
    print("[PASS] test_new_verification_and_discovery_tabs_are_wired")


def test_tool_profiles_and_health_button_are_wired():
    text = _source_text()
    required_tokens = [
        'tool_health_btn = JButton("Tool Health")',
        "tool_health_btn.addActionListener(lambda e: self._run_tool_health_check(e))",
        "def _run_tool_health_check(",
        "def _tool_health_specs(",
        "def _resolve_tool_health_path(",
        "def _normalize_profile(",
        "def _evaluate_help_text(",
        'self.sqlmap_profile_combo = JComboBox(self._profile_labels())',
        'self.dalfox_profile_combo = JComboBox(self._profile_labels())',
        'self.asset_profile_combo = JComboBox(self._profile_labels())',
        'self.asset_custom_cmd_checkbox = JCheckBox("Enable Custom", False)',
        'self.asset_custom_cmd_field = JTextField("", 35)',
        'self.nuclei_profile_combo = JComboBox(self._profile_labels())',
        "def _build_sqlmap_command(",
        "def _build_dalfox_command(",
        "def _asset_profile_settings(",
        "def _nuclei_profile_settings(",
    ]
    for token in required_tokens:
        assert token in text, "Missing tool profile/health token: {}".format(token)
    assert "import tool_profiles" not in text, "Legacy tool_profiles import should be removed"
    print("[PASS] test_tool_profiles_and_health_button_are_wired")


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
        'capture_path = os.path.join(temp_dir, "nuclei_runtime.log")',
        "with open(capture_path, \"rb\") as capture_reader:",
        "combined_output = self._decode_process_data(",
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
        '"-bs",',
        '"bulk_size", self.NUCLEI_BULK_SIZE',
        '"-mhe",',
        '"max_host_error",',
        '"-ss",',
        '"scan_strategy", self.NUCLEI_SCAN_STRATEGY',
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
        '["pkill", "-TERM", "-f", pattern]',
        '["killall", "-q", pattern]',
        '["taskkill", "/IM", name, "/F", "/T"]',
    ]
    for token in required_tokens:
        assert token in text, "Missing emergency kill token: {}".format(token)
    for area_name in [
        "nuclei_area",
        "httpx_area",
        "katana_area",
        "ffuf_area",
        "wayback_area",
    ]:
        token = 'lambda: getattr(self, "{}", None)'.format(area_name)
        assert token in text, "Missing emergency kill area binding: {}".format(area_name)
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
    command_label_hits = (
        text.count('controls.add(JLabel("Command:"))')
        + text.count('controls_line1.add(JLabel("Command:"))')
    )
    assert command_label_hits >= 4
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


def test_ai_export_bundle_contains_rich_context_and_llm_formats():
    text = _source_text()
    required_tokens = [
        "def _build_ai_export_bundle(",
        "def _collect_all_tabs_ai_context(",
        "def _export_vulnerability_context_for_ai(",
        "def _snapshot_list_attr(",
        "def _snapshot_text_area(",
        "def _sanitize_for_ai_payload(",
        "def _extract_response_patterns(",
        "def _extract_error_signatures(",
        "def _format_ai_sample(",
        "def _sanitize_headers_for_ai(",
        "def _sanitize_text_for_ai(",
        "def _export_behavioral_analysis(",
        "def _analyze_param_dependencies(",
        "def _create_ai_feedback_loop_export(",
        "def _export_for_llm_platform(",
        "def _export_openai_format(",
        "def _export_anthropic_format(",
        "def _export_ollama_format(",
        "def _find_similar_endpoints(",
        "def _generate_enhanced_ai_prompt(",
        "ai_vulnerability_context.json",
        "ai_all_tabs_context.json",
        "ai_behavioral_analysis.json",
        "ai_feedback_template.json",
        "ai_openai_request.json",
        "ai_anthropic_request.json",
        "ai_ollama_request.json",
        "ai_golden_ticket_findings.json",
        "ai_golden_ticket_ledger.json",
        "ai_state_transition_findings.json",
        "ai_state_transition_ledger.json",
        "\"golden_tickets\": golden_tickets,",
        "\"state_transitions\": state_transitions,",
        "def _build_golden_ticket_package(",
        "def _build_state_transition_package(",
        "def _sort_and_store_golden_ticket_payload(",
        "def _sort_and_store_state_transition_payload(",
    ]
    for token in required_tokens:
        assert token in text, "Missing enhanced AI export token: {}".format(token)
    print("[PASS] test_ai_export_bundle_contains_rich_context_and_llm_formats")


def test_ai_sanitizer_preserves_numeric_count_fields():
    text = _source_text()
    required_tokens = [
        "def _sanitize_for_ai_payload(",
        'if key_lower.endswith("_count"):',
        "if isinstance(val, (int, float)):",
        'if value_text and re.match(r"^-?\\d+$", value_text):',
        "sanitized[safe_key] = int(value_text)",
        'sanitized[safe_key] = "<redacted>"',
    ]
    for token in required_tokens:
        assert token in text, "Missing sanitizer count-preservation token: {}".format(
            token
        )
    print("[PASS] test_ai_sanitizer_preserves_numeric_count_fields")


def test_ai_prep_layer_exports_are_additive_and_non_destructive():
    text = _source_text()
    required_tokens = [
        "AI_PREP_LAYER_ENV_VAR = \"AI_PREP_LAYER\"",
        "def _ai_prep_layer_enabled(",
        "def _build_ai_prep_layer(",
        "def _build_ai_prep_invariant_hints(",
        "def _build_ai_prep_sequence_candidates(",
        "def _build_ai_prep_evidence_graph(",
        "\"ai_prep_layer\": ai_prep_layer,",
        "if self._ai_prep_layer_enabled():",
        "ai_prep_invariant_hints.json",
        "ai_prep_sequence_candidates.json",
        "ai_prep_evidence_graph.json",
        "No endpoint filtering or suppression is applied in runtime scanning.",
    ]
    for token in required_tokens:
        assert token in text, "Missing AI prep layer token: {}".format(token)
    print("[PASS] test_ai_prep_layer_exports_are_additive_and_non_destructive")


def test_sequence_invariants_and_ledger_are_wired():
    text = _source_text()
    required_tokens = [
        "import behavior_analysis",
        "import burp_counterfactual_methods",
        "actions_row = JPanel(FlowLayout(FlowLayout.LEFT))",
        "deep_logic_row = JPanel(FlowLayout(FlowLayout.LEFT))",
        "deep_logic_row.add(JLabel(\"Deep Logic:\"))",
        "Non-destructive deep logic checks. Includes scoreless differential invariants plus Sequence/Golden/State analysis.",
        'refresh_invariants_btn = JButton("Refresh Invariants")',
        "self.recon_invariant_status_label = JLabel(\"\")",
        "def _refresh_sequence_invariants_from_recon(",
        "def _refresh_recon_invariant_status_label(",
        "def _build_recon_invariant_status_text(",
        "self._refresh_recon_invariant_status_label()",
        '"Run Invariants",',
        '"Run Differential",',
        '"Export Ledger",',
        '"Run All Advanced",',
        '"Abuse Chains",',
        '"Proof Mode",',
        '"Spec Guardrails",',
        '"Role Delta",',
        "def _run_counterfactual_differentials(",
        "def _build_counterfactual_differential_package(",
        "def _sort_and_store_counterfactual_payload(",
        "def _format_counterfactual_output(",
        "def _run_sequence_invariants(",
        "def _build_sequence_invariant_package(",
        "def _build_golden_ticket_package(",
        "def _build_state_transition_package(",
        "def _build_advanced_logic_packages(",
        "def _store_advanced_logic_packages(",
        "def _format_advanced_logic_output(",
        "def _run_abuse_chain_builder(",
        "def _run_all_advanced_logic(",
        "def _run_proof_mode(",
        "def _run_spec_guardrails(",
        "def _run_role_delta_engine(",
        "\"abuse_chain_findings.json\"",
        "\"proof_mode_packet_sets.json\"",
        "\"spec_guardrails_rules.json\"",
        "\"spec_guardrails_violations.json\"",
        "\"role_delta_findings.json\"",
        "\"role_delta_ledger.json\"",
        "behavior_analysis.build_sequence_invariant_package(",
        "behavior_analysis.build_golden_ticket_package(",
        "behavior_analysis.build_state_transition_package(",
        "def _format_golden_ticket_output(",
        "def _format_state_transition_output(",
        "def _export_sequence_invariant_ledger(",
        "\"counterfactual_differential_findings.json\"",
        "\"counterfactual_differential_summary.json\"",
        "\"sequence_invariant_findings.json\"",
        "\"sequence_evidence_ledger.json\"",
        "\"golden_ticket_findings.json\"",
        "\"golden_ticket_ledger.json\"",
        "\"state_transition_findings.json\"",
        "\"state_transition_ledger.json\"",
        "\"ai_counterfactual_differential_findings.json\"",
        "\"ai_counterfactual_differential_summary.json\"",
        "\"ai_sequence_invariant_findings.json\"",
        "\"ai_sequence_evidence_ledger.json\"",
        "\"ai_golden_ticket_findings.json\"",
        "\"ai_golden_ticket_ledger.json\"",
        "\"ai_state_transition_findings.json\"",
        "\"ai_state_transition_ledger.json\"",
        "\"counterfactual_differentials\": counterfactual_differentials,",
        "\"sequence_invariants\": sequence_invariants,",
        "\"golden_tickets\": golden_tickets,",
        "\"state_transitions\": state_transitions,",
        "\"counterfactual_differential_count\"",
        "\"counterfactual_differentials\": {",
        "\"counterfactual_meta\"",
        "\"sequence_invariants\": {",
        "\"sequence_invariant_meta\"",
        "\"golden_tickets\": {",
        "\"golden_ticket_meta\"",
        "\"state_transitions\": {",
        "\"state_transition_meta\"",
        "source_label=\"ai_export\"",
        "def _snapshot_dict_attr(",
    ]
    for token in required_tokens:
        assert token in text, "Missing sequence invariant wiring token: {}".format(token)
    print("[PASS] test_sequence_invariants_and_ledger_are_wired")


def test_heavy_runner_methods_are_delegated_for_jython_compile_safety():
    text = _source_text()
    required_tokens = [
        "import heavy_runners",
        "def _run_graphql_analysis(self, event):",
        "return heavy_runners._run_graphql_analysis(self, event)",
        "def _run_nuclei(self):",
        "return heavy_runners._run_nuclei(self)",
        "def _run_httpx(self, event):",
        "return heavy_runners._run_httpx(self, event)",
        "def _run_katana(self, event):",
        "return heavy_runners._run_katana(self, event)",
        "def _run_ffuf(self, event):",
        "return heavy_runners._run_ffuf(self, event)",
        "def _run_wayback(self):",
        "return heavy_runners._run_wayback(self)",
        "Heavy external-tool runner methods extracted to reduce Jython method size pressure.",
    ]
    for token in required_tokens:
        assert token in text, "Missing heavy-runner delegation token: {}".format(token)
    print("[PASS] test_heavy_runner_methods_are_delegated_for_jython_compile_safety")


def test_golden_ticket_logic_is_extracted_to_dedicated_module():
    text = _source_text()
    required_tokens = [
        "import golden_ticket_analysis",
        "def build_golden_ticket_findings(data_snapshot, get_entry=None):",
        "return golden_ticket_analysis.build_golden_ticket_findings(",
        "def build_golden_ticket_package(data_snapshot, get_entry=None):",
        "return golden_ticket_analysis.build_golden_ticket_package(",
        "def _build_golden_ticket_package(",
    ]
    for token in required_tokens:
        assert token in text, "Missing extracted golden-ticket token: {}".format(token)
    print("[PASS] test_golden_ticket_logic_is_extracted_to_dedicated_module")


def test_state_transition_logic_is_extracted_to_dedicated_module():
    text = _source_text()
    required_tokens = [
        "import state_transition_analysis",
        "def build_state_transition_findings(data_snapshot, get_entry=None):",
        "return state_transition_analysis.build_state_transition_findings(",
        "def build_state_transition_package(data_snapshot, get_entry=None):",
        "return state_transition_analysis.build_state_transition_package(",
        "def _build_state_transition_package(",
    ]
    for token in required_tokens:
        assert token in text, "Missing extracted state-transition token: {}".format(token)
    print("[PASS] test_state_transition_logic_is_extracted_to_dedicated_module")


def test_checkbox_state_persistence_is_wired():
    text = _source_text()
    required_tokens = [
        "_PERSISTED_CHECKBOX_ATTRS",
        "def _load_bool_setting(",
        "def _save_bool_setting(",
        "def _persist_checkbox_attr(",
        "def _restore_persisted_ui_state(",
        "self._restore_persisted_ui_state()",
        "self._callbacks.loadExtensionSetting(",
        "self._callbacks.saveExtensionSetting(",
        "target_base_scope_only_enabled",
        'self._save_bool_setting("target_base_scope_only_enabled", desired)',
        "lambda _event, name=attr_name: self._persist_checkbox_attr(name)",
    ]
    for token in required_tokens:
        assert token in text, "Missing checkbox persistence token: {}".format(token)
    print("[PASS] test_checkbox_state_persistence_is_wired")


def test_text_and_combo_field_persistence_is_wired():
    text = _source_text()
    required_tokens = [
        "_PERSISTED_TEXT_ATTRS",
        "_PERSISTED_COMBO_ATTRS",
        "class _PersistTextFieldListener(DocumentListener):",
        "def _load_text_setting(",
        "def _save_text_setting(",
        "def _persist_text_attr(",
        "def _combo_contains_item(",
        "def _persist_combo_attr(",
        'self._save_text_setting("text.{}".format(attr_name), value)',
        'self._save_text_setting("combo.{}".format(attr_name), self._ascii_safe(selected or ""))',
        "_PersistTextFieldListener(self, attr_name)",
        "combo.addActionListener(",
        'scope_lines_text = self._load_text_setting("target_base_scope_lines", scope_lines_default)',
        'self._save_text_setting(',
        '"target_base_scope_lines", "\\n".join(self.target_base_scope_lines)',
    ]
    for token in required_tokens:
        assert token in text, "Missing text/combo persistence token: {}".format(token)
    print("[PASS] test_text_and_combo_field_persistence_is_wired")


def test_logger_popup_persistence_is_wired():
    text = _source_text()
    required_tokens = [
        "def _persist_logger_filter_library(",
        "def _restore_logger_filter_library(",
        "def _persist_logger_tag_rules(",
        "def _restore_logger_tag_rules(",
        "def _restore_logger_popup_persistence(",
        "self._restore_logger_popup_persistence()",
        'self._load_text_setting("logger_popup.grep_pattern", inline_pattern)',
        'self._save_text_setting(',
        '"logger_popup.grep_pattern", self._ascii_safe(regex_field.getText() or "")',
        '"logger_popup.grep_req"',
        '"logger_popup.grep_resp"',
        '"logger_popup.grep_scope"',
        '"logger_filter_library_json"',
        '"logger_tag_rules_json"',
        '"logger_popup.tag.quick_tag"',
        '"logger_popup.tag.quick_scope"',
        '"logger_popup.tag.quick_regex"',
        '"logger_popup.tag.quick_fg"',
        '"logger_popup.tag.quick_bg"',
        '"logger_popup.tag.quick_enabled"',
        "self._persist_logger_filter_library()",
        "self._persist_logger_tag_rules()",
    ]
    for token in required_tokens:
        assert token in text, "Missing logger popup persistence token: {}".format(token)
    print("[PASS] test_logger_popup_persistence_is_wired")


def test_ai_export_actions_are_wired_across_outputs():
    text = _source_text()
    required_tokens = [
        'ai_item = JMenuItem("Send to AI Analysis")',
        'item_send_ai = JMenuItem("Send Selected To AI Analysis")',
        "def _send_endpoint_to_ai(",
        "def _logger_send_selected_to_ai(",
        "def _build_entry_request_text(",
        "def _build_entry_curl_command(",
        "SMART PROMPT:",
        "READY CURL:",
        "FULL HTTP REQUEST:",
        "def _export_text_output_to_ai(",
    ]
    for token in required_tokens:
        assert token in text, "Missing AI export token: {}".format(token)
    assert text.count('"To AI"') >= 12
    print("[PASS] test_ai_export_actions_are_wired_across_outputs")
