# -*- coding: utf-8 -*-
"""Large BurpExtender methods extracted to reduce Jython compile-size pressure."""

import threading
import time

from java.awt import BorderLayout, Color, Dimension, FlowLayout
from javax.swing import (
    BorderFactory,
    BoxLayout,
    JCheckBox,
    JComboBox,
    JLabel,
    JPanel,
    JScrollPane,
    JSplitPane,
    JTable,
    JTextField,
    SwingUtilities,
)
from javax.swing.table import DefaultTableModel


class _AuthReplayTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

def create_auth_replay_tab(extender):
    self = extender
    """Create Auth Replay tab for multi-role authorization checks."""
    panel = JPanel(BorderLayout())
    top_controls = JPanel(FlowLayout(FlowLayout.LEFT))
    top_controls.add(JLabel("Scope:"))
    self.auth_replay_scope_combo = JComboBox(
        ["Selected Endpoint", "Filtered View", "All Endpoints"]
    )
    self.auth_replay_scope_combo.setSelectedItem("All Endpoints")
    top_controls.add(self.auth_replay_scope_combo)
    top_controls.add(JLabel("Max:"))
    self.auth_replay_max_field = JTextField("50", 4)
    top_controls.add(self.auth_replay_max_field)
    self.auth_replay_check_unauth_checkbox = JCheckBox("Check Unauth", True)
    self.auth_replay_check_unauth_checkbox.setToolTipText(
        "Replay each request without auth header and evaluate enforcement."
    )
    top_controls.add(self.auth_replay_check_unauth_checkbox)
    top_controls.add(
        self._create_action_button(
            "Run Replay", Color(220, 53, 69), lambda e: self._run_auth_replay(e)
        )
    )
    top_controls.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_auth_replay(e)
        )
    )
    top_controls.add(
        self._create_action_button(
            "Clear Table",
            Color(108, 117, 125),
            lambda e: _clear_auth_replay_views(self),
        )
    )
    top_controls.add(
        self._create_action_button(
            "Copy",
            Color(70, 130, 180),
            lambda e: self._copy_to_clipboard(self.auth_replay_area.getText()),
        )
    )
    top_controls.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "Auth Replay", self.auth_replay_area.getText()
            ),
        )
    )
    panel.add(top_controls, BorderLayout.NORTH)

    config_container = JPanel()
    config_container.setLayout(BoxLayout(config_container, BoxLayout.Y_AXIS))
    config_container.setBorder(
        BorderFactory.createTitledBorder("Configuration / Profiles")
    )

    profiles_panel = JPanel()
    profiles_panel.setLayout(BoxLayout(profiles_panel, BoxLayout.Y_AXIS))
    profiles_panel.setBorder(BorderFactory.createTitledBorder("Headers"))
    guest_row = JPanel(FlowLayout(FlowLayout.LEFT))
    guest_row.add(JLabel("Guest Header:"))
    self.auth_guest_header_field = JTextField("", 45)
    self.auth_guest_header_field.setToolTipText(
        "Optional. Format: Header-Name: value (example: Cookie: session=...)"
    )
    guest_row.add(self.auth_guest_header_field)
    guest_row.add(
        self._create_action_button(
            "Extract",
            Color(40, 167, 69),
            lambda e: self._extract_auth_profile_header("guest"),
        )
    )
    profiles_panel.add(guest_row)

    user_row = JPanel(FlowLayout(FlowLayout.LEFT))
    user_row.add(JLabel("User Header:"))
    self.auth_user_header_field = JTextField("", 46)
    self.auth_user_header_field.setToolTipText(
        "Optional but recommended. Format: Authorization: Bearer <user_token>"
    )
    user_row.add(self.auth_user_header_field)
    user_row.add(
        self._create_action_button(
            "Extract",
            Color(40, 167, 69),
            lambda e: self._extract_auth_profile_header("user"),
        )
    )
    profiles_panel.add(user_row)

    admin_row = JPanel(FlowLayout(FlowLayout.LEFT))
    admin_row.add(JLabel("Admin Header:"))
    self.auth_admin_header_field = JTextField("", 45)
    self.auth_admin_header_field.setToolTipText(
        "Optional but recommended. Format: Authorization: Bearer <admin_token>"
    )
    admin_row.add(self.auth_admin_header_field)
    admin_row.add(
        self._create_action_button(
            "Extract",
            Color(40, 167, 69),
            lambda e: self._extract_auth_profile_header("admin"),
        )
    )
    profiles_panel.add(admin_row)
    config_container.add(profiles_panel)

    filters_panel = JPanel()
    filters_panel.setLayout(BoxLayout(filters_panel, BoxLayout.Y_AXIS))
    filters_panel.setBorder(BorderFactory.createTitledBorder("Filters"))
    filter_row = JPanel(FlowLayout(FlowLayout.LEFT))
    filter_row.add(JLabel("Include Regex:"))
    self.auth_replay_include_regex_field = JTextField("", 34)
    self.auth_replay_include_regex_field.setToolTipText(
        "Optional. Only replay endpoint keys that match this regex."
    )
    filter_row.add(self.auth_replay_include_regex_field)
    filters_panel.add(filter_row)

    filter_row_exclude = JPanel(FlowLayout(FlowLayout.LEFT))
    filter_row_exclude.add(JLabel("Exclude Regex:"))
    self.auth_replay_exclude_regex_field = JTextField(
        r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf)$", 34
    )
    self.auth_replay_exclude_regex_field.setToolTipText(
        "Optional. Skip endpoint keys that match this regex."
    )
    filter_row_exclude.add(self.auth_replay_exclude_regex_field)
    filters_panel.add(filter_row_exclude)

    methods_row = JPanel(FlowLayout(FlowLayout.LEFT))
    methods_row.add(JLabel("Methods:"))
    self.auth_replay_methods_field = JTextField("GET,POST,PUT,PATCH,DELETE", 33)
    self.auth_replay_methods_field.setToolTipText(
        "Optional comma-separated methods to include in replay."
    )
    methods_row.add(self.auth_replay_methods_field)
    filters_panel.add(methods_row)
    config_container.add(filters_panel)

    detector_panel = JPanel()
    detector_panel.setLayout(BoxLayout(detector_panel, BoxLayout.Y_AXIS))
    detector_panel.setBorder(BorderFactory.createTitledBorder("Unauth Detection"))
    detector_row = JPanel(FlowLayout(FlowLayout.LEFT))
    detector_row.add(JLabel("Enforced Status:"))
    self.auth_replay_enforced_status_field = JTextField("401,403", 9)
    self.auth_replay_enforced_status_field.setToolTipText(
        "Comma-separated status codes treated as enforced responses."
    )
    detector_row.add(self.auth_replay_enforced_status_field)
    detector_row.add(JLabel("Enforced Regex:"))
    self.auth_replay_enforced_regex_field = JTextField(
        r"unauthori|forbidden|access denied|not allow|permission", 34
    )
    self.auth_replay_enforced_regex_field.setToolTipText(
        "Regex that marks low-privileged response as enforced."
    )
    detector_row.add(self.auth_replay_enforced_regex_field)
    detector_panel.add(detector_row)

    profile_detector_row = JPanel(FlowLayout(FlowLayout.LEFT))
    profile_detector_row.add(JLabel("Guest Status:"))
    self.auth_replay_guest_status_field = JTextField("", 7)
    self.auth_replay_guest_status_field.setToolTipText(
        "Optional guest-only enforced status override (comma-separated)."
    )
    profile_detector_row.add(self.auth_replay_guest_status_field)
    profile_detector_row.add(JLabel("Guest Regex:"))
    self.auth_replay_guest_regex_field = JTextField("", 16)
    self.auth_replay_guest_regex_field.setToolTipText(
        "Optional guest-only enforced regex override."
    )
    profile_detector_row.add(self.auth_replay_guest_regex_field)
    profile_detector_row.add(JLabel("User Status:"))
    self.auth_replay_user_status_field = JTextField("", 7)
    self.auth_replay_user_status_field.setToolTipText(
        "Optional user-only enforced status override (comma-separated)."
    )
    profile_detector_row.add(self.auth_replay_user_status_field)
    profile_detector_row.add(JLabel("User Regex:"))
    self.auth_replay_user_regex_field = JTextField("", 16)
    self.auth_replay_user_regex_field.setToolTipText(
        "Optional user-only enforced regex override."
    )
    profile_detector_row.add(self.auth_replay_user_regex_field)
    profile_detector_row.add(JLabel("Unauth Status:"))
    self.auth_replay_unauth_status_field = JTextField("", 7)
    self.auth_replay_unauth_status_field.setToolTipText(
        "Optional unauth-only enforced status override (comma-separated)."
    )
    profile_detector_row.add(self.auth_replay_unauth_status_field)
    profile_detector_row.add(JLabel("Unauth Regex:"))
    self.auth_replay_unauth_regex_field = JTextField("", 16)
    self.auth_replay_unauth_regex_field.setToolTipText(
        "Optional unauth-only enforced regex override."
    )
    profile_detector_row.add(self.auth_replay_unauth_regex_field)
    detector_panel.add(profile_detector_row)
    config_container.add(detector_panel)

    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(
        JLabel(
            "Autorize-like layout: results table on left, replay settings on right."
        )
    )
    config_container.add(help_row)

    columns = [
        "ID",
        "Method",
        "URL",
        "Orig Len",
        "Orig Status",
        "Unauth Len",
        "Unauth Status",
        "Guest Len",
        "Guest Status",
        "User Len",
        "User Status",
        "Admin Len",
        "Admin Status",
        "Result",
    ]
    self.auth_replay_table_model = _AuthReplayTableModel(columns, 0)
    self.auth_replay_table = JTable(self.auth_replay_table_model)
    self.auth_replay_table.setFillsViewportHeight(True)
    self.auth_replay_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)

    table_scroll = JScrollPane(self.auth_replay_table)
    table_scroll.setBorder(BorderFactory.createTitledBorder("Replay Results"))

    self.auth_replay_area, log_scroll = self._create_text_area_panel()
    log_scroll.setBorder(BorderFactory.createTitledBorder("Replay Output"))

    left_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, log_scroll)
    left_split.setResizeWeight(0.66)

    right_scroll = JScrollPane(config_container)
    right_scroll.setPreferredSize(Dimension(620, 200))

    center_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_split, right_scroll)
    center_split.setResizeWeight(0.72)
    panel.add(center_split, BorderLayout.CENTER)
    self.auth_replay_findings = []
    self.auth_replay_lock = threading.Lock()
    return panel


def _clear_auth_replay_views(extender):
    self = extender
    if getattr(self, "auth_replay_table_model", None) is not None:
        self.auth_replay_table_model.setRowCount(0)
    if getattr(self, "auth_replay_area", None) is not None:
        self.auth_replay_area.setText("")
    if getattr(self, "auth_replay_lock", None) is not None:
        with self.auth_replay_lock:
            self.auth_replay_findings = []


def _auth_replay_primary_role(role_results):
    if "admin" in role_results:
        return "admin"
    if "user" in role_results:
        return "user"
    if "guest" in role_results:
        return "guest"
    if "unauth" in role_results:
        return "unauth"
    return None


def _auth_replay_table_value(role_results, role_name, field_name):
    data = role_results.get(role_name)
    if not data:
        return "-"
    if data.get("error"):
        return "ERR"
    value = int(data.get(field_name, 0) or 0)
    return str(value)


def _auth_replay_row_summary(endpoint_findings, role_results):
    if endpoint_findings:
        severity_rank = {"critical": 0, "high": 1, "medium": 2}
        sorted_findings = sorted(
            endpoint_findings,
            key=lambda x: severity_rank.get(
                (x.get("severity") or "medium").lower(), 3
            ),
        )
        top = sorted_findings[0]
        sev = (top.get("severity") or "medium").upper()
        return "{} ({})".format(sev, len(endpoint_findings))
    error_count = 0
    for role_data in role_results.values():
        if role_data.get("error"):
            error_count += 1
    if error_count:
        return "ERROR ({})".format(error_count)
    return "OK"


def _auth_replay_build_result_row(
    extender, row_id, endpoint_key, entry, role_results, endpoint_findings
):
    self = extender
    method = self._ascii_safe(entry.get("method") or "GET").upper()
    protocol = (
        self._ascii_safe(entry.get("protocol") or "https", lower=True).strip()
        or "https"
    )
    host = self._ascii_safe(entry.get("host") or "").strip()
    path = self._ascii_safe(entry.get("path") or "/")
    query = self._ascii_safe(entry.get("query_string") or "")
    if query:
        path = "{}?{}".format(path, query)
    if host:
        url = "{}://{}{}".format(protocol, host, path)
    else:
        url = self._ascii_safe(endpoint_key)

    primary_role = _auth_replay_primary_role(role_results)
    if primary_role:
        orig_len = _auth_replay_table_value(role_results, primary_role, "length")
        orig_status = _auth_replay_table_value(role_results, primary_role, "status")
    else:
        orig_len = "-"
        orig_status = "-"

    return [
        str(row_id),
        method,
        url,
        orig_len,
        orig_status,
        _auth_replay_table_value(role_results, "unauth", "length"),
        _auth_replay_table_value(role_results, "unauth", "status"),
        _auth_replay_table_value(role_results, "guest", "length"),
        _auth_replay_table_value(role_results, "guest", "status"),
        _auth_replay_table_value(role_results, "user", "length"),
        _auth_replay_table_value(role_results, "user", "status"),
        _auth_replay_table_value(role_results, "admin", "length"),
        _auth_replay_table_value(role_results, "admin", "status"),
        _auth_replay_row_summary(endpoint_findings, role_results),
    ]

def collect_nuclei_targets(extender):
    self = extender
    """Collect scoped Nuclei targets without cross-host path cartesian expansion."""
    static_skip_parts = set(
        [
            "js",
            "css",
            "static",
            "dist",
            "assets",
            "images",
            "img",
            "fonts",
            "cdn-cgi",
            "captcha",
            "recaptcha",
            "player",
        ]
    )

    with self.lock:
        entries_snapshot = [self._get_entry(entries) for entries in self.api_data.values()]

    scope_override = self._get_target_scope_override()
    host_counts = {}
    base_scores = {}
    for entry in entries_snapshot:
        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        if not host:
            continue
        if scope_override.get("enabled") and not self._host_matches_target_scope(
            host, scope_override
        ):
            continue
        host_counts[host] = host_counts.get(host, 0) + 1
        if (not scope_override.get("enabled")) and self._is_wayback_noise_host(host):
            continue

        base = self._infer_base_domain(host)
        if not base:
            continue

        score = 1
        method = self._ascii_safe(entry.get("method"), lower=True).strip()
        if method in ["post", "put", "patch", "delete"]:
            score += 2

        path = self._ascii_safe(entry.get("normalized_path") or "/", lower=True)
        parts = [p for p in path.strip("/").split("/") if p]
        if parts:
            first_part = parts[0]
            if first_part.startswith("api") or first_part in [
                "v1",
                "v2",
                "v3",
                "v4",
                "graphql",
                "rest",
                "svc",
                "internal",
                "auth",
                "oauth",
            ]:
                score += 3
        base_scores[base] = base_scores.get(base, 0) + score

    if scope_override.get("enabled"):
        selected_host = "target-bases"
        force_host = False
        allowed_bases = set(scope_override.get("bases", set()))
    else:
        selected_host = "all"
        try:
            if hasattr(self, "host_filter") and self.host_filter is not None:
                selected_host = self._ascii_safe(
                    str(self.host_filter.getSelectedItem()), lower=True
                ).strip()
        except Exception as e:
            self._callbacks.printError("Nuclei host-filter read error: {}".format(str(e)))
            selected_host = "all"
        force_host = bool(selected_host and selected_host != "all")

        sorted_bases = sorted(base_scores.items(), key=lambda item: (-item[1], item[0]))
        allowed_bases = set([base for base, _ in sorted_bases[:1]])
        if not allowed_bases:
            fallback_bases = {}
            for host, count in host_counts.items():
                if self._is_wayback_noise_host(host):
                    continue
                base = self._infer_base_domain(host)
                if not base:
                    continue
                fallback_bases[base] = fallback_bases.get(base, 0) + count
            fallback_sorted = sorted(
                fallback_bases.items(), key=lambda item: (-item[1], item[0])
            )
            allowed_bases = set([base for base, _ in fallback_sorted[:1]])

    dropped_noise_host = 0
    dropped_scope_host = 0
    dropped_path = 0
    inspected_entries = 0
    candidates = set()
    for entry in entries_snapshot:
        inspected_entries += 1
        protocol = self._ascii_safe(entry.get("protocol"), lower=True).strip() or "https"
        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        if not host:
            dropped_scope_host += 1
            continue

        if scope_override.get("enabled"):
            if not self._host_matches_target_scope(host, scope_override):
                dropped_scope_host += 1
                continue
        elif force_host:
            if host != selected_host:
                dropped_scope_host += 1
                continue
        else:
            if self._is_wayback_noise_host(host):
                dropped_noise_host += 1
                continue
            host_base = self._infer_base_domain(host)
            if allowed_bases and host_base not in allowed_bases:
                dropped_scope_host += 1
                continue

        port = entry.get("port", -1)
        if port == -1:
            port = 443 if protocol == "https" else 80
        if (protocol == "https" and port == 443) or (
            protocol == "http" and port == 80
        ):
            base = "{}://{}".format(protocol, host)
        else:
            base = "{}://{}:{}".format(protocol, host, port)

        candidates.add(base)

        raw_path = self._ascii_safe(entry.get("normalized_path") or "/")
        parts = [self._ascii_safe(part, lower=True).strip() for part in raw_path.strip("/").split("/") if part]
        if not parts:
            continue

        first_part = parts[0]
        if first_part in static_skip_parts or self._ffuf_is_noise_path_segment(first_part):
            dropped_path += 1
            continue

        candidates.add(base + "/" + first_part)

        if first_part == "api" and len(parts) > 1:
            second_part = parts[1]
            if (
                second_part
                and second_part not in static_skip_parts
                and not self._ffuf_is_noise_path_segment(second_part)
            ):
                candidates.add(base + "/api/" + second_part)

        if first_part.startswith("v") and len(parts) > 1:
            second_part = parts[1]
            if (
                second_part
                and second_part not in static_skip_parts
                and not self._ffuf_is_noise_path_segment(second_part)
            ):
                candidates.add(base + "/" + first_part + "/" + second_part)

    ordered = sorted(candidates)
    raw_candidates = len(ordered)
    truncated = 0
    if raw_candidates > self.NUCLEI_MAX_TARGETS:
        truncated = raw_candidates - self.NUCLEI_MAX_TARGETS
        ordered = ordered[: self.NUCLEI_MAX_TARGETS]

    meta = {
        "inspected_entries": inspected_entries,
        "raw_candidates": raw_candidates,
        "dropped_noise_host": dropped_noise_host,
        "dropped_scope_host": dropped_scope_host,
        "dropped_path": dropped_path,
        "truncated": truncated,
        "force_host": force_host,
        "selected_host": selected_host,
        "allowed_bases": sorted(list(allowed_bases)),
        "manual_scope_enabled": bool(scope_override.get("enabled")),
        "manual_scope_line_count": len(scope_override.get("lines", [])),
        "manual_scope_host_count": len(scope_override.get("hosts", set())),
        "manual_scope_base_count": len(scope_override.get("bases", set())),
        "manual_scope_preview": list(scope_override.get("lines", []))[:3],
    }
    return ordered, meta

def process_traffic(extender, messageInfo, source_tool="Unknown"):
    self = extender
    try:
        if not messageInfo:
            return
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        if not request:
            self._callbacks.printOutput("[DEBUG] Skipped: No request")
            return
        if not response:
            self._callbacks.printOutput("[DEBUG] Skipped: No response")
            return

        start_time = time.time()
        req_info = self._helpers.analyzeRequest(messageInfo)
        resp_info = self._helpers.analyzeResponse(response)

        url = req_info.getUrl()
        method = req_info.getMethod()
        path = url.getPath()

        # Filter only obvious noise: images and fonts
        path_lower = path.lower()
        if any(
            path_lower.endswith(ext)
            for ext in [
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".webp",
                ".svg",
                ".ico",
                ".woff",
                ".woff2",
                ".ttf",
            ]
        ):
            return

        # Normalize path for grouping
        normalized_path = self._normalize_path(path)
        endpoint_key = "{}:{}".format(method, normalized_path)

        # Memory limit check + sample-cap gate under one lock window.
        max_samples = int(str(self.sample_limit.getSelectedItem()))
        with self.lock:
            if len(self.api_data) >= self.max_endpoints:
                # Remove 10% oldest endpoints
                to_remove = int(self.max_endpoints * 0.1)
                # Create snapshot to avoid modification during iteration
                times_snapshot = list(self.endpoint_times.items())
                oldest = sorted(
                    times_snapshot,
                    key=lambda x: min(x[1]) if isinstance(x[1], list) else x[1],
                )[:to_remove]
                for key, _ in oldest:
                    self.api_data.pop(key, None)
                    self.endpoint_times.pop(key, None)
                    self.endpoint_tags.pop(key, None)
                self.log_to_ui(
                    "[*] Rotated {} old endpoints (limit: {})".format(
                        to_remove, self.max_endpoints
                    )
                )
            if (
                endpoint_key in self.api_data
                and len(self.api_data[endpoint_key]) >= max_samples
            ):
                return

        # Extract comprehensive data
        req_body = self._extract_body(request, req_info.getBodyOffset())
        resp_body = self._extract_body(response, resp_info.getBodyOffset())
        content_type = self._get_content_type(resp_info)

        response_time = int((time.time() - start_time) * 1000)
        captured_epoch_ms = int(time.time() * 1000)
        captured_at = time.strftime("%Y-%m-%d %H:%M:%S")

        api_entry = {
            "method": method,
            "path": path,
            "normalized_path": normalized_path,
            "host": url.getHost(),
            "protocol": url.getProtocol(),
            "port": url.getPort(),
            "query_string": url.getQuery() or "",
            "parameters": self._extract_params(req_info),
            "headers": self._extract_headers(req_info),
            "request_body": req_body,
            "response_status": resp_info.getStatusCode(),
            "response_headers": self._extract_response_headers(resp_info),
            "response_body": resp_body,
            "response_length": max(0, len(response) - resp_info.getBodyOffset()),
            "response_time_ms": response_time,
            "captured_at": captured_at,
            "captured_at_epoch_ms": captured_epoch_ms,
            "source_tool": self._ascii_safe(source_tool),
            "content_type": content_type,
            "auth_detected": self._detect_auth(req_info),
            "api_patterns": self._detect_api_patterns(
                path, content_type, resp_body
            ),
            "jwt_detected": self._extract_jwt(req_info),
            "encryption_indicators": self._detect_encryption(
                req_body, resp_body, self._extract_headers(req_info)
            ),
            "param_patterns": self._analyze_param_patterns(
                req_info, req_body, resp_body
            ),
        }

        is_new = False
        logger_tags = []
        auto_tags = list(self._auto_tag(api_entry) or [])
        with self.lock:
            if (
                endpoint_key in self.api_data
                and len(self.api_data[endpoint_key]) >= max_samples
            ):
                return
            if endpoint_key not in self.api_data:
                self.api_data[endpoint_key] = []
                self.endpoint_tags[endpoint_key] = list(auto_tags)
                self.endpoint_times[endpoint_key] = []
                is_new = True
            self.api_data[endpoint_key].append(api_entry)
            merged_tags = set(self.endpoint_tags.get(endpoint_key, []) or [])
            merged_tags.update(auto_tags)
            self.endpoint_tags[endpoint_key] = sorted(merged_tags)
            self.endpoint_times[endpoint_key].append(response_time)
            logger_tags = list(self.endpoint_tags.get(endpoint_key, []) or [])

        skip_logger_capture = bool(
            getattr(self, "_suspend_logger_capture_during_recon_backfill", False)
        )
        if (not skip_logger_capture) and hasattr(self, "_logger_capture_event"):
            self._logger_capture_event(endpoint_key, api_entry, logger_tags)

        count = len(self.api_data)
        self._callbacks.setExtensionName(
            "API Recon" if count == 0 else "API Recon ({})".format(count)
        )

        if is_new:
            SwingUtilities.invokeLater(
                lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
            )
            severity = self._get_severity(endpoint_key, [api_entry])
            if severity == "critical":
                self.log_to_ui(
                    "[!] CRITICAL: {} {} @ {} (Total: {})".format(
                        method, normalized_path, url.getHost(), len(self.api_data)
                    )
                )
            elif severity == "high":
                self.log_to_ui(
                    "[!] HIGH: {} {} @ {} (Total: {})".format(
                        method, normalized_path, url.getHost(), len(self.api_data)
                    )
                )
            elif severity == "medium":
                self.log_to_ui(
                    "[*] MEDIUM: {} {} @ {} (Total: {})".format(
                        method, normalized_path, url.getHost(), len(self.api_data)
                    )
                )
            else:
                self.log_to_ui(
                    "[+] Captured: {} {} @ {} (Total: {})".format(
                        method, normalized_path, url.getHost(), len(self.api_data)
                    )
                )
            self._schedule_capture_ui_refresh()

    except Exception as e:
        self._callbacks.printError("Error processing: " + str(e))

def show_endpoint_details(extender, endpoint_key):
    self = extender
    """Show detailed information for selected endpoint"""
    resolved_key = self._ascii_safe(endpoint_key or "").strip()
    with self.lock:
        if resolved_key in self.api_data:
            entries = self.api_data[resolved_key]
            times = self.endpoint_times.get(resolved_key, [])
        else:
            entries = None
            times = None

    if entries is None:
        if hasattr(self, "_resolve_recon_endpoint_key"):
            try:
                candidate_key = self._resolve_recon_endpoint_key(resolved_key)
                if candidate_key:
                    resolved_key = candidate_key
            except Exception as resolve_err:
                self._callbacks.printError(
                    "Endpoint detail key resolution error: {}".format(str(resolve_err))
                )
        with self.lock:
            if resolved_key not in self.api_data:
                if hasattr(self, "_show_recon_missing_detail_message"):
                    self._show_recon_missing_detail_message(
                        resolved_key,
                        reason="Requested endpoint key is not present in Recon cache.",
                    )
                return
            entries = self.api_data[resolved_key]
            times = self.endpoint_times.get(resolved_key, [])

    entries_list = entries if isinstance(entries, list) else [entries]
    times_list = times if isinstance(times, list) else [times]
    severity = self._get_severity(resolved_key, entries)

    details = []
    details.append("=" * 80)
    details.append("ENDPOINT: {}".format(resolved_key))
    details.append("Host: {}".format(self._get_entry(entries)["host"]))
    details.append("Severity: {}".format(severity.upper()))
    details.append("Samples: {}".format(len(entries_list)))
    details.append("=" * 80)
    details.append("")

    # Response times
    if times_list:
        avg_time = sum(times_list) / len(times_list)
        details.append(
            "Response Times: Avg={}ms, Min={}ms, Max={}ms".format(
                int(avg_time), min(times_list), max(times_list)
            )
        )

    # Auth
    auth = list(set([a for e in entries_list for a in e["auth_detected"]]))
    details.append("Authentication: {}".format(", ".join(auth)))

    # Parameters
    params = self._merge_params(entries_list)
    if any(params.values()):
        details.append("")
        details.append("Parameters:")
        for ptype, pnames in params.items():
            if pnames:
                details.append("  {}: {}".format(ptype, ", ".join(pnames[:10])))

    # Response codes
    codes = list(set([e["response_status"] for e in entries_list]))
    details.append("")
    details.append("Response Codes: {}".format(", ".join(map(str, codes))))

    # Content types
    ctypes = list(set([e["content_type"] for e in entries_list]))
    details.append("Content Types: {}".format(", ".join(ctypes)))

    # Encryption
    enc_types = list(
        set(
            [
                t
                for e in entries_list
                for t in e.get("encryption_indicators", {}).get("types", [])
            ]
        )
    )
    if enc_types:
        details.append("Encryption: {}".format(", ".join(enc_types)))

    # Reflected params
    reflected = list(
        set(
            [
                p
                for e in entries_list
                for p in e.get("param_patterns", {}).get("reflected", [])
            ]
        )
    )
    if reflected:
        details.append("Reflected Parameters: {}".format(", ".join(reflected)))

    # JWT Details
    jwt_data = None
    for e in entries_list:
        if e.get("jwt_detected"):
            jwt_data = e.get("jwt_detected")
            break

    if jwt_data:
        details.append("")
        details.append("-" * 80)
        details.append("JWT TOKEN DETECTED")
        details.append("-" * 80)
        details.append("Location: {}".format(jwt_data.get("location", "Unknown")))
        details.append("")
        details.append("Header:")
        for k, v in jwt_data.get("header", {}).items():
            details.append("  {}: {}".format(k, v))
        details.append("")
        details.append("Payload:")
        for k, v in jwt_data.get("payload", {}).items():
            details.append("  {}: {}".format(k, v))
        details.append("")
        details.append("Signature: {}...".format(jwt_data.get("signature", "")[:50]))
        details.append("")

        # Security analysis
        header = jwt_data.get("header", {})
        payload = jwt_data.get("payload", {})
        alg = header.get("alg", "")

        details.append("Security Analysis:")
        if alg.lower() in ["none", "null"]:
            details.append("  [CRITICAL] Algorithm is 'none' - signature not verified!")
        elif alg.startswith("HS"):
            details.append("  [INFO] HMAC algorithm ({}) - symmetric key".format(alg))
        elif alg.startswith("RS") or alg.startswith("ES"):
            details.append("  [INFO] Asymmetric algorithm ({})".format(alg))

        if "exp" in payload:
            import time
            exp = payload.get("exp")
            try:
                integer_types = (int, long)  # noqa: F821 (Python2/Jython)
            except NameError:
                integer_types = (int,)
            if isinstance(exp, integer_types):
                if exp < time.time():
                    details.append("  [WARNING] Token is EXPIRED")
                else:
                    details.append("  [INFO] Token expires: {}".format(exp))
        else:
            details.append("  [WARNING] No expiration claim (exp)")

        if "iat" not in payload:
            details.append("  [WARNING] No issued-at claim (iat)")

        if "sub" not in payload and "user" not in payload and "userId" not in payload:
            details.append("  [INFO] No user identifier found in standard claims")

    # Sample request/response
    details.append("")
    details.append("-" * 80)
    details.append("SAMPLE REQUEST #1:")
    details.append("-" * 80)
    sample = self._get_entry(entries)
    details.append("{} {}".format(sample["method"], sample["path"]))
    if sample.get("query_string"):
        details.append("Query: {}".format(sample["query_string"]))
    details.append("")
    for k, v in list(sample.get("headers", {}).items())[:10]:
        details.append("{}: {}".format(k, str(v)[:100]))
    if sample.get("request_body"):
        details.append("")
        details.append("Body: {}".format(sample["request_body"][:500]))

    details.append("")
    details.append("-" * 80)
    details.append("SAMPLE RESPONSE #1:")
    details.append("-" * 80)
    details.append("Status: {}".format(sample["response_status"]))
    details.append("Length: {} bytes".format(sample["response_length"]))
    if sample.get("response_body"):
        details.append("")
        details.append("Body: {}".format(sample["response_body"][:500]))

    self.details_area.setText("\n".join(details))
    self.details_area.setCaretPosition(0)

def _auto_detect_auth_profile_headers(extender):
    """Best-effort autorize-like header prefill for empty profile fields."""
    self = extender
    notes = []
    selected_key = self._get_selected_endpoint_key()
    with self.lock:
        data_snapshot = list(self.api_data.items())

    def pick_candidate_for_profile(profile_key):
        # Prefer currently selected endpoint when available.
        if selected_key:
            for endpoint_key, entries in data_snapshot:
                if endpoint_key != selected_key:
                    continue
                preferred = self._find_profile_header_candidates_in_entries(
                    entries, profile_key, prefer_match=True, max_candidates=1
                )
                if preferred:
                    return preferred[0], endpoint_key
                fallback = self._find_profile_header_candidates_in_entries(
                    entries, profile_key, prefer_match=False, max_candidates=1
                )
                if fallback:
                    return fallback[0], endpoint_key

        # Then search across captured entries.
        for endpoint_key, entries in data_snapshot:
            preferred = self._find_profile_header_candidates_in_entries(
                entries, profile_key, prefer_match=True, max_candidates=1
            )
            if preferred:
                return preferred[0], endpoint_key
        for endpoint_key, entries in data_snapshot:
            fallback = self._find_profile_header_candidates_in_entries(
                entries, profile_key, prefer_match=False, max_candidates=1
            )
            if fallback:
                return fallback[0], endpoint_key
        return None, None

    profile_map = [
        ("guest", "Guest", getattr(self, "auth_guest_header_field", None)),
        ("user", "User", getattr(self, "auth_user_header_field", None)),
        ("admin", "Admin", getattr(self, "auth_admin_header_field", None)),
    ]
    for profile_key, profile_label, field in profile_map:
        if field is None:
            continue
        existing_value = self._ascii_safe(field.getText()).strip()
        if existing_value:
            continue
        candidate, endpoint_key = pick_candidate_for_profile(profile_key)
        if not candidate:
            continue
        field.setText(candidate)
        notes.append(
            "{} header auto-detected from {}".format(
                profile_label, endpoint_key or "captured traffic"
            )
        )
    return notes

def run_auth_replay(extender, event):
    self = extender
    """Replay endpoints across roles and score likely authz weaknesses."""
    if not self.api_data:
        self.auth_replay_area.setText(
            "[!] No endpoints in Recon tab. Capture or import first\n"
        )
        return

    max_text = self.auth_replay_max_field.getText().strip() or "50"
    try:
        max_count = int(max_text)
        if max_count < 1:
            max_count = 1
        if max_count > 500:
            max_count = 500
    except ValueError:
        max_count = 50

    auto_detect_notes = _auto_detect_auth_profile_headers(self)

    try:
        guest_header = self._parse_auth_profile_header(
            "Guest", self.auth_guest_header_field.getText()
        )
        user_header = self._parse_auth_profile_header(
            "User", self.auth_user_header_field.getText()
        )
        admin_header = self._parse_auth_profile_header(
            "Admin", self.auth_admin_header_field.getText()
        )
    except ValueError as e:
        self.auth_replay_area.setText("[!] {}\n".format(str(e)))
        return

    try:
        include_regex = self._compile_optional_regex(
            self.auth_replay_include_regex_field.getText(),
            "Include",
        )
        exclude_regex = self._compile_optional_regex(
            self.auth_replay_exclude_regex_field.getText(),
            "Exclude",
        )
        enforced_regex = self._compile_optional_regex(
            self.auth_replay_enforced_regex_field.getText(),
            "Enforced",
        )
        guest_enforced_regex = self._compile_optional_regex(
            self.auth_replay_guest_regex_field.getText(),
            "Guest Enforced",
        )
        user_enforced_regex = self._compile_optional_regex(
            self.auth_replay_user_regex_field.getText(),
            "User Enforced",
        )
        unauth_enforced_regex = self._compile_optional_regex(
            self.auth_replay_unauth_regex_field.getText(),
            "Unauth Enforced",
        )
    except ValueError as e:
        self.auth_replay_area.setText("[!] {}\n".format(self._ascii_safe(e)))
        return

    method_allowlist = set(
        [
            self._ascii_safe(item, lower=True).upper()
            for item in self._parse_comma_newline_values(
                self.auth_replay_methods_field.getText()
            )
        ]
    )
    if not method_allowlist:
        method_allowlist = set(["GET", "POST", "PUT", "PATCH", "DELETE"])

    enforced_statuses = self._parse_auth_replay_status_codes(
        self.auth_replay_enforced_status_field.getText()
    )
    if not enforced_statuses:
        enforced_statuses = set([401, 403])

    guest_enforced_statuses = self._parse_auth_replay_status_codes(
        self.auth_replay_guest_status_field.getText()
    )
    user_enforced_statuses = self._parse_auth_replay_status_codes(
        self.auth_replay_user_status_field.getText()
    )
    unauth_enforced_statuses = self._parse_auth_replay_status_codes(
        self.auth_replay_unauth_status_field.getText()
    )

    by_role_detector_cfg = {}
    if guest_enforced_statuses or guest_enforced_regex:
        by_role_detector_cfg["guest"] = {
            "enforced_statuses": set(guest_enforced_statuses)
            if guest_enforced_statuses
            else None,
            "enforced_regex": guest_enforced_regex,
        }
    if user_enforced_statuses or user_enforced_regex:
        by_role_detector_cfg["user"] = {
            "enforced_statuses": set(user_enforced_statuses)
            if user_enforced_statuses
            else None,
            "enforced_regex": user_enforced_regex,
        }
    if unauth_enforced_statuses or unauth_enforced_regex:
        by_role_detector_cfg["unauth"] = {
            "enforced_statuses": set(unauth_enforced_statuses)
            if unauth_enforced_statuses
            else None,
            "enforced_regex": unauth_enforced_regex,
        }

    detector_cfg = {
        "enforced_statuses": set(enforced_statuses),
        "enforced_regex": enforced_regex,
        "by_role": by_role_detector_cfg,
    }

    include_unauth = bool(self.auth_replay_check_unauth_checkbox.isSelected())
    profiles = []
    if guest_header:
        profiles.append(("guest", guest_header))
    elif include_unauth:
        profiles.append(("unauth", None))
    else:
        profiles.append(("guest", None))
    if include_unauth and guest_header:
        profiles.append(("unauth", None))
    if user_header:
        profiles.append(("user", user_header))
    if admin_header:
        profiles.append(("admin", admin_header))
    if len(profiles) < 2:
        self.auth_replay_area.setText(
            "[!] Provide at least one non-empty User or Admin header\n"
        )
        self.auth_replay_area.append(
            "[*] Header format: Authorization: Bearer <token>\n"
        )
        return

    scope = str(self.auth_replay_scope_combo.getSelectedItem())
    endpoint_keys, total_available = self._collect_auth_replay_targets(
        scope,
        max_count,
        include_regex=include_regex,
        exclude_regex=exclude_regex,
        method_allowlist=method_allowlist,
    )
    if not endpoint_keys:
        self.auth_replay_area.setText(
            "[!] No endpoints found for scope '{}'\n".format(scope)
        )
        if scope == "Selected Endpoint":
            self.auth_replay_area.append(
                "[*] Select one endpoint from Recon list and retry\n"
            )
        return

    self._clear_tool_cancel("authreplay")
    _clear_auth_replay_views(self)
    self.auth_replay_area.setText("[*] Starting Auth Replay MVP...\n")
    if auto_detect_notes:
        for note in auto_detect_notes:
            self.auth_replay_area.append("[*] {}\n".format(note))
    self.auth_replay_area.append("[*] Scope: {}\n".format(scope))
    self.auth_replay_area.append(
        "[*] Targets: {} of {} available\n".format(
            len(endpoint_keys), total_available
        )
    )
    self.auth_replay_area.append(
        "[*] Profiles: {}\n".format(
            ", ".join([name for name, _ in profiles])
        )
    )
    self.auth_replay_area.append(
        "[*] Method Filter: {}\n".format(", ".join(sorted(method_allowlist)))
    )
    self.auth_replay_area.append(
        "[*] Enforced Status: {}\n".format(
            ", ".join([str(x) for x in sorted(enforced_statuses)])
        )
    )
    if by_role_detector_cfg:
        role_lines = []
        for role_name in ["guest", "user", "unauth"]:
            role_cfg = by_role_detector_cfg.get(role_name)
            if not role_cfg:
                continue
            role_statuses = role_cfg.get("enforced_statuses")
            if role_statuses:
                status_text = ",".join([str(x) for x in sorted(role_statuses)])
            else:
                status_text = "<default>"
            role_regex = role_cfg.get("enforced_regex")
            regex_text = role_regex.pattern if role_regex else "<default>"
            role_lines.append(
                "{}: status={} regex={}".format(role_name, status_text, regex_text)
            )
        if role_lines:
            self.auth_replay_area.append(
                "[*] Per-Profile Detectors: {}\n".format(" | ".join(role_lines))
            )
    if include_regex:
        self.auth_replay_area.append(
            "[*] Include Regex: {}\n".format(
                self._ascii_safe(self.auth_replay_include_regex_field.getText()).strip()
            )
        )
    if exclude_regex:
        self.auth_replay_area.append(
            "[*] Exclude Regex: {}\n".format(
                self._ascii_safe(self.auth_replay_exclude_regex_field.getText()).strip()
            )
        )
    self.auth_replay_area.append(
        "[*] Tip: use Stop to cancel the run at any time\n\n"
    )
    self.log_to_ui(
        "[*] Auth Replay: {} targets, profiles={}".format(
            len(endpoint_keys), ",".join([name for name, _ in profiles])
        )
    )

    def run_replay():
        findings = []
        scanned = 0
        cancelled = False
        errors = 0

        try:
            idx = 0
            for endpoint_key in endpoint_keys:
                if self._is_tool_cancelled("authreplay"):
                    cancelled = True
                    break

                idx += 1
                if idx == 1 or idx % 5 == 0:
                    SwingUtilities.invokeLater(
                        lambda i=idx, total=len(endpoint_keys): self.auth_replay_area.append(
                            "[*] Replaying {}/{}...\n".format(i, total)
                        )
                    )

                with self.lock:
                    entries = self.api_data.get(endpoint_key)
                if not entries:
                    continue

                entry = self._get_entry(entries)
                role_results = {}
                for role_name, role_header in profiles:
                    if self._is_tool_cancelled("authreplay"):
                        cancelled = True
                        break
                    result = self._perform_auth_replay_request(entry, role_header)
                    role_results[role_name] = result
                    if result.get("error"):
                        errors += 1

                if cancelled:
                    break

                endpoint_findings = self._evaluate_auth_replay_findings(
                    endpoint_key, role_results, detector_cfg=detector_cfg
                )
                findings.extend(endpoint_findings)
                scanned += 1
                row_data = _auth_replay_build_result_row(
                    self, idx, endpoint_key, entry, role_results, endpoint_findings
                )
                SwingUtilities.invokeLater(
                    lambda row=row_data: self.auth_replay_table_model.addRow(row)
                )

            severity_order = {"critical": 0, "high": 1, "medium": 2}
            findings.sort(
                key=lambda f: (
                    severity_order.get(f.get("severity", "medium"), 3),
                    f.get("endpoint", ""),
                )
            )
            with self.auth_replay_lock:
                self.auth_replay_findings = list(findings)

            severity_counts = {"critical": 0, "high": 0, "medium": 0}
            for finding in findings:
                sev = finding.get("severity", "medium")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            output = []
            output.append("")
            output.append("=" * 80)
            output.append("AUTH REPLAY RESULTS")
            output.append("=" * 80)
            output.append("[*] Scanned Endpoints: {}".format(scanned))
            output.append("[*] Findings: {}".format(len(findings)))
            output.append("[*] Request Errors: {}".format(errors))
            if cancelled:
                output.append("[!] Run cancelled by user")
            output.append(
                "[*] Severity: Critical={} High={} Medium={}".format(
                    severity_counts["critical"],
                    severity_counts["high"],
                    severity_counts["medium"],
                )
            )
            output.append("")

            if findings:
                output.append("TOP FINDINGS")
                output.append("-" * 80)
                for finding in findings[:25]:
                    output.append(
                        "[{}] {}".format(
                            finding.get("severity", "medium").upper(),
                            finding.get("issue", ""),
                        )
                    )
                    output.append("  Endpoint: {}".format(finding.get("endpoint", "")))
                    output.append(
                        "  {} status/len: {}/{} | {} status/len: {}/{}".format(
                            finding.get("low_role", "low"),
                            finding.get("low_status", 0),
                            finding.get("low_length", 0),
                            finding.get("high_role", "high"),
                            finding.get("high_status", 0),
                            finding.get("high_length", 0),
                        )
                    )
                    output.append("")
                if len(findings) > 25:
                    output.append("[*] {} more findings not shown".format(len(findings) - 25))
            else:
                output.append("[+] No obvious cross-role authz issues detected")
                output.append("[*] Try broader endpoint scope or different tokens")

            result_text = "\n".join(output) + "\n"
            SwingUtilities.invokeLater(
                lambda t=result_text: self.auth_replay_area.append(t)
            )
            if cancelled:
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[!] Auth Replay cancelled ({} scanned, {} findings)".format(
                            scanned, len(findings)
                        )
                    )
                )
            else:
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[+] Auth Replay complete ({} scanned, {} findings)".format(
                            scanned, len(findings)
                        )
                    )
                )
        except Exception as e:
            err = "[!] Auth Replay failed: {}\n".format(str(e))
            SwingUtilities.invokeLater(lambda t=err: self.auth_replay_area.append(t))
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] Auth Replay error: {}".format(m))
            )
        finally:
            self._clear_tool_cancel("authreplay")

    thread = threading.Thread(target=run_replay)
    thread.daemon = True
    thread.start()

def collect_ffuf_targets(extender):
    self = extender
    """Collect prioritized FFUF targets from Recon with first-party filtering."""
    static_skip_parts = set(
        [
            "js",
            "css",
            "static",
            "dist",
            "assets",
            "images",
            "img",
            "fonts",
            "shreddit",
            "recaptcha",
            "gsi",
            "sw.js",
            "service-worker.js",
        ]
    )

    with self.lock:
        entries_snapshot = [self._get_entry(entries) for entries in self.api_data.values()]

    scope_override = self._get_target_scope_override()
    host_counts = {}
    base_scores = {}
    for entry in entries_snapshot:
        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        if not host:
            continue
        if scope_override.get("enabled") and not self._host_matches_target_scope(
            host, scope_override
        ):
            continue
        host_counts[host] = host_counts.get(host, 0) + 1
        if (not scope_override.get("enabled")) and self._ffuf_is_noise_host(host):
            continue

        base = self._infer_base_domain(host)
        if not base:
            continue

        score = 1
        method = self._ascii_safe(entry.get("method"), lower=True).strip()
        if method in ["post", "put", "patch", "delete"]:
            score += 2

        path = self._ascii_safe(entry.get("normalized_path") or "/", lower=True)
        first_part = ""
        parts = [p for p in path.strip("/").split("/") if p]
        if parts:
            first_part = parts[0]
            if first_part.startswith("api") or first_part in [
                "v1",
                "v2",
                "v3",
                "v4",
                "graphql",
                "rest",
                "svc",
                "internal",
                "auth",
                "oauth",
            ]:
                score += 3

        parameters = entry.get("parameters", {})
        if isinstance(parameters, dict):
            for value in parameters.values():
                if isinstance(value, list) and value:
                    score += 2
                    break
                if isinstance(value, dict) and value:
                    score += 2
                    break

        base_scores[base] = base_scores.get(base, 0) + score

    if scope_override.get("enabled"):
        selected_host = "target-bases"
        force_host = False
        allowed_bases = set(scope_override.get("bases", set()))
    else:
        selected_host = "All"
        try:
            if hasattr(self, "host_filter") and self.host_filter is not None:
                selected_host = self._ascii_safe(
                    str(self.host_filter.getSelectedItem()), lower=True
                )
        except Exception as e:
            self._callbacks.printError("FFUF host-filter read error: {}".format(str(e)))
            selected_host = "All"

        force_host = selected_host and selected_host != "all"
        sorted_bases = sorted(base_scores.items(), key=lambda item: (-item[1], item[0]))
        allowed_bases = set([base for base, _ in sorted_bases[:1]])
        if not allowed_bases:
            fallback_bases = {}
            for host, count in host_counts.items():
                if self._ffuf_is_noise_host(host):
                    continue
                base = self._infer_base_domain(host)
                if not base:
                    continue
                fallback_bases[base] = fallback_bases.get(base, 0) + count
            fallback_sorted = sorted(
                fallback_bases.items(), key=lambda item: (-item[1], item[0])
            )
            allowed_bases = set([base for base, _ in fallback_sorted[:1]])

    candidates = {}
    dropped_noise_host = 0
    dropped_scope_host = 0
    dropped_path = 0
    inspected_entries = 0
    for entry in entries_snapshot:
        inspected_entries += 1
        protocol = self._ascii_safe(entry.get("protocol"), lower=True).strip() or "https"
        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        if not host:
            dropped_scope_host += 1
            continue

        if scope_override.get("enabled"):
            if not self._host_matches_target_scope(host, scope_override):
                dropped_scope_host += 1
                continue
        elif force_host:
            if host != selected_host:
                dropped_scope_host += 1
                continue
        else:
            if self._ffuf_is_noise_host(host):
                dropped_noise_host += 1
                continue
            if allowed_bases:
                host_base = self._infer_base_domain(host)
                if host_base not in allowed_bases:
                    dropped_scope_host += 1
                    continue

        port = entry.get("port", -1)
        if port == -1:
            port = 443 if protocol == "https" else 80
        if (protocol == "https" and port == 443) or (
            protocol == "http" and port == 80
        ):
            base = "{}://{}".format(protocol, host)
        else:
            base = "{}://{}:{}".format(protocol, host, port)

        path = self._ascii_safe(entry.get("normalized_path") or "/")
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            first_part = "api"
        else:
            first_part = self._ascii_safe(parts[0], lower=True).strip()

        if first_part in static_skip_parts or self._ffuf_is_noise_path_segment(first_part):
            dropped_path += 1
            continue

        target = base + "/" + first_part + "/FUZZ"
        api_like = (
            first_part.startswith("api")
            or first_part in ["v1", "v2", "v3", "v4", "graphql", "rest", "svc", "internal"]
            or "/api/" in path.lower()
        )
        priority = 0 if api_like else 1
        prev = candidates.get(target)
        if prev is None or priority < prev:
            candidates[target] = priority

    ordered = sorted(candidates.items(), key=lambda item: (item[1], item[0]))
    total_candidates = len(ordered)
    truncated = 0
    if total_candidates > self.FFUF_MAX_TARGETS:
        truncated = total_candidates - self.FFUF_MAX_TARGETS
        ordered = ordered[: self.FFUF_MAX_TARGETS]
    targets = [target for target, _ in ordered]

    meta = {
        "inspected_entries": inspected_entries,
        "raw_candidates": total_candidates,
        "dropped_noise_host": dropped_noise_host,
        "dropped_scope_host": dropped_scope_host,
        "dropped_path": dropped_path,
        "truncated": truncated,
        "force_host": force_host,
        "selected_host": selected_host,
        "allowed_bases": sorted(list(allowed_bases)),
        "manual_scope_enabled": bool(scope_override.get("enabled")),
        "manual_scope_line_count": len(scope_override.get("lines", [])),
        "manual_scope_host_count": len(scope_override.get("hosts", set())),
        "manual_scope_base_count": len(scope_override.get("bases", set())),
        "manual_scope_preview": list(scope_override.get("lines", []))[:3],
    }
    return targets, meta

def collect_wayback_queries(extender):
    self = extender
    """Collect scoped Wayback host/path queries from first-party Recon data."""
    static_skip_parts = set(
        [
            "favicon.ico",
            "robots.txt",
            "static",
            "dist",
            "css",
            "js",
            "img",
            "images",
            "fonts",
            "cdn-cgi",
            "captcha",
            "recaptcha",
        ]
    )
    with self.lock:
        entries_snapshot = [self._get_entry(entries) for entries in self.api_data.values()]

    scope_override = self._get_target_scope_override()
    host_counts = {}
    base_scores = {}
    for entry in entries_snapshot:
        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        if not host:
            continue
        if scope_override.get("enabled") and not self._host_matches_target_scope(
            host, scope_override
        ):
            continue
        host_counts[host] = host_counts.get(host, 0) + 1
        if (not scope_override.get("enabled")) and self._ffuf_is_noise_host(host):
            continue
        base = self._infer_base_domain(host)
        if not base:
            continue

        score = 1
        method = self._ascii_safe(entry.get("method"), lower=True).strip()
        if method in ["post", "put", "patch", "delete"]:
            score += 2
        path = self._ascii_safe(entry.get("normalized_path") or "/", lower=True)
        if "/api/" in path or "/graphql" in path:
            score += 3
        base_scores[base] = base_scores.get(base, 0) + score

    if scope_override.get("enabled"):
        selected_host = "target-bases"
        force_host = False
        allowed_bases = set(scope_override.get("bases", set()))
    else:
        selected_host = "all"
        try:
            if hasattr(self, "host_filter") and self.host_filter is not None:
                selected_host = self._ascii_safe(
                    str(self.host_filter.getSelectedItem()), lower=True
                ).strip()
        except Exception as e:
            self._callbacks.printError("Wayback host-filter read error: {}".format(str(e)))
            selected_host = "all"
        force_host = bool(selected_host and selected_host != "all")

        sorted_bases = sorted(base_scores.items(), key=lambda item: (-item[1], item[0]))
        allowed_bases = set([base for base, _ in sorted_bases[:1]])
        if not allowed_bases:
            fallback_bases = {}
            for host, count in host_counts.items():
                if self._ffuf_is_noise_host(host):
                    continue
                base = self._infer_base_domain(host)
                if not base:
                    continue
                fallback_bases[base] = fallback_bases.get(base, 0) + count
            fallback_sorted = sorted(
                fallback_bases.items(), key=lambda item: (-item[1], item[0])
            )
            allowed_bases = set([base for base, _ in fallback_sorted[:1]])

    dropped_noise_host = 0
    dropped_scope_host = 0
    dropped_path = 0
    inspected_entries = 0
    hosts = set()
    path_candidates = {}
    for entry in entries_snapshot:
        inspected_entries += 1
        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        if not host:
            dropped_scope_host += 1
            continue

        if scope_override.get("enabled"):
            if not self._host_matches_target_scope(host, scope_override):
                dropped_scope_host += 1
                continue
        elif force_host:
            if host != selected_host:
                dropped_scope_host += 1
                continue
        else:
            if self._ffuf_is_noise_host(host):
                dropped_noise_host += 1
                continue
            host_base = self._infer_base_domain(host)
            if allowed_bases and host_base not in allowed_bases:
                dropped_scope_host += 1
                continue

        hosts.add(host)
        raw_path = self._ascii_safe(
            entry.get("normalized_path") or entry.get("path") or "/",
            lower=True,
        )
        parts = [p for p in raw_path.strip("/").split("/") if p]
        if not parts:
            continue

        first_part = parts[0]
        if first_part in static_skip_parts or self._ffuf_is_noise_path_segment(first_part):
            dropped_path += 1
            continue

        base_path = "/" + first_part
        score = 1
        if first_part.startswith("api") or first_part in [
            "v1",
            "v2",
            "v3",
            "v4",
            "graphql",
            "rest",
            "auth",
            "oauth",
            "internal",
        ]:
            score += 3
        key = (host, base_path)
        previous = path_candidates.get(key)
        if previous is None or score > previous:
            path_candidates[key] = score

        if first_part == "api" and len(parts) > 1:
            second_part = self._ascii_safe(parts[1], lower=True).strip()
            if (
                second_part
                and second_part not in static_skip_parts
                and not self._ffuf_is_noise_path_segment(second_part)
            ):
                key2 = (host, "/api/" + second_part)
                score2 = score + 1
                previous2 = path_candidates.get(key2)
                if previous2 is None or score2 > previous2:
                    path_candidates[key2] = score2

    host_queries = [(host, "") for host in sorted(hosts)]
    ranked_paths = sorted(
        path_candidates.items(),
        key=lambda item: (-item[1], item[0][0], item[0][1]),
    )
    path_queries = [item[0] for item in ranked_paths]
    queries = host_queries + path_queries
    raw_queries = len(queries)
    truncated = 0
    if raw_queries > self.WAYBACK_MAX_QUERIES:
        truncated = raw_queries - self.WAYBACK_MAX_QUERIES
        queries = queries[: self.WAYBACK_MAX_QUERIES]

    meta = {
        "inspected_entries": inspected_entries,
        "host_count": len(hosts),
        "path_count": len(path_candidates),
        "raw_queries": raw_queries,
        "dropped_noise_host": dropped_noise_host,
        "dropped_scope_host": dropped_scope_host,
        "dropped_path": dropped_path,
        "truncated": truncated,
        "force_host": force_host,
        "selected_host": selected_host,
        "allowed_bases": sorted(list(allowed_bases)),
        "manual_scope_enabled": bool(scope_override.get("enabled")),
        "manual_scope_line_count": len(scope_override.get("lines", [])),
        "manual_scope_host_count": len(scope_override.get("hosts", set())),
        "manual_scope_base_count": len(scope_override.get("bases", set())),
        "manual_scope_preview": list(scope_override.get("lines", []))[:3],
    }
    return queries, meta
