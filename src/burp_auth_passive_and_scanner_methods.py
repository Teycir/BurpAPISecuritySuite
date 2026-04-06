# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Authorization replay, passive analysis, and scanner target orchestration helpers."""
import json
import os
import re
import shlex
import threading
import time
import ai_prep_layer
import behavior_analysis
import heavy_runners
import jython_size_helpers
import recon_param_intel

from java.awt import BorderLayout, Color, Dimension, FlowLayout, Font, GridLayout
from java.awt.event import MouseAdapter
from java.io import File, FileWriter
from java.net import URL
from java.text import SimpleDateFormat
from java.util import ArrayList, Date
from javax.swing import (
    BorderFactory,
    Box,
    BoxLayout,
    DefaultListModel,
    JButton,
    JCheckBox,
    JComboBox,
    JFileChooser,
    JLabel,
    JList,
    JMenuItem,
    JOptionPane,
    JPanel,
    JPopupMenu,
    JScrollPane,
    JSplitPane,
    JTabbedPane,
    JTextArea,
    JTextField,
    ListCellRenderer,
    SwingUtilities,
    ToolTipManager,
)
from javax.swing.event import DocumentListener, ListSelectionListener

def _stop_asset_discovery(self, event):
    self._stop_tool_run("assetdiscovery", "Subfinder", self.asset_area)

def _stop_openapi_drift(self, event):
    self._set_tool_cancel("openapidrift")
    self.openapi_area.append("[!] OpenAPI drift stop requested by user\n")
    self.log_to_ui("[!] OpenAPI drift stop requested by user")

def _stop_graphql(self, event):
    self._stop_tool_run("graphqlanalysis", "GraphQL Analysis", self.graphql_area)

def _stop_auth_replay(self, event):
    """Request cancellation for auth replay run."""
    self._set_tool_cancel("authreplay")
    self.auth_replay_area.append("[!] Auth Replay stop requested by user\n")
    self.log_to_ui("[!] Auth Replay stop requested by user")

def _parse_auth_profile_header(self, profile_name, header_value):
    """Parse optional role header in 'Name: Value' format."""
    raw = (header_value or "").strip()
    if not raw:
        return None
    if ":" not in raw:
        raise ValueError(
            "{} header must use 'Name: Value' format".format(profile_name)
        )
    name, value = raw.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        raise ValueError(
            "{} header must include both name and value".format(profile_name)
        )
    return (name, value)

def _get_auth_profile_field(self, profile_key):
    """Return UI field for auth replay profile key."""
    mapping = {
        "guest": self.auth_guest_header_field,
        "user": self.auth_user_header_field,
        "admin": self.auth_admin_header_field,
    }
    return mapping.get(profile_key)

def _extract_endpoint_key_from_recon_value(self, raw_value):
    """Parse one Recon list row label into canonical endpoint key."""
    text = self._ascii_safe(raw_value or "").strip()
    if not text:
        return None
    if text.startswith("==="):
        return None

    # Canonical list rows look like: "[3x] METHOD:/path/{id} @ host [tags]"
    if "] " in text:
        parts = text.split("] ", 1)
        if len(parts) > 1:
            text = self._ascii_safe(parts[1] or "").strip()
    if " @ " in text:
        text = self._ascii_safe(text.split(" @ ", 1)[0] or "").strip()
    if text and ":" in text:
        return text
    return None

def _get_recon_view_key(self, index):
    """Return endpoint key for one Recon list row index using backend mapping."""
    try:
        idx = int(index)
    except (TypeError, ValueError):
        return None
    if idx < 0:
        return None

    endpoint_list = getattr(self, "endpoint_list", None)
    if endpoint_list is None:
        return None
    try:
        model = endpoint_list.getModel()
        size = int(model.getSize() or 0)
        if idx >= size:
            return None
        raw_value = model.getElementAt(idx)
    except Exception as read_err:
        self._callbacks.printError(
            "Recon view-key fallback read error: {}".format(str(read_err))
        )
        raw_value = None

    key_from_model = self._extract_endpoint_key_from_recon_value(raw_value)
    if key_from_model:
        return key_from_model

    with self.lock:
        keys_snapshot = list(getattr(self, "recon_view_keys", []) or [])
    if idx < len(keys_snapshot):
        key = self._ascii_safe(keys_snapshot[idx] or "").strip()
        if key:
            return key
    return None

def _recon_selected_indices(self):
    """Return selected row indices from Recon list using backend view mapping."""
    endpoint_list = getattr(self, "endpoint_list", None)
    if endpoint_list is None:
        return []

    selected_index = -1
    try:
        selected_index = int(endpoint_list.getSelectedIndex())
    except Exception as read_err:
        self._callbacks.printError(
            "Recon selection read error: {}".format(str(read_err))
        )
    if selected_index < 0:
        return []
    return [selected_index]

def _get_recon_selected_index(self, event=None):
    """Resolve selected Recon list index using lead selection first, then fallback."""
    endpoint_list = getattr(self, "endpoint_list", None)
    if endpoint_list is None:
        return -1

    index = -1
    if event is not None:
        try:
            selection_model = event.getSource()
            if selection_model is not None and hasattr(
                selection_model, "getMinSelectionIndex"
            ):
                candidate = int(selection_model.getMinSelectionIndex())
                if candidate >= 0:
                    if hasattr(selection_model, "isSelectedIndex"):
                        if selection_model.isSelectedIndex(candidate):
                            index = candidate
                    else:
                        index = candidate
        except (TypeError, ValueError):
            index = -1
        except Exception as lead_err:
            self._callbacks.printError(
                "Recon lead selection index read error: {}".format(str(lead_err))
            )
            index = -1

    if index < 0:
        try:
            index = int(endpoint_list.getSelectedIndex())
        except (TypeError, ValueError):
            index = -1
        except Exception as selected_err:
            self._callbacks.printError(
                "Recon selected index read error: {}".format(str(selected_err))
            )
            index = -1

    if index < 0:
        return -1
    try:
        size = int(endpoint_list.getModel().getSize() or 0)
    except (TypeError, ValueError):
        size = 0
    if index >= size:
        return -1
    return index

def _get_selected_endpoint_key(self, event=None):
    """Get currently selected endpoint key from Recon list."""
    index = self._get_recon_selected_index(event=event)
    if index >= 0:
        return self._get_recon_view_key(index)
    return None

def _recon_set_detail_redirect_text(self, endpoint_key=None):
    """Render a lightweight Recon endpoint summary and next-step guidance."""
    details_area = getattr(self, "details_area", None)
    if details_area is None:
        return
    key_text = self._ascii_safe(endpoint_key or "").strip()

    lines = ["Endpoint Detail", "=" * 60]
    if not key_text:
        lines.append("Selected: (none)")
        lines.append("")
        lines.append("Select an endpoint to view Recon summary.")
        lines.append("")
        lines.append("To view full request/response:")
        lines.append("1) Right-click selected endpoint in Recon.")
        lines.append("2) Click 'Show Detail (Logger)'.")
        details_area.setText("\n".join(lines))
        details_area.setCaretPosition(0)
        return

    with self.lock:
        entries = self.api_data.get(key_text)
        tags_snapshot = list(self.endpoint_tags.get(key_text, []) or [])
        times_snapshot = list(self.endpoint_times.get(key_text, []) or [])

    if entries is None:
        lines.append("Selected: {}".format(key_text))
        lines.append("Status: Not found in Recon cache")
        lines.append("")
        lines.append("To view full request/response:")
        lines.append("1) Right-click selected endpoint in Recon.")
        lines.append("2) Click 'Show Detail (Logger)'.")
        details_area.setText("\n".join(lines))
        details_area.setCaretPosition(0)
        return

    entries_list = entries if isinstance(entries, list) else [entries]
    sample = self._get_entry(entries_list)

    method = self._ascii_safe(sample.get("method") or "").upper().strip()
    path = self._ascii_safe(
        sample.get("normalized_path") or sample.get("path") or "/"
    ).strip() or "/"
    host = self._ascii_safe(sample.get("host") or "", lower=True).strip() or "-"
    severity = self._ascii_safe(self._get_severity(key_text, entries_list) or "info").upper()

    status_codes = []
    seen_codes = set()
    auth_signals = set()
    content_types = set()
    derived_times = []
    response_sizes = []
    error_count = 0
    first_seen = ""
    last_seen = ""

    def _extract_seen_value(row_obj):
        if not isinstance(row_obj, dict):
            return ""
        for field in [
            "captured_at",
            "timestamp",
            "time",
            "seen_at",
            "created_at",
            "updated_at",
        ]:
            value = self._ascii_safe(row_obj.get(field) or "").strip()
            if value:
                return value
        return ""

    for row in entries_list:
        code = int(row.get("response_status", 0) or 0)
        if code > 0 and code not in seen_codes:
            seen_codes.add(code)
            status_codes.append(code)
        if code >= 400:
            error_count += 1
        for auth_value in list(row.get("auth_detected", []) or []):
            token = self._ascii_safe(auth_value or "").strip()
            if token:
                auth_signals.add(token)
        ctype = self._ascii_safe(row.get("content_type") or "").strip()
        if ctype:
            content_types.add(ctype.split(";", 1)[0].strip())
        try:
            resp_len = int(row.get("response_length", 0) or 0)
        except (TypeError, ValueError):
            resp_len = 0
        if resp_len >= 0:
            response_sizes.append(resp_len)
        try:
            rt = int(row.get("response_time_ms", 0) or 0)
        except (TypeError, ValueError):
            rt = 0
        if rt > 0:
            derived_times.append(rt)
        seen_value = _extract_seen_value(row)
        if seen_value:
            if not first_seen:
                first_seen = seen_value
            last_seen = seen_value

    if not times_snapshot:
        times_snapshot = list(derived_times)

    if (not first_seen) or (not last_seen):
        with self.logger_lock:
            logger_snapshot = list(getattr(self, "logger_events", []) or [])
        first_logger_time = ""
        last_logger_time = ""
        for event in logger_snapshot:
            event_key = self._ascii_safe(event.get("endpoint_key") or "").strip()
            if event_key != key_text:
                continue
            event_time = self._ascii_safe(event.get("time") or "").strip()
            if not event_time:
                continue
            if not first_logger_time:
                first_logger_time = event_time
            last_logger_time = event_time
        if not first_seen:
            first_seen = first_logger_time
        if not last_seen:
            last_seen = last_logger_time

    status_text = ", ".join([str(code) for code in sorted(status_codes)]) if status_codes else "-"
    auth_text = ", ".join(sorted(auth_signals)) if auth_signals else "-"
    ctype_text = ", ".join(sorted(content_types)) if content_types else "-"
    tags_text = ", ".join(tags_snapshot[:8]) if tags_snapshot else "-"
    first_seen_text = first_seen if first_seen else "-"
    last_seen_text = last_seen if last_seen else "-"

    sample_count = len(entries_list)
    if sample_count > 0:
        error_rate = (100.0 * float(error_count)) / float(sample_count)
        error_rate_text = "{}/{} ({:.1f}%)".format(error_count, sample_count, error_rate)
    else:
        error_rate_text = "-"

    lower_auth = set([self._ascii_safe(item, lower=True).strip() for item in auth_signals if self._ascii_safe(item).strip()])
    if len(lower_auth) <= 1:
        auth_drift_text = "No"
    elif ("none" in lower_auth) and (len(lower_auth) > 1):
        auth_drift_text = "YES (none + authenticated variants)"
    else:
        auth_drift_text = "YES ({} variants)".format(len(lower_auth))

    if response_sizes:
        avg_size = int(float(sum(response_sizes)) / float(len(response_sizes)))
        size_text = "avg={} min={} max={}".format(
            avg_size, int(min(response_sizes)), int(max(response_sizes))
        )
    else:
        size_text = "-"

    param_text = "-"
    try:
        merged_params = self._merge_params(entries_list)
        top_params = []
        for ptype in ["url", "body", "cookie", "json"]:
            for pname in sorted(list(merged_params.get(ptype, []) or [])):
                safe_name = self._ascii_safe(pname or "").strip()
                if safe_name and (safe_name not in top_params):
                    top_params.append(safe_name)
                if len(top_params) >= 8:
                    break
            if len(top_params) >= 8:
                break
        if top_params:
            param_text = ", ".join(top_params)
    except Exception as param_err:
        self._callbacks.printError(
            "Recon detail param summary error: {}".format(str(param_err))
        )

    lines.append("Selected: {}".format(key_text))
    lines.append("Host: {} | Method: {} | Path: {}".format(host, method or "-", path))
    lines.append("Severity: {} | Samples: {}".format(severity, len(entries_list)))
    lines.append("First Seen: {} | Last Seen: {}".format(first_seen_text, last_seen_text))
    lines.append("Status Codes: {}".format(status_text))
    lines.append("Error Rate (4xx/5xx): {}".format(error_rate_text))
    lines.append("Auth Drift: {}".format(auth_drift_text))
    if times_snapshot:
        avg_time = int(float(sum(times_snapshot)) / float(len(times_snapshot)))
        lines.append(
            "Response Time (ms): avg={} min={} max={}".format(
                avg_time, int(min(times_snapshot)), int(max(times_snapshot))
            )
        )
    else:
        lines.append("Response Time (ms): -")
    lines.append("Response Size (bytes): {}".format(size_text))
    lines.append("Auth Signals: {}".format(auth_text))
    lines.append("Content Types: {}".format(ctype_text))
    lines.append("Tags: {}".format(tags_text))
    lines.append("Top Params: {}".format(param_text))
    lines.append("")
    lines.append("To view full request/response:")
    lines.append("1) Right-click selected endpoint in Recon.")
    lines.append("2) Click 'Show Detail (Logger)'.")
    details_area.setText("\n".join(lines))
    details_area.setCaretPosition(0)

def _recon_show_selected_endpoint_detail(self):
    """Track selected Recon row and show redirect text (details now live in Logger)."""
    endpoint_key = self._get_selected_endpoint_key()
    if not endpoint_key:
        self._recon_set_detail_redirect_text(None)
        return False
    self._recon_selected_endpoint_key = endpoint_key
    self._recon_set_detail_redirect_text(endpoint_key)
    return True

def _show_selected_recon_endpoint_details(self, event=None):
    """Compat wrapper for Recon selection refresh (redirect text only)."""
    if self._recon_show_selected_endpoint_detail():
        return
    endpoint_key = self._get_selected_endpoint_key(event=event)
    if endpoint_key:
        self._recon_selected_endpoint_key = endpoint_key
        self._recon_set_detail_redirect_text(endpoint_key)
    else:
        self._recon_set_detail_redirect_text(None)

def _entry_matches_profile_hint(self, entry, profile_key):
    """Heuristic to prefer entries that likely match chosen profile."""
    auth_detected = [str(a).lower() for a in entry.get("auth_detected", [])]
    if profile_key == "guest":
        return (
            ("none" in auth_detected)
            or ("session cookie" in auth_detected)
            or (len(auth_detected) == 0)
        )
    return "none" not in auth_detected

def _extract_profile_header_candidates_from_headers(self, headers, profile_key):
    """Collect ordered header candidates from one request header set."""
    if not headers or not isinstance(headers, dict):
        return []

    if profile_key == "guest":
        priority = [
            "cookie",
            "authorization",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-session-token",
            "x-csrf-token",
        ]
    else:
        priority = [
            "authorization",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "cookie",
            "x-session-token",
            "x-csrf-token",
        ]

    header_items = []
    for key, value in headers.items():
        key_str = str(key).strip()
        value_str = str(value).strip()
        if key_str and value_str:
            header_items.append((key_str, value_str))

    candidates = []
    seen = set()

    for wanted in priority:
        for key, value in header_items:
            candidate = "{}: {}".format(key, value)
            candidate_key = candidate.lower()
            if key.lower() == wanted and candidate_key not in seen:
                candidates.append(candidate)
                seen.add(candidate_key)

    keyword_priority = ["auth", "token", "cookie", "session", "api-key", "apikey"]
    for keyword in keyword_priority:
        for key, value in header_items:
            key_lower = key.lower()
            candidate = "{}: {}".format(key, value)
            candidate_key = candidate.lower()
            if keyword in key_lower and candidate_key not in seen:
                candidates.append(candidate)
                seen.add(candidate_key)

    return candidates

def _extract_profile_header_from_headers(self, headers, profile_key):
    """Pick first best candidate header from header dict for selected profile."""
    candidates = self._extract_profile_header_candidates_from_headers(
        headers, profile_key
    )
    return candidates[0] if candidates else None

def _find_profile_header_candidates_in_entries(
    self, entries, profile_key, prefer_match=True, max_candidates=10
):
    """Search entries list and return ordered unique header candidates."""
    entries_list = entries if isinstance(entries, list) else [entries]
    if prefer_match:
        first_pass = [
            e
            for e in entries_list
            if isinstance(e, dict) and self._entry_matches_profile_hint(e, profile_key)
        ]
        second_pass = entries_list
    else:
        first_pass = entries_list
        second_pass = []

    results = []
    seen = set()
    for pass_entries in [first_pass, second_pass]:
        for entry in pass_entries:
            if not isinstance(entry, dict):
                continue
            candidates = self._extract_profile_header_candidates_from_headers(
                entry.get("headers", {}), profile_key
            )
            for header_line in candidates:
                normalized = header_line.lower()
                if normalized in seen:
                    continue
                results.append(header_line)
                seen.add(normalized)
                if len(results) >= max_candidates:
                    return results
    return results

def _build_auth_header_choice_label(self, index, endpoint_key, header_line, is_selected):
    """Build readable label for header extraction popup."""
    source_label = "[Selected]" if is_selected else "[Captured]"
    endpoint_label = endpoint_key or "<unknown endpoint>"
    preview = header_line
    if len(preview) > 110:
        preview = preview[:107] + "..."
    return "#{:02d} {} {} -> {}".format(
        index, source_label, endpoint_label, preview
    )

def _choose_auth_profile_header_candidate(self, profile_key, options):
    """Show searchable popup for choosing extracted header candidate."""
    chooser_panel = JPanel(BorderLayout(6, 6))
    top_row = JPanel(FlowLayout(FlowLayout.LEFT))
    top_row.add(JLabel("Filter:"))
    search_field = JTextField("", 42)
    top_row.add(search_field)
    chooser_panel.add(top_row, BorderLayout.NORTH)

    list_model = DefaultListModel()
    candidate_list = JList(list_model)
    candidate_list.setVisibleRowCount(12)
    candidate_scroll = JScrollPane(candidate_list)
    candidate_scroll.setPreferredSize(Dimension(1080, 260))
    chooser_panel.add(candidate_scroll, BorderLayout.CENTER)

    footer = JLabel(
        "Type to filter by endpoint/header text. Select one item then click OK."
    )
    chooser_panel.add(footer, BorderLayout.SOUTH)

    visible_indices = []

    def rebuild_visible_candidates():
        query = search_field.getText().strip().lower()
        list_model.clear()
        visible_indices[:] = []
        for idx, option in enumerate(options):
            searchable = "{} {} {}".format(
                option.get("label", ""),
                option.get("value", ""),
                option.get("endpoint", ""),
            ).lower()
            if query and query not in searchable:
                continue
            list_model.addElement(option.get("label", ""))
            visible_indices.append(idx)
        if list_model.getSize() > 0:
            candidate_list.setSelectedIndex(0)

    class HeaderFilterListener(DocumentListener):
        def insertUpdate(self, e):
            rebuild_visible_candidates()

        def removeUpdate(self, e):
            rebuild_visible_candidates()

        def changedUpdate(self, e):
            rebuild_visible_candidates()

    search_field.getDocument().addDocumentListener(HeaderFilterListener())
    rebuild_visible_candidates()

    result = JOptionPane.showConfirmDialog(
        self._panel,
        chooser_panel,
        "{} Header Extract".format(profile_key.capitalize()),
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
    )
    if result != JOptionPane.OK_OPTION:
        return None

    selected_idx = candidate_list.getSelectedIndex()
    if selected_idx < 0 or selected_idx >= len(visible_indices):
        self.auth_replay_area.append(
            "[!] No {} header selected from popup.\n".format(profile_key)
        )
        return None

    option_index = visible_indices[selected_idx]
    if option_index < 0 or option_index >= len(options):
        self.auth_replay_area.append(
            "[!] Invalid {} header selection index.\n".format(profile_key)
        )
        return None
    return options[option_index]

def _parse_comma_newline_values(self, text):
    """Parse comma/newline text into ordered unique values."""
    values = []
    seen = set()
    raw = self._ascii_safe(text or "")
    for part in re.split(r"[\n,]+", raw):
        value = self._ascii_safe(part).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values

def _show_multi_select_targets_popup(
    self, title, options, preselected_values=None, footer_text=""
):
    """Show searchable multi-select popup and return selected values."""
    normalized_options = []
    seen = set()
    for item in (options or []):
        value = self._ascii_safe(item.get("value") or "").strip()
        if (not value) or value in seen:
            continue
        seen.add(value)
        label = self._ascii_safe(item.get("label") or value).strip()
        normalized_options.append({"value": value, "label": label})

    if not normalized_options:
        return []

    selected = set()
    for value in (preselected_values or []):
        safe_value = self._ascii_safe(value).strip()
        if safe_value:
            selected.add(safe_value)
    if not selected:
        selected = set([item.get("value") for item in normalized_options])

    chooser_panel = JPanel(BorderLayout(6, 6))
    top_row = JPanel(FlowLayout(FlowLayout.LEFT))
    top_row.add(JLabel("Filter:"))
    search_field = JTextField("", 36)
    top_row.add(search_field)

    select_all_btn = JButton("Select All")
    clear_btn = JButton("Clear")
    top_row.add(select_all_btn)
    top_row.add(clear_btn)
    chooser_panel.add(top_row, BorderLayout.NORTH)

    checkbox_panel = JPanel()
    checkbox_panel.setLayout(BoxLayout(checkbox_panel, BoxLayout.Y_AXIS))
    scroll = JScrollPane(checkbox_panel)
    scroll.setPreferredSize(Dimension(1080, 300))
    chooser_panel.add(scroll, BorderLayout.CENTER)

    chooser_panel.add(
        JLabel(
            footer_text
            or "Selected items are applied when you click OK. Use Filter to narrow the list."
        ),
        BorderLayout.SOUTH,
    )

    visible_boxes = []

    def rebuild():
        query = self._ascii_safe(search_field.getText(), lower=True).strip()
        checkbox_panel.removeAll()
        del visible_boxes[:]

        matched = 0
        for item in normalized_options:
            value = item.get("value")
            label = item.get("label")
            searchable = self._ascii_safe(
                "{} {}".format(label, value), lower=True
            )
            if query and query not in searchable:
                continue

            checkbox = JCheckBox(label, value in selected)
            checkbox.setToolTipText(value)
            checkbox.addActionListener(
                lambda e, v=value, cb=checkbox: selected.add(v)
                if cb.isSelected()
                else selected.discard(v)
            )
            checkbox_panel.add(checkbox)
            visible_boxes.append({"value": value, "box": checkbox})
            matched += 1

        if matched == 0:
            checkbox_panel.add(JLabel("No matches."))

        checkbox_panel.revalidate()
        checkbox_panel.repaint()

    class TargetPopupFilterListener(DocumentListener):
        def insertUpdate(self, e):
            rebuild()

        def removeUpdate(self, e):
            rebuild()

        def changedUpdate(self, e):
            rebuild()

    def select_visible(event):
        for item in visible_boxes:
            value = item.get("value")
            box = item.get("box")
            if box is not None:
                box.setSelected(True)
            if value:
                selected.add(value)

    def clear_visible(event):
        for item in visible_boxes:
            value = item.get("value")
            box = item.get("box")
            if box is not None:
                box.setSelected(False)
            if value in selected:
                selected.remove(value)

    search_field.getDocument().addDocumentListener(TargetPopupFilterListener())
    select_all_btn.addActionListener(select_visible)
    clear_btn.addActionListener(clear_visible)
    rebuild()

    result = JOptionPane.showConfirmDialog(
        self._panel,
        chooser_panel,
        self._ascii_safe(title) or "Targets",
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE,
    )
    if result != JOptionPane.OK_OPTION:
        return None

    return [
        item.get("value")
        for item in normalized_options
        if item.get("value") in selected
    ]

def _extract_auth_profile_header(self, profile_key):
    """Extract profile header candidates and let user choose via popup."""
    profile_key = (profile_key or "").strip().lower()
    field = self._get_auth_profile_field(profile_key)
    if field is None:
        self.auth_replay_area.append("[!] Unknown profile: {}\n".format(profile_key))
        return

    selected_key = self._get_selected_endpoint_key()
    with self.lock:
        data_snapshot = list(self.api_data.items())

    options = []
    seen_values = set()
    max_options = 35

    def add_option(endpoint_key, header_line, is_selected):
        if not header_line:
            return
        normalized = header_line.strip().lower()
        if not normalized or normalized in seen_values:
            return
        if len(options) >= max_options:
            return
        options.append(
            {
                "label": self._build_auth_header_choice_label(
                    len(options) + 1, endpoint_key, header_line, is_selected
                ),
                "value": header_line,
                "endpoint": endpoint_key,
            }
        )
        seen_values.add(normalized)

    if selected_key:
        selected_entries = None
        for endpoint_key, entries in data_snapshot:
            if endpoint_key == selected_key:
                selected_entries = entries
                break
        if selected_entries:
            selected_candidates = self._find_profile_header_candidates_in_entries(
                selected_entries, profile_key, prefer_match=True, max_candidates=12
            )
            if not selected_candidates:
                selected_candidates = self._find_profile_header_candidates_in_entries(
                    selected_entries, profile_key, prefer_match=False, max_candidates=12
                )
            for header_line in selected_candidates:
                add_option(selected_key, header_line, True)

    for endpoint_key, entries in data_snapshot:
        if len(options) >= max_options:
            break
        if selected_key and endpoint_key == selected_key:
            continue
        candidates = self._find_profile_header_candidates_in_entries(
            entries, profile_key, prefer_match=True, max_candidates=4
        )
        for header_line in candidates:
            add_option(endpoint_key, header_line, False)
            if len(options) >= max_options:
                break

    if not options:
        for endpoint_key, entries in data_snapshot:
            if len(options) >= max_options:
                break
            if selected_key and endpoint_key == selected_key:
                continue
            candidates = self._find_profile_header_candidates_in_entries(
                entries, profile_key, prefer_match=False, max_candidates=3
            )
            for header_line in candidates:
                add_option(endpoint_key, header_line, False)
                if len(options) >= max_options:
                    break

    if not options:
        self.auth_replay_area.append(
            "[!] No {} header candidate found. Select endpoint with auth/cookie headers and retry.\n".format(
                profile_key
            )
        )
        return

    chosen = self._choose_auth_profile_header_candidate(profile_key, options)
    if chosen is None:
        self.auth_replay_area.append(
            "[*] {} header extraction cancelled by user.\n".format(
                profile_key.capitalize()
            )
        )
        return

    field.setText(chosen["value"])
    self.auth_replay_area.append(
        "[+] {} header selected from {}.\n".format(
            profile_key.capitalize(), chosen["endpoint"]
        )
    )

def _build_auth_replay_request(self, entry, profile_header):
    """Build raw HTTP request with optional auth/profile header override."""
    method = (entry.get("method") or "GET").upper()
    path = entry.get("path") or "/"
    query = entry.get("query_string") or ""
    if query:
        path += "?" + query

    request_line = "{} {} HTTP/1.1\r\n".format(method, path)
    headers = ["Host: {}".format(entry.get("host", ""))]
    existing_headers = entry.get("headers", {}) or {}

    override_header_name = None
    if profile_header:
        override_header_name = profile_header[0].lower()

    added = set(["host"])
    for key, value in existing_headers.items():
        key_str = str(key)
        value_str = str(value)
        key_lower = key_str.lower()
        if key_lower in ["host", "content-length", "connection"]:
            continue
        if override_header_name and key_lower == override_header_name:
            continue
        headers.append("{}: {}".format(key_str, value_str))
        added.add(key_lower)

    if "user-agent" not in added:
        headers.append("User-Agent: BurpAPISecuritySuite/AuthReplay")
    if "accept" not in added:
        headers.append("Accept: */*")
    headers.append("Connection: close")

    if profile_header:
        headers.append("{}: {}".format(profile_header[0], profile_header[1]))

    body = entry.get("request_body") or ""
    if body:
        headers.append("Content-Length: {}".format(len(body)))

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    if body:
        request += body
    return request

def _perform_auth_replay_request(self, entry, profile_header):
    """Send request and return compact response signature."""
    host = entry.get("host", "")
    protocol = entry.get("protocol", "https")
    use_https = protocol == "https"
    port = entry.get("port", -1)
    if port == -1:
        port = 443 if use_https else 80

    request = self._build_auth_replay_request(entry, profile_header)
    request_bytes = self._helpers.stringToBytes(request)

    try:
        response_obj = self._callbacks.makeHttpRequest(
            host, port, use_https, request_bytes
        )
    except Exception as e:
        return {
            "status": 0,
            "length": 0,
            "preview": "",
            "error": "request failed: {}".format(str(e)),
        }

    response = response_obj
    if hasattr(response_obj, "getResponse"):
        response = response_obj.getResponse()

    if not response:
        return {
            "status": 0,
            "length": 0,
            "preview": "",
            "error": "empty response",
        }

    try:
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        response_len = max(0, len(response) - body_offset)
        preview_bytes = response[body_offset : body_offset + 320]
        preview = self._helpers.bytesToString(preview_bytes)
        preview = re.sub(r"\s+", " ", (preview or "")).strip()
        return {
            "status": resp_info.getStatusCode(),
            "length": response_len,
            "preview": preview,
            "error": None,
        }
    except Exception as e:
        return {
            "status": 0,
            "length": 0,
            "preview": "",
            "error": "response parse failed: {}".format(str(e)),
        }

def _auth_replay_preview_similar(self, left_preview, right_preview):
    """Loose similarity check for body previews."""
    left = (left_preview or "").lower()
    right = (right_preview or "").lower()
    left = re.sub(r"\s+", " ", left)
    right = re.sub(r"\s+", " ", right)
    left = re.sub(r"[0-9a-f]{24,}", "{token}", left)
    right = re.sub(r"[0-9a-f]{24,}", "{token}", right)
    left = re.sub(r"\d+", "0", left)
    right = re.sub(r"\d+", "0", right)

    if not left and not right:
        return True
    if left == right:
        return True

    overlap = min(len(left), len(right), 140)
    if overlap >= 40 and left[:overlap] == right[:overlap]:
        return True
    return False

def _parse_auth_replay_status_codes(self, raw_text):
    """Parse comma-separated enforcement status list."""
    values = []
    seen = set()
    for token in self._parse_comma_newline_values(raw_text or ""):
        try:
            code = int(self._ascii_safe(token).strip())
        except (TypeError, ValueError):
            continue
        if code < 100 or code > 599 or code in seen:
            continue
        seen.add(code)
        values.append(code)
    return set(values)

def _compile_optional_regex(self, pattern_text, field_label):
    """Compile optional regex, raising ValueError for invalid patterns."""
    pattern = self._ascii_safe(pattern_text or "").strip()
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as regex_err:
        raise ValueError("{} regex invalid: {}".format(field_label, self._ascii_safe(regex_err)))

def _auth_replay_detector_for_role(self, role_name, detector_cfg):
    """Resolve effective detector config for one low-priv profile."""
    base_statuses = set(detector_cfg.get("enforced_statuses") or set())
    base_regex = detector_cfg.get("enforced_regex")
    by_role = detector_cfg.get("by_role") or {}
    override = by_role.get(self._ascii_safe(role_name, lower=True).strip()) or {}

    role_statuses = override.get("enforced_statuses")
    if role_statuses is not None:
        role_statuses = set(role_statuses or set())
    else:
        role_statuses = set(base_statuses)

    role_regex = override.get("enforced_regex")
    if role_regex is None:
        role_regex = base_regex

    return {
        "enforced_statuses": role_statuses,
        "enforced_regex": role_regex,
    }

def _auth_replay_response_is_enforced(self, low_role, low_data, detector_cfg):
    """Determine if low-privileged response indicates enforced access control."""
    role_detector = self._auth_replay_detector_for_role(low_role, detector_cfg)
    status = int((low_data or {}).get("status", 0) or 0)
    if status in (role_detector.get("enforced_statuses") or set()):
        return True

    enforced_regex = role_detector.get("enforced_regex")
    preview = self._ascii_safe((low_data or {}).get("preview") or "", lower=True)
    if enforced_regex and preview and enforced_regex.search(preview):
        return True

    if status in [401, 403]:
        return True
    return False

def _evaluate_auth_replay_findings(self, endpoint_key, role_results, detector_cfg=None):
    """Score likely authorization issues from role response signatures."""
    findings = []
    detector_cfg = detector_cfg or {}
    if "admin" in role_results:
        high_role = "admin"
    elif "user" in role_results:
        high_role = "user"
    else:
        high_role = "guest"

    high_data = role_results.get(high_role, {})
    if high_data.get("error"):
        return findings

    success_codes = set([200, 201, 202, 204, 206])
    compare_roles = [role for role in ["unauth", "guest", "user"] if role in role_results]
    for low_role in compare_roles:
        if low_role == high_role:
            continue
        low_data = role_results.get(low_role, {})
        if low_data.get("error"):
            continue

        low_status = int(low_data.get("status", 0) or 0)
        high_status = int(high_data.get("status", 0) or 0)
        low_len = int(low_data.get("length", 0) or 0)
        high_len = int(high_data.get("length", 0) or 0)
        similar_preview = self._auth_replay_preview_similar(
            low_data.get("preview", ""), high_data.get("preview", "")
        )
        length_delta = abs(low_len - high_len)
        length_close = length_delta <= max(32, int(max(low_len, high_len) * 0.12))
        low_enforced = self._auth_replay_response_is_enforced(
            low_role, low_data, detector_cfg
        )

        finding = None
        if (
            (not low_enforced)
            and
            low_status in success_codes
            and high_status in success_codes
            and low_status == high_status
            and (similar_preview or length_close)
        ):
            severity = (
                "critical"
                if low_role == "guest" and high_role == "admin"
                else "high"
            )
            finding = {
                "severity": severity,
                "endpoint": endpoint_key,
                "issue": "{} response looks similar to {} response".format(
                    low_role, high_role
                ),
                "low_role": low_role,
                "high_role": high_role,
                "low_status": low_status,
                "high_status": high_status,
                "low_length": low_len,
                "high_length": high_len,
            }
        elif low_status in success_codes and high_status in [401, 403]:
            finding = {
                "severity": "high",
                "endpoint": endpoint_key,
                "issue": "{} access succeeded while {} was denied".format(
                    low_role, high_role
                ),
                "low_role": low_role,
                "high_role": high_role,
                "low_status": low_status,
                "high_status": high_status,
                "low_length": low_len,
                "high_length": high_len,
            }
        elif (
            (not low_enforced)
            and
            low_status == high_status
            and low_status not in [0, 401, 403, 404]
            and length_close
            and similar_preview
        ):
            finding = {
                "severity": "medium",
                "endpoint": endpoint_key,
                "issue": "{} and {} responses are nearly identical".format(
                    low_role, high_role
                ),
                "low_role": low_role,
                "high_role": high_role,
                "low_status": low_status,
                "high_status": high_status,
                "low_length": low_len,
                "high_length": high_len,
            }

        if finding:
            findings.append(finding)

    return findings

def _collect_auth_replay_targets(
    self, scope, max_count, include_regex=None, exclude_regex=None, method_allowlist=None
):
    """Collect endpoint keys based on replay scope."""
    keys = []
    if scope == "Selected Endpoint":
        selected_value = self.endpoint_list.getSelectedValue()
        if not selected_value:
            return [], 0
        endpoint_key = EndpointClickListener._extract_endpoint_key(str(selected_value))
        if not endpoint_key:
            return [], 0
        keys = [endpoint_key]
    elif scope == "Filtered View":
        with self.lock:
            keys = list(self._filter_endpoints().keys())
    else:
        with self.lock:
            keys = list(self.api_data.keys())

    prioritized = []
    with self.lock:
        for endpoint_key in keys:
            entries = self.api_data.get(endpoint_key)
            if not entries:
                continue
            entry = self._get_entry(entries)
            endpoint_text = self._ascii_safe(endpoint_key)
            method_upper = self._ascii_safe(entry.get("method") or "", lower=True).upper()
            if method_allowlist and method_upper not in method_allowlist:
                continue
            if include_regex and not include_regex.search(endpoint_text):
                continue
            if exclude_regex and exclude_regex.search(endpoint_text):
                continue
            severity = self._get_severity(endpoint_key, entries)
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
            id_like = (
                0
                if re.search(
                    r"/{id}|/{uuid}|/{objectid}", entry.get("normalized_path", "")
                )
                else 1
            )
            prioritized.append(
                (
                    severity_rank.get(severity, 4),
                    id_like,
                    endpoint_key,
                )
            )

    prioritized.sort(key=lambda item: (item[0], item[1], item[2]))
    ordered_keys = [item[2] for item in prioritized]
    total_available = len(ordered_keys)
    if max_count > 0:
        ordered_keys = ordered_keys[:max_count]
    return ordered_keys, total_available

def _run_auth_replay(self, event):
    return jython_size_helpers.run_auth_replay(self, event)

def _run_passive_discovery(self, event):
    """Run passive API3/API4/API5/API6/API9/API10 heuristics from captured history."""
    if not self.api_data:
        self.passive_area.setText(
            "[!] No endpoints in Recon tab. Capture or import first\n"
        )
        return

    max_text = self.passive_max_field.getText().strip() or "250"
    try:
        max_count = int(max_text)
        if max_count < 1:
            max_count = 1
        if max_count > 1000:
            max_count = 1000
    except ValueError:
        max_count = 250

    scope = str(self.passive_scope_combo.getSelectedItem())
    mode = str(self.passive_mode_combo.getSelectedItem())
    endpoint_keys, total_available = self._collect_auth_replay_targets(scope, max_count)
    if not endpoint_keys:
        self.passive_area.setText(
            "[!] No endpoints found for scope '{}'\n".format(scope)
        )
        return

    self.passive_area.setText("[*] Starting passive discovery...\n")
    self.passive_area.append(
        "[*] Scope: {} | Mode: {} | Targets: {} of {}\n\n".format(
            scope, mode, len(endpoint_keys), total_available
        )
    )

    def run_passive():
        try:
            snapshot = self._collect_passive_snapshot(endpoint_keys)
            findings = self._run_passive_mode_handlers(mode, snapshot)
            findings = self._sort_and_store_passive_findings(findings)

            text = self._format_passive_discovery_output(
                findings, len(snapshot), total_available, mode
            )
            SwingUtilities.invokeLater(lambda t=text: self.passive_area.setText(t))
            SwingUtilities.invokeLater(
                lambda: self.log_to_ui(
                    "[+] Passive discovery complete ({} findings)".format(
                        len(findings)
                    )
                )
            )
        except Exception as e:
            err_msg = self._ascii_safe(e)
            err = "[!] Passive discovery failed: {}\n".format(err_msg)
            SwingUtilities.invokeLater(lambda t=err: self.passive_area.append(t))
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui(
                    "[!] Passive discovery error: {}".format(m)
                )
            )

    worker = threading.Thread(target=run_passive)
    worker.daemon = True
    worker.start()

def _run_sequence_invariants(self, event):
    """Run non-destructive sequence/state invariant checks for deep logic gaps."""
    if not self.api_data:
        self.passive_area.setText(
            "[!] No endpoints in Recon tab. Capture or import first\n"
        )
        return

    max_text = self.passive_max_field.getText().strip() or "250"
    try:
        max_count = int(max_text)
        if max_count < 1:
            max_count = 1
        if max_count > 1000:
            max_count = 1000
    except ValueError:
        max_count = 250

    scope = str(self.passive_scope_combo.getSelectedItem())
    endpoint_keys, total_available = self._collect_auth_replay_targets(
        scope, max_count
    )
    if not endpoint_keys:
        self.passive_area.setText(
            "[!] No endpoints found for scope '{}'\n".format(scope)
        )
        return

    self.passive_area.setText("[*] Starting deep-logic analysis (Sequence + Golden + State)...\n")
    self.passive_area.append(
        "[*] Scope: {} | Targets: {} of {}\n\n".format(
            scope, len(endpoint_keys), total_available
        )
    )

    def run_invariants():
        try:
            snapshot = self._collect_passive_snapshot(endpoint_keys)
            package = self._build_sequence_invariant_package(snapshot)
            golden_package = self._build_golden_ticket_package(snapshot)
            state_package = self._build_state_transition_package(snapshot)
            advanced_packages = self._build_advanced_logic_packages(
                snapshot,
                sequence_package=package,
                golden_package=golden_package,
                state_package=state_package,
            )
            self._sort_and_store_sequence_invariant_payload(
                package,
                source_label="passive_run",
                scope_label=scope,
                target_count=len(snapshot),
            )
            self._sort_and_store_golden_ticket_payload(
                golden_package,
                source_label="passive_run",
                scope_label=scope,
                target_count=len(snapshot),
            )
            self._sort_and_store_state_transition_payload(
                state_package,
                source_label="passive_run",
                scope_label=scope,
                target_count=len(snapshot),
            )
            self._store_advanced_logic_packages(
                advanced_packages,
                source_label="passive_run",
                scope_label=scope,
                target_count=len(snapshot),
            )
            text = self._format_sequence_invariant_output(
                package, len(snapshot), total_available, scope
            )
            text += self._format_golden_ticket_output(golden_package)
            text += self._format_state_transition_output(state_package)
            text += self._format_advanced_logic_output(advanced_packages, mode="all")
            SwingUtilities.invokeLater(lambda t=text: self.passive_area.setText(t))
            finding_count = int(package.get("finding_count", 0) or 0)
            golden_count = int(golden_package.get("finding_count", 0) or 0)
            state_count = int(state_package.get("finding_count", 0) or 0)
            chain_count = int(
                (advanced_packages.get("abuse_chains", {}) or {}).get(
                    "finding_count", 0
                )
                or 0
            )
            proof_count = int(
                (advanced_packages.get("proof_mode", {}) or {}).get(
                    "packet_set_count", 0
                )
                or 0
            )
            guardrail_count = int(
                (advanced_packages.get("spec_guardrails", {}) or {}).get(
                    "violation_count", 0
                )
                or 0
            )
            role_count = int(
                (advanced_packages.get("role_delta", {}) or {}).get(
                    "finding_count", 0
                )
                or 0
            )
            SwingUtilities.invokeLater(
                lambda c=finding_count, g=golden_count, s=state_count, ac=chain_count, pm=proof_count, sg=guardrail_count, rd=role_count: self.log_to_ui(
                    "[+] Invariant analysis complete (seq={} golden={} state={} chains={} proof={} guardrails={} role={})".format(
                        c, g, s
                        , ac, pm, sg, rd
                    )
                )
            )
        except Exception as e:
            err_msg = self._ascii_safe(e)
            err = "[!] Sequence invariant analysis failed: {}\n".format(err_msg)
            SwingUtilities.invokeLater(lambda t=err: self.passive_area.append(t))
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui(
                    "[!] Sequence invariant error: {}".format(m)
                )
            )

    worker = threading.Thread(target=run_invariants)
    worker.daemon = True
    worker.start()

def _build_sequence_invariant_package(self, data_snapshot):
    """Build sequence-invariant findings and confidence ledger from snapshot."""
    payload = behavior_analysis.build_sequence_invariant_package(
        data_snapshot,
        get_entry=self._get_entry,
        extract_param_names=self._extract_param_names,
    )
    return self._sanitize_for_ai_payload(payload)

def _build_golden_ticket_package(self, data_snapshot):
    """Build Golden Ticket package from captured token behavior."""
    payload = behavior_analysis.build_golden_ticket_package(
        data_snapshot,
        get_entry=self._get_entry,
    )
    return self._sanitize_for_ai_payload(payload)

def _build_state_transition_package(self, data_snapshot):
    """Build State Transition package from captured workflow/state behavior."""
    payload = behavior_analysis.build_state_transition_package(
        data_snapshot,
        get_entry=self._get_entry,
    )
    return self._sanitize_for_ai_payload(payload)

def _sort_and_store_sequence_invariant_payload(
    self, package, source_label="passive", scope_label="Filtered Scope", target_count=None
):
    """Sort/store sequence invariant findings and associated ledger."""
    findings = list((package or {}).get("findings", []) or [])
    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
            self._ascii_safe(item.get("resource"), lower=True),
        )
    )
    ledger = dict((package or {}).get("ledger", {}) or {})
    generated_at = self._ascii_safe(
        (package or {}).get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")
    )
    count_value = (
        int(target_count)
        if isinstance(target_count, int) and target_count >= 0
        else None
    )
    with self.sequence_invariant_lock:
        self.sequence_invariant_findings = list(findings)
        self.sequence_invariant_ledger = ledger
        self.sequence_invariant_meta = {
            "generated_at": generated_at,
            "source": self._ascii_safe(source_label),
            "scope": self._ascii_safe(scope_label),
            "target_count": count_value,
            "finding_count": len(findings),
        }
    self._refresh_recon_invariant_status_label_async()

def _sort_and_store_golden_ticket_payload(
    self, package, source_label="passive", scope_label="Filtered Scope", target_count=None
):
    """Sort/store Golden Ticket findings and associated ledger."""
    findings = list((package or {}).get("findings", []) or [])
    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
            self._ascii_safe(item.get("resource"), lower=True),
        )
    )
    ledger = dict((package or {}).get("ledger", {}) or {})
    generated_at = self._ascii_safe(
        (package or {}).get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")
    )
    count_value = (
        int(target_count)
        if isinstance(target_count, int) and target_count >= 0
        else None
    )
    observed_token_count = int((package or {}).get("observed_token_count", 0) or 0)
    with self.golden_ticket_lock:
        self.golden_ticket_findings = list(findings)
        self.golden_ticket_ledger = ledger
        self.golden_ticket_meta = {
            "generated_at": generated_at,
            "source": self._ascii_safe(source_label),
            "scope": self._ascii_safe(scope_label),
            "target_count": count_value,
            "observed_token_count": observed_token_count,
            "finding_count": len(findings),
        }
    self._refresh_recon_invariant_status_label_async()

def _sort_and_store_state_transition_payload(
    self, package, source_label="passive", scope_label="Filtered Scope", target_count=None
):
    """Sort/store State Transition findings and associated ledger."""
    findings = list((package or {}).get("findings", []) or [])
    findings.sort(
        key=lambda item: (
            -float(item.get("confidence_score", 0.0) or 0.0),
            self._ascii_safe(item.get("severity"), lower=True),
            self._ascii_safe(item.get("resource"), lower=True),
        )
    )
    ledger = dict((package or {}).get("ledger", {}) or {})
    generated_at = self._ascii_safe(
        (package or {}).get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")
    )
    count_value = (
        int(target_count)
        if isinstance(target_count, int) and target_count >= 0
        else None
    )
    transition_edge_count = int((package or {}).get("transition_edge_count", 0) or 0)
    with self.state_transition_lock:
        self.state_transition_findings = list(findings)
        self.state_transition_ledger = ledger
        self.state_transition_meta = {
            "generated_at": generated_at,
            "source": self._ascii_safe(source_label),
            "scope": self._ascii_safe(scope_label),
            "target_count": count_value,
            "transition_edge_count": transition_edge_count,
            "finding_count": len(findings),
        }
    self._refresh_recon_invariant_status_label_async()

def _format_sequence_invariant_output(
    self, package, scanned_count, total_available, scope_label
):
    """Format sequence invariant findings for Passive tab output area."""
    findings = list((package or {}).get("findings", []) or [])
    ledger = dict((package or {}).get("ledger", {}) or {})
    severity_distribution = ledger.get("severity_distribution", {}) or {}
    confidence_distribution = ledger.get("confidence_distribution", {}) or {}

    lines = []
    lines.append("=" * 80)
    lines.append("SEQUENCE INVARIANT RESULTS")
    lines.append("=" * 80)
    lines.append("[*] Scope: {}".format(self._ascii_safe(scope_label)))
    lines.append("[*] Endpoints Scanned: {} (of {})".format(scanned_count, total_available))
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(severity_distribution.get("critical", 0) or 0),
            int(severity_distribution.get("high", 0) or 0),
            int(severity_distribution.get("medium", 0) or 0),
            int(severity_distribution.get("info", 0) or 0),
        )
    )
    lines.append(
        "[*] Confidence: High={} Medium={} Low={}".format(
            int(confidence_distribution.get("high", 0) or 0),
            int(confidence_distribution.get("medium", 0) or 0),
            int(confidence_distribution.get("low", 0) or 0),
        )
    )
    lines.append("")

    if not findings:
        lines.append("[+] No sequence invariant gaps flagged for current scope.")
        lines.append("[*] Capture richer role/state traffic, then rerun.")
        return "\n".join(lines) + "\n"

    lines.append("TOP FINDINGS")
    lines.append("-" * 80)
    for finding in findings[:120]:
        severity = self._ascii_safe(finding.get("severity", "info"), lower=True).upper()
        title = self._ascii_safe(finding.get("title", ""))
        invariant = self._ascii_safe(finding.get("invariant", ""))
        resource = self._ascii_safe(finding.get("resource", ""))
        score = float(finding.get("confidence_score", 0.0) or 0.0)
        label = self._ascii_safe(finding.get("confidence_label", ""))
        lines.append(
            "[{}][{} {:.2f}] {}".format(severity, label.upper(), score, title)
        )
        lines.append("  Invariant: {}".format(invariant))
        lines.append("  Resource: {}".format(resource))
        lines.append(
            "  Endpoints: {}".format(
                ", ".join(
                    [
                        self._ascii_safe(x)
                        for x in (finding.get("endpoint_scope", []) or [])[:6]
                    ]
                )
            )
        )
        evidence_lines = finding.get("evidence", []) or []
        for evidence in evidence_lines[:3]:
            lines.append("  Evidence: {}".format(self._ascii_safe(evidence)))
        suggested = finding.get("suggested_checks", []) or []
        if suggested:
            lines.append("  Next: {}".format(self._ascii_safe(suggested[0])))
        lines.append("")

    if len(findings) > 120:
        lines.append("[*] {} more findings not shown".format(len(findings) - 120))
    lines.append("")
    lines.append("[*] Use 'Export Ledger' for confidence/evidence JSON artifact.")
    return "\n".join(lines) + "\n"

def _format_golden_ticket_output(self, package):
    """Format Golden Ticket findings for Passive tab output area."""
    findings = list((package or {}).get("findings", []) or [])
    ledger = dict((package or {}).get("ledger", {}) or {})
    observed = int((package or {}).get("observed_token_count", 0) or 0)
    severity_distribution = ledger.get("severity_distribution", {}) or {}
    confidence_distribution = ledger.get("confidence_distribution", {}) or {}

    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("GOLDEN TICKET RESULTS")
    lines.append("=" * 80)
    lines.append("[*] Observed Tokens: {}".format(observed))
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(severity_distribution.get("critical", 0) or 0),
            int(severity_distribution.get("high", 0) or 0),
            int(severity_distribution.get("medium", 0) or 0),
            int(severity_distribution.get("info", 0) or 0),
        )
    )
    lines.append(
        "[*] Confidence: High={} Medium={} Low={}".format(
            int(confidence_distribution.get("high", 0) or 0),
            int(confidence_distribution.get("medium", 0) or 0),
            int(confidence_distribution.get("low", 0) or 0),
        )
    )
    lines.append("")

    if not findings:
        lines.append(
            "[+] No Golden Ticket patterns flagged from current captured token usage."
        )
        lines.append(
            "[*] Capture multiple roles/sessions/logout flows for stronger coverage."
        )
        return "\n".join(lines) + "\n"

    lines.append("TOP FINDINGS")
    lines.append("-" * 80)
    for finding in findings[:80]:
        severity = self._ascii_safe(finding.get("severity", "info"), lower=True).upper()
        title = self._ascii_safe(finding.get("title", ""))
        invariant = self._ascii_safe(finding.get("invariant", ""))
        score = float(finding.get("confidence_score", 0.0) or 0.0)
        label = self._ascii_safe(finding.get("confidence_label", ""))
        lines.append("[{}][{} {:.2f}] {}".format(severity, label.upper(), score, title))
        lines.append("  Pattern: {}".format(invariant))
        evidence_lines = finding.get("evidence", []) or []
        for evidence in evidence_lines[:2]:
            lines.append("  Evidence: {}".format(self._ascii_safe(evidence)))
        suggested = finding.get("suggested_checks", []) or []
        if suggested:
            lines.append("  Next: {}".format(self._ascii_safe(suggested[0])))
        lines.append("")

    if len(findings) > 80:
        lines.append("[*] {} more findings not shown".format(len(findings) - 80))
    return "\n".join(lines) + "\n"

def _format_state_transition_output(self, package):
    """Format State Transition findings for Passive tab output area."""
    findings = list((package or {}).get("findings", []) or [])
    ledger = dict((package or {}).get("ledger", {}) or {})
    resources = int((package or {}).get("resource_count", 0) or 0)
    edges = int((package or {}).get("transition_edge_count", 0) or 0)
    severity_distribution = ledger.get("severity_distribution", {}) or {}
    confidence_distribution = ledger.get("confidence_distribution", {}) or {}

    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("STATE TRANSITION MATRIX RESULTS")
    lines.append("=" * 80)
    lines.append("[*] Resources: {} | Transition Edges: {}".format(resources, edges))
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            int(severity_distribution.get("critical", 0) or 0),
            int(severity_distribution.get("high", 0) or 0),
            int(severity_distribution.get("medium", 0) or 0),
            int(severity_distribution.get("info", 0) or 0),
        )
    )
    lines.append(
        "[*] Confidence: High={} Medium={} Low={}".format(
            int(confidence_distribution.get("high", 0) or 0),
            int(confidence_distribution.get("medium", 0) or 0),
            int(confidence_distribution.get("low", 0) or 0),
        )
    )
    lines.append("")

    if not findings:
        lines.append("[+] No state-transition drift patterns flagged in current scope.")
        lines.append("[*] Capture more complete user workflows and rerun.")
        return "\n".join(lines) + "\n"

    lines.append("TOP FINDINGS")
    lines.append("-" * 80)
    for finding in findings[:80]:
        severity = self._ascii_safe(finding.get("severity", "info"), lower=True).upper()
        title = self._ascii_safe(finding.get("title", ""))
        invariant = self._ascii_safe(finding.get("invariant", ""))
        score = float(finding.get("confidence_score", 0.0) or 0.0)
        label = self._ascii_safe(finding.get("confidence_label", ""))
        lines.append("[{}][{} {:.2f}] {}".format(severity, label.upper(), score, title))
        lines.append("  Pattern: {}".format(invariant))
        evidence_lines = finding.get("evidence", []) or []
        for evidence in evidence_lines[:2]:
            lines.append("  Evidence: {}".format(self._ascii_safe(evidence)))
        suggested = finding.get("suggested_checks", []) or []
        if suggested:
            lines.append("  Next: {}".format(self._ascii_safe(suggested[0])))
        lines.append("")

    if len(findings) > 80:
        lines.append("[*] {} more findings not shown".format(len(findings) - 80))
    return "\n".join(lines) + "\n"

def _collect_passive_snapshot(self, endpoint_keys):
    """Collect immutable-ish endpoint snapshot for passive processing."""
    raw_snapshot = {}
    with self.lock:
        for key in endpoint_keys:
            raw_entries = self.api_data.get(key)
            if not raw_entries:
                continue
            if isinstance(raw_entries, list):
                raw_snapshot[key] = list(raw_entries)
            elif isinstance(raw_entries, dict):
                raw_snapshot[key] = [raw_entries]
            else:
                self._callbacks.printError(
                    "Passive snapshot skip {} (unsupported type: {})".format(
                        key, type(raw_entries)
                    )
                )
    filter_cfg = self._build_passive_filter_config(raw_snapshot)
    snapshot = {}
    for key, entries in raw_snapshot.items():
        filtered_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if self._passive_entry_allowed(entry, filter_cfg):
                filtered_entries.append(entry)
        if filtered_entries:
            snapshot[key] = filtered_entries
    return snapshot

def _build_passive_filter_config(self, snapshot):
    """Build passive filtering config to focus heuristics on API-like first-party traffic."""
    scope_override = self._get_target_scope_override()
    selected_host = "all"
    force_host = False
    if not scope_override.get("enabled"):
        try:
            if hasattr(self, "host_filter") and self.host_filter is not None:
                selected_host = self._ascii_safe(
                    str(self.host_filter.getSelectedItem()), lower=True
                ).strip() or "all"
        except Exception as e:
            self._callbacks.printError("Passive host-filter read error: {}".format(str(e)))
            selected_host = "all"
        force_host = bool(selected_host and selected_host != "all")

    entries_snapshot = []
    for entries in snapshot.values():
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            if isinstance(entry, dict):
                entries_snapshot.append(entry)

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
            score += 3

        path = self._ascii_safe(entry.get("normalized_path") or "/", lower=True)
        if (
            "/api/" in path
            or "/graphql" in path
            or "/rest/" in path
            or "/openapi" in path
            or "/swagger" in path
            or re.match(r"^/v\d+(?:\.\d+)?(?:/|$)", path)
        ):
            score += 3

        content_type = self._ascii_safe(entry.get("content_type"), lower=True)
        if "json" in content_type or "xml" in content_type:
            score += 2

        api_patterns = [
            self._ascii_safe(x, lower=True)
            for x in (entry.get("api_patterns", []) or [])
        ]
        if any(hint in api_patterns for hint in self.PASSIVE_API_PATTERN_HINTS):
            score += 2

        base_scores[base] = base_scores.get(base, 0) + score

    if scope_override.get("enabled"):
        allowed_bases = set(scope_override.get("bases", set()))
    elif force_host:
        base = self._infer_base_domain(selected_host)
        allowed_bases = set([base]) if base else set()
    else:
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

    return {
        "scope_override_enabled": bool(scope_override.get("enabled")),
        "scope_override": scope_override,
        "force_host": force_host,
        "selected_host": selected_host,
        "allowed_bases": allowed_bases,
    }

def _passive_entry_is_api_like(self, entry):
    """Heuristic gate to keep passive checks focused on API-like traffic."""
    method = self._ascii_safe(entry.get("method"), lower=True).strip().upper()
    path = self._ascii_safe(entry.get("normalized_path") or "/", lower=True).strip()
    content_type = self._ascii_safe(entry.get("content_type"), lower=True).strip()
    api_patterns = [
        self._ascii_safe(x, lower=True)
        for x in (entry.get("api_patterns", []) or [])
    ]

    first_part = ""
    parts = [p for p in path.strip("/").split("/") if p]
    if parts:
        first_part = parts[0]

    has_api_marker = bool(
        "/api/" in path
        or "/graphql" in path
        or "/rest/" in path
        or "/openapi" in path
        or "/swagger" in path
        or re.match(r"^/v\d+(?:\.\d+)?(?:/|$)", path)
    )
    has_structured_content = bool(
        ("json" in content_type or "xml" in content_type or "protobuf" in content_type)
        and ("javascript" not in content_type)
        and ("html" not in content_type)
    )
    has_api_pattern = any(
        hint in api_patterns for hint in self.PASSIVE_API_PATTERN_HINTS
    )
    has_write_method = method in ["POST", "PUT", "PATCH", "DELETE"]

    query_text = self._ascii_safe(entry.get("query_string") or "")
    query_count = len([p for p in query_text.split("&") if p]) if query_text else 0
    param_count = query_count
    params = entry.get("parameters", {}) or {}
    if isinstance(params, dict):
        for value in params.values():
            if isinstance(value, dict):
                param_count += len(value)
            elif isinstance(value, list):
                param_count += len(value)

    if method in ["GET", "HEAD", "OPTIONS"]:
        if path.endswith(self.PASSIVE_STATIC_EXTENSIONS):
            return False
        if first_part in self.PASSIVE_STATIC_PATH_PARTS:
            return False
        if self._ffuf_is_noise_path_segment(first_part):
            return False
        if (
            "javascript" in content_type
            or "ecmascript" in content_type
            or "text/css" in content_type
            or content_type.startswith("image/")
            or content_type.startswith("font/")
            or content_type.startswith("video/")
            or content_type.startswith("audio/")
        ):
            return False
        if (
            "html" in content_type
            and not has_api_marker
            and not has_structured_content
            and param_count < 5
        ):
            return False

    if len(path) > 220 and not (has_api_marker or has_structured_content or has_write_method):
        return False
    if re.search(r"/[a-z0-9_-]{80,}", path) and not (
        has_api_marker or has_structured_content or has_write_method
    ):
        return False

    if has_write_method:
        return True
    if has_api_marker or has_structured_content or has_api_pattern:
        return True
    if param_count >= 6 and first_part and first_part not in self.PASSIVE_STATIC_PATH_PARTS:
        return True
    return False

def _passive_entry_allowed(self, entry, filter_cfg):
    """Enforce passive host scope + API-likeness filtering."""
    host = self._ascii_safe(entry.get("host"), lower=True).strip()
    if not host:
        return False

    scope_override_enabled = bool(filter_cfg.get("scope_override_enabled"))
    scope_override = filter_cfg.get("scope_override", {})
    if scope_override_enabled:
        if not self._host_matches_target_scope(host, scope_override):
            return False
    elif filter_cfg.get("force_host"):
        if host != filter_cfg.get("selected_host"):
            return False
    else:
        if self._is_wayback_noise_host(host):
            return False
        allowed_bases = set(filter_cfg.get("allowed_bases", set()))
        if allowed_bases:
            host_base = self._infer_base_domain(host)
            if host_base not in allowed_bases:
                return False

    return self._passive_entry_is_api_like(entry)

def _run_passive_mode_handlers(self, mode, snapshot):
    """Run passive discovery handlers selected by UI mode."""
    findings = []
    handlers = [
        ("API5 (BFLA)", self._passive_discover_api5),
        ("API3 (Data)", self._passive_discover_api3),
        ("API4 (Resource)", self._passive_discover_api4),
        ("API6 (Flows)", self._passive_discover_api6),
        ("API9 (Version)", self._passive_discover_api9),
        ("API10 (Consumption)", self._passive_discover_api10),
    ]
    for mode_name, handler in handlers:
        if mode in ["All", mode_name]:
            findings.extend(handler(snapshot))
    return findings

def _sort_and_store_passive_findings(self, findings):
    """Sort and persist passive findings snapshot for export."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    ordered = sorted(
        findings,
        key=lambda x: (
            severity_order.get(
                self._ascii_safe(x.get("severity", "info"), lower=True), 4
            ),
            self._ascii_safe(x.get("category", ""), lower=True),
            self._ascii_safe(x.get("endpoint", ""), lower=True),
        ),
    )
    with self.passive_discovery_lock:
        self.passive_discovery_findings = list(ordered)
    return ordered

def _passive_discover_api5(self, snapshot):
    """Heuristic passive API5/BFLA detection from endpoint history."""
    findings = []
    success_codes = set([200, 201, 202, 204, 206])
    write_methods = set(["POST", "PUT", "PATCH", "DELETE"])

    for endpoint_key, entries in snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        if not entries_list:
            continue
        entry = self._get_entry(entries_list)
        path = self._ascii_safe(entry.get("normalized_path", "") or "", lower=True)
        method = self._ascii_safe(entry.get("method", "") or "").upper()
        id_like_path = bool(re.search(r"/{id}|/{uuid}|/{objectid}", path))
        sensitive_path = bool(self.PASSIVE_ADMIN_PATH_PATTERN.search(path)) or id_like_path
        if not sensitive_path and method not in write_methods:
            continue

        success_entries = [
            e
            for e in entries_list
            if int(e.get("response_status", 0) or 0) in success_codes
        ]
        if not success_entries:
            continue

        fp_to_sigs = {}
        for e in success_entries:
            fp = self._passive_auth_fingerprint(e)
            sig = self._passive_body_signature(e.get("response_body", ""))
            if fp not in fp_to_sigs:
                fp_to_sigs[fp] = set()
            fp_to_sigs[fp].add(sig)

        auth_fps = sorted(fp_to_sigs.keys())
        if sensitive_path and "none" in fp_to_sigs:
            findings.append(
                {
                    "category": "API5",
                    "severity": "high",
                    "endpoint": endpoint_key,
                    "issue": "Sensitive/admin-like endpoint returns success without explicit auth signal",
                    "evidence": "Success fingerprints: {}".format(", ".join(auth_fps)),
                }
            )

        if len(auth_fps) >= 2 and sensitive_path:
            shared_sig = None
            all_sigs = [fp_to_sigs.get(fp, set()) for fp in auth_fps]
            if all_sigs:
                intersection = set(all_sigs[0])
                for sigs in all_sigs[1:]:
                    intersection &= sigs
                if intersection:
                    shared_sig = list(intersection)[0]

            if shared_sig:
                findings.append(
                    {
                        "category": "API5",
                        "severity": "high",
                        "endpoint": endpoint_key,
                        "issue": "Multiple auth contexts received highly similar success responses",
                        "evidence": "Auth contexts: {} | Shared response signature: {}".format(
                            ", ".join(auth_fps), shared_sig[:90]
                        ),
                    }
                )
            elif method in write_methods:
                findings.append(
                    {
                        "category": "API5",
                        "severity": "medium",
                        "endpoint": endpoint_key,
                        "issue": "Write/admin-like endpoint succeeds across multiple auth contexts",
                        "evidence": "Auth contexts: {} | Samples: {}".format(
                            ", ".join(auth_fps), len(success_entries)
                        ),
                    }
                )

    return findings

def _passive_discover_api3(self, snapshot):
    """Passive API3 data exposure discovery via JSON field-set drift."""
    findings = []
    for endpoint_key, entries in snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        context_fields = self._passive_context_json_fields(entries_list)
        if len(context_fields) < 2:
            continue

        union_fields = set()
        field_sets = list(context_fields.values())
        common_fields = set(field_sets[0])
        for field_set in field_sets:
            union_fields |= set(field_set)
            common_fields &= set(field_set)

        variable_fields = sorted(list(union_fields - common_fields))
        if not variable_fields:
            continue

        min_fields = min([len(x) for x in field_sets])
        max_fields = max([len(x) for x in field_sets])
        sensitive_delta = [
            field for field in variable_fields if self._field_is_sensitive(field)
        ]
        contexts = sorted(list(context_fields.keys()))

        if sensitive_delta:
            findings.append(
                {
                    "category": "API3",
                    "severity": "high",
                    "endpoint": endpoint_key,
                    "issue": "Cross-context JSON field drift includes sensitive/PII-like attributes",
                    "evidence": "Contexts: {} | Field count range: {}-{} | Sensitive variable fields: {}".format(
                        ", ".join(contexts[:4]),
                        min_fields,
                        max_fields,
                        ", ".join(sensitive_delta[:8]),
                    ),
                }
            )
        elif (max_fields - min_fields) >= 5 and len(variable_fields) >= 4:
            findings.append(
                {
                    "category": "API3",
                    "severity": "medium",
                    "endpoint": endpoint_key,
                    "issue": "Large cross-context JSON field drift detected",
                    "evidence": "Contexts: {} | Field count range: {}-{} | Variable fields: {}".format(
                        ", ".join(contexts[:4]),
                        min_fields,
                        max_fields,
                        ", ".join(variable_fields[:8]),
                    ),
                }
            )

    return findings

def _entry_param_names_lower(self, entry):
    """Extract request parameter names in lowercase with bounded parsing."""
    names = set()
    params = entry.get("parameters", {}) or {}
    for param_type in ["url", "body", "json", "cookie"]:
        raw = params.get(param_type, [])
        if isinstance(raw, dict):
            iterable = raw.keys()
        elif isinstance(raw, list):
            iterable = raw
        else:
            iterable = []
        count = 0
        for name in iterable:
            if count >= 80:
                break
            count += 1
            if name is None:
                continue
            safe_name = self._ascii_safe(name, lower=True).strip()
            if safe_name:
                names.add(safe_name)

    query = (entry.get("query_string", "") or "")
    if query:
        for part in query.split("&")[:80]:
            if not part:
                continue
            name = self._ascii_safe(part.split("=", 1)[0], lower=True).strip()
            if name:
                names.add(name)
    return names

def _entry_header_names_lower(self, entry):
    """Extract request header names in lowercase with bounded parsing."""
    headers = entry.get("headers", {}) or {}
    out = set()
    count = 0
    for key in headers.keys():
        if count >= 40:
            break
        count += 1
        safe_key = self._ascii_safe(key, lower=True).strip()
        if safe_key:
            out.add(safe_key)
    return out

def _entry_limit_values(self, entry):
    """Extract numeric pagination limits from query string."""
    query = self._ascii_safe(entry.get("query_string", "") or "", lower=True)
    if not query:
        return []
    values = []
    for value_text in self.PASSIVE_LIMIT_QUERY_PATTERN.findall(query)[:8]:
        try:
            value = int(value_text)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            values.append(value)
    return values

def _passive_discover_api4(self, snapshot):
    """Passive API4 resource-consumption heuristics from captured history."""
    findings = []
    pagination_keys = set(["limit", "page", "page_size", "pagesize", "offset", "cursor", "per_page"])
    throttled_codes = set([429, 503])

    for endpoint_key, entries in snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        if not entries_list:
            continue
        entry = self._get_entry(entries_list)
        path = self._ascii_safe(entry.get("normalized_path", "") or "", lower=True)
        method = self._ascii_safe(entry.get("method", "") or "").upper()

        success_entries = []
        throttled_count = 0
        max_response_length = 0
        slow_success_count = 0
        max_limit = 0
        param_names = set()

        for sample in entries_list[:40]:
            status = int(sample.get("response_status", 0) or 0)
            if status in throttled_codes:
                throttled_count += 1
            if 200 <= status < 300:
                success_entries.append(sample)
                resp_len = int(sample.get("response_length", 0) or 0)
                if resp_len > max_response_length:
                    max_response_length = resp_len
                resp_time = int(sample.get("response_time_ms", 0) or 0)
                if resp_time >= 4000:
                    slow_success_count += 1
            param_names.update(self._entry_param_names_lower(sample))
            for limit_value in self._entry_limit_values(sample):
                if limit_value > max_limit:
                    max_limit = limit_value

        if not success_entries:
            continue

        resource_like = bool(self.PASSIVE_RESOURCE_PATH_PATTERN.search(path))
        has_pagination = any(name in pagination_keys for name in param_names)
        if not resource_like and not has_pagination and method not in ["GET", "POST"]:
            continue

        if max_limit >= 1000:
            findings.append(
                {
                    "category": "API4",
                    "severity": "high",
                    "endpoint": endpoint_key,
                    "issue": "Very large pagination/window value accepted",
                    "evidence": "Max observed limit/size value: {}".format(max_limit),
                }
            )

        if max_response_length >= 250000 and not has_pagination:
            findings.append(
                {
                    "category": "API4",
                    "severity": "high",
                    "endpoint": endpoint_key,
                    "issue": "Large successful response without pagination controls",
                    "evidence": "Largest 2xx response length: {} bytes".format(max_response_length),
                }
            )
        elif max_response_length >= 120000 and not has_pagination:
            findings.append(
                {
                    "category": "API4",
                    "severity": "medium",
                    "endpoint": endpoint_key,
                    "issue": "Potential unbounded response size",
                    "evidence": "Largest 2xx response length: {} bytes".format(max_response_length),
                }
            )

        if len(success_entries) >= 12 and throttled_count == 0:
            findings.append(
                {
                    "category": "API4",
                    "severity": "medium",
                    "endpoint": endpoint_key,
                    "issue": "High success volume observed without throttling signals",
                    "evidence": "2xx samples: {} | 429/503 samples: {}".format(
                        len(success_entries), throttled_count
                    ),
                }
            )

        if slow_success_count >= 3 and max_response_length >= 120000 and throttled_count == 0:
            findings.append(
                {
                    "category": "API4",
                    "severity": "medium",
                    "endpoint": endpoint_key,
                    "issue": "Slow heavy responses may enable resource exhaustion",
                    "evidence": "Slow 2xx samples (>=4s): {} | Max length: {}".format(
                        slow_success_count, max_response_length
                    ),
                }
            )

    return findings

def _passive_discover_api6(self, snapshot):
    """Passive API6 business-flow authorization heuristics."""
    findings = []
    write_methods = set(["POST", "PUT", "PATCH", "DELETE"])

    for endpoint_key, entries in snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        if not entries_list:
            continue
        entry = self._get_entry(entries_list)
        path = self._ascii_safe(entry.get("normalized_path", "") or "", lower=True)
        method = self._ascii_safe(entry.get("method", "") or "").upper()

        flow_like = bool(self.PASSIVE_FLOW_PATH_PATTERN.search(path))
        if not flow_like and method in write_methods:
            flow_like = any(
                marker in path
                for marker in ["/admin", "/role", "/permission", "/billing", "/transfer", "/withdraw", "/approve"]
            )
        if not flow_like:
            continue

        fp_to_sigs = {}
        fp_to_success_count = {}
        for sample in entries_list[:40]:
            status = int(sample.get("response_status", 0) or 0)
            if status < 200 or status >= 300:
                continue
            fp = self._passive_auth_fingerprint(sample)
            sig = self._passive_body_signature(sample.get("response_body", ""))
            if fp not in fp_to_sigs:
                fp_to_sigs[fp] = set()
                fp_to_success_count[fp] = 0
            fp_to_sigs[fp].add(sig)
            fp_to_success_count[fp] += 1

        if not fp_to_sigs:
            continue

        auth_contexts = sorted(fp_to_sigs.keys())
        if "none" in fp_to_sigs:
            findings.append(
                {
                    "category": "API6",
                    "severity": "critical" if method in write_methods else "high",
                    "endpoint": endpoint_key,
                    "issue": "Sensitive business flow succeeded without explicit auth signal",
                    "evidence": "Auth contexts: {} | unauth success samples: {}".format(
                        ", ".join(auth_contexts),
                        fp_to_success_count.get("none", 0),
                    ),
                }
            )

        if len(auth_contexts) >= 2:
            all_sigs = [fp_to_sigs.get(fp, set()) for fp in auth_contexts]
            shared_sig = None
            if all_sigs:
                intersection = set(all_sigs[0])
                for sigs in all_sigs[1:]:
                    intersection &= sigs
                if intersection:
                    shared_sig = list(intersection)[0]

            if shared_sig:
                findings.append(
                    {
                        "category": "API6",
                        "severity": "high",
                        "endpoint": endpoint_key,
                        "issue": "Business-flow responses look identical across auth contexts",
                        "evidence": "Contexts: {} | Shared signature: {}".format(
                            ", ".join(auth_contexts), shared_sig[:90]
                        ),
                    }
                )
            elif method in write_methods:
                findings.append(
                    {
                        "category": "API6",
                        "severity": "medium",
                        "endpoint": endpoint_key,
                        "issue": "Write business-flow endpoint succeeded for multiple auth contexts",
                        "evidence": "Contexts: {} | Success samples: {}".format(
                            ", ".join(auth_contexts),
                            sum(fp_to_success_count.values()),
                        ),
                    }
                )

    return findings

def _passive_discover_api10(self, snapshot):
    """Passive API10 heuristics for unsafe upstream API consumption."""
    findings = []
    webhook_write_methods = set(["POST", "PUT", "PATCH"])

    for endpoint_key, entries in snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        if not entries_list:
            continue
        entry = self._get_entry(entries_list)
        path = self._ascii_safe(entry.get("normalized_path", "") or "", lower=True)
        method = self._ascii_safe(entry.get("method", "") or "").upper()

        success_entries = []
        param_names = set()
        header_names = set()
        upstream_hints = set()

        for sample in entries_list[:40]:
            status = int(sample.get("response_status", 0) or 0)
            if 200 <= status < 300:
                success_entries.append(sample)
            param_names.update(self._entry_param_names_lower(sample))
            header_names.update(self._entry_header_names_lower(sample))
            body = self._ascii_safe(sample.get("response_body", "") or "", lower=True)
            for hint in self.PASSIVE_UPSTREAM_ERROR_HINTS:
                if hint in body:
                    upstream_hints.add(hint)
                    if len(upstream_hints) >= 4:
                        break

        if not success_entries and not upstream_hints:
            continue

        has_external_param = any(
            any(keyword in name for keyword in self.PASSIVE_CALLBACK_PARAM_KEYWORDS)
            for name in param_names
        )
        webhook_like = bool(self.PASSIVE_WEBHOOK_PATH_PATTERN.search(path))
        has_signature = any(
            any(hint in header_name for hint in self.PASSIVE_SIGNATURE_HEADER_HINTS)
            for header_name in header_names
        )

        if has_external_param and success_entries:
            findings.append(
                {
                    "category": "API10",
                    "severity": "high" if webhook_like else "medium",
                    "endpoint": endpoint_key,
                    "issue": "Endpoint accepts external callback/URL-style input",
                    "evidence": "Param hints: {} | 2xx samples: {}".format(
                        ", ".join(sorted(list(param_names))[:8]),
                        len(success_entries),
                    ),
                }
            )

        if webhook_like and method in webhook_write_methods and success_entries and not has_signature:
            findings.append(
                {
                    "category": "API10",
                    "severity": "high",
                    "endpoint": endpoint_key,
                    "issue": "Webhook/callback endpoint observed without signature header signal",
                    "evidence": "Observed headers: {}".format(
                        ", ".join(sorted(list(header_names))[:8]) or "<none>"
                    ),
                }
            )

        if upstream_hints:
            findings.append(
                {
                    "category": "API10",
                    "severity": "medium",
                    "endpoint": endpoint_key,
                    "issue": "Responses leak upstream dependency/network failure details",
                    "evidence": "Detected upstream error hints: {}".format(
                        ", ".join(sorted(list(upstream_hints))[:6])
                    ),
                }
            )

    return findings

def _passive_context_json_fields(self, entries_list):
    """Build auth-context -> union JSON fields from successful responses."""
    context_fields = {}
    for entry in entries_list:
        status = int(entry.get("response_status", 0) or 0)
        if status < 200 or status >= 300:
            continue
        parsed = self._parse_json_loose(entry.get("response_body", ""))
        if parsed is None:
            continue
        paths = set()
        self._flatten_json_paths(parsed, "", paths, 0)
        if not paths:
            continue
        context = self._passive_auth_fingerprint(entry)
        if context not in context_fields:
            context_fields[context] = set()
        context_fields[context].update(paths)
    return context_fields

def _passive_discover_api9(self, snapshot):
    """Passive API9 shadow/version drift detection."""
    findings = []
    groups = {}

    for endpoint_key, entries in snapshot.items():
        entries_list = entries if isinstance(entries, list) else [entries]
        if not entries_list:
            continue
        entry = self._get_entry(entries_list)
        method = self._ascii_safe(entry.get("method", "") or "").upper()
        path = self._ascii_safe(entry.get("normalized_path", "") or "")
        version_token = self._extract_version_segment(path)
        if not version_token:
            continue
        version_value = self._parse_version_value(version_token)
        if version_value is None:
            continue
        versionless = self._strip_version_segment(path, version_token)
        group_key = "{}:{}".format(method, versionless)
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(
            {
                "endpoint": endpoint_key,
                "version_token": version_token,
                "version_value": version_value,
                "entries": entries_list,
            }
        )

    for group_key, versions in groups.items():
        if len(versions) < 2:
            continue

        versions.sort(key=lambda x: x["version_value"])
        for version_data in versions:
            entries_data = version_data.get("entries", [])
            version_data["has_success"] = self._has_success_response(entries_data)
            version_data["fields"] = self._passive_union_json_fields(entries_data)
        latest = versions[-1]
        latest_fields = latest.get("fields", set())
        latest_success = bool(latest.get("has_success"))

        for older in versions[:-1]:
            older_success = bool(older.get("has_success"))
            if not (latest_success and older_success):
                continue

            findings.append(
                {
                    "category": "API9",
                    "severity": "medium",
                    "endpoint": older.get("endpoint", group_key),
                    "issue": "Legacy API version remains active alongside newer version",
                    "evidence": "Legacy: {} | Latest: {} | Group: {}".format(
                        older.get("version_token", ""),
                        latest.get("version_token", ""),
                        group_key,
                    ),
                }
            )

            older_fields = older.get("fields", set())
            if not older_fields or not latest_fields:
                continue

            legacy_only = sorted(list(older_fields - latest_fields))
            if not legacy_only:
                continue
            sensitive_legacy = [
                field for field in legacy_only if self._field_is_sensitive(field)
            ]
            if sensitive_legacy:
                findings.append(
                    {
                        "category": "API9",
                        "severity": "high",
                        "endpoint": older.get("endpoint", group_key),
                        "issue": "Legacy version exposes sensitive fields absent in newer version",
                        "evidence": "Legacy-only sensitive fields: {}".format(
                            ", ".join(sensitive_legacy[:8])
                        ),
                    }
                )
            elif len(legacy_only) >= 4:
                findings.append(
                    {
                        "category": "API9",
                        "severity": "medium",
                        "endpoint": older.get("endpoint", group_key),
                        "issue": "Versioned response schema drift detected",
                        "evidence": "Legacy-only fields: {}".format(
                            ", ".join(legacy_only[:8])
                        ),
                    }
                )

    return findings

def _passive_union_json_fields(self, entries):
    fields = set()
    entries_list = entries if isinstance(entries, list) else [entries]
    for entry in entries_list:
        status = int(entry.get("response_status", 0) or 0)
        if status < 200 or status >= 300:
            continue
        parsed = self._parse_json_loose(entry.get("response_body", ""))
        if parsed is None:
            continue
        self._flatten_json_paths(parsed, "", fields, 0)
    return fields

def _has_success_response(self, entries):
    entries_list = entries if isinstance(entries, list) else [entries]
    for entry in entries_list:
        status = int(entry.get("response_status", 0) or 0)
        if 200 <= status < 300:
            return True
    return False

def _passive_auth_fingerprint(self, entry):
    headers = entry.get("headers", {}) or {}
    normalized = {}
    for key, value in headers.items():
        normalized[self._ascii_safe(key, lower=True)] = self._ascii_safe(value)

    authz = normalized.get("authorization", "").strip()
    if authz:
        lowered = authz.lower()
        if lowered.startswith("bearer "):
            token = authz.split(" ", 1)[1].strip()
            jwt_identity = self._passive_jwt_identity(token)
            if jwt_identity:
                return jwt_identity
            return "bearer:" + token[:16]
        return "authorization:" + authz[:20]

    api_key = normalized.get("x-api-key", "").strip()
    if api_key:
        return "x-api-key:" + api_key[:12]

    cookie = normalized.get("cookie", "").strip()
    if cookie:
        names = []
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                names.append(self._ascii_safe(part.split("=", 1)[0], lower=True).strip())
        names = sorted(list(set(names)))
        return "cookie:" + ",".join(names[:4])

    auth_types = [
        self._ascii_safe(x, lower=True)
        for x in (entry.get("auth_detected", []) or [])
    ]
    if any(x != "none" for x in auth_types):
        return "auth:" + "|".join(sorted(list(set(auth_types))))
    return "none"

def _passive_jwt_identity(self, token):
    """Derive stable identity fingerprint from JWT claims when possible."""
    import base64
    import binascii

    try:
        text_types = (basestring,)
    except NameError:
        text_types = (str,)

    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return None
    payload_part = parts[1]
    if not payload_part:
        return None

    padding = "=" * (-len(payload_part) % 4)
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_part + padding)
        payload_obj = json.loads(payload_bytes)
    except (TypeError, ValueError, binascii.Error):
        return None

    role = payload_obj.get("role")
    roles = payload_obj.get("roles")
    is_admin = payload_obj.get("is_admin")
    subject = payload_obj.get("sub")
    user_id = payload_obj.get("user_id")
    tenant = payload_obj.get("tenant")

    if isinstance(role, text_types + (int, float)):
        return "jwt-role:{}".format(self._ascii_safe(role, lower=True, max_len=24))
    if isinstance(roles, list) and roles:
        role_text = ",".join([self._ascii_safe(x, lower=True) for x in roles[:4]])
        return "jwt-roles:{}".format(role_text[:32])
    if isinstance(is_admin, bool):
        return "jwt-admin:{}".format("true" if is_admin else "false")
    if isinstance(subject, text_types + (int, float)):
        return "jwt-sub:{}".format(self._ascii_safe(subject, lower=True, max_len=24))
    if isinstance(user_id, text_types + (int, float)):
        return "jwt-user:{}".format(self._ascii_safe(user_id, lower=True, max_len=24))
    if isinstance(tenant, text_types + (int, float)):
        return "jwt-tenant:{}".format(self._ascii_safe(tenant, lower=True, max_len=24))
    return None

def _passive_body_signature(self, body_text):
    body = self._ascii_safe(body_text or "", lower=True)
    body = re.sub(r"\s+", " ", body).strip()
    body = re.sub(r"[0-9a-f]{24,}", "{token}", body)
    body = re.sub(r"\d+", "0", body)
    if not body:
        return "empty"
    return "{}:{}".format(len(body), body[:120])

def _parse_json_loose(self, body_text):
    text = (body_text or "").strip()
    if not text:
        return None
    if text.startswith(")]}',"):
        parts = text.split("\n", 1)
        if len(parts) == 2:
            text = parts[1].strip()
        else:
            return None
    if not text or text[0] not in ["{", "["]:
        return None
    text = text.rstrip(" ;")
    try:
        return json.loads(text)
    except ValueError:
        return None

def _flatten_json_paths(self, value, prefix, out, depth):
    if depth > 6:
        return
    if isinstance(value, dict):
        count = 0
        for key in sorted(value.keys()):
            if count >= 80:
                break
            count += 1
            key_str = self._ascii_safe(key)
            path = key_str if not prefix else "{}.{}".format(prefix, key_str)
            out.add(path)
            self._flatten_json_paths(value.get(key), path, out, depth + 1)
        return
    if isinstance(value, list):
        path = "[]" if not prefix else "{}[]".format(prefix)
        out.add(path)
        for item in value[:5]:
            self._flatten_json_paths(item, path, out, depth + 1)
        return
    if prefix:
        out.add(prefix)
    else:
        out.add("<root>")

def _field_is_sensitive(self, field_path):
    lower = self._ascii_safe(field_path, lower=True)
    return any(word in lower for word in self.PASSIVE_SENSITIVE_FIELD_KEYWORDS)

def _extract_version_segment(self, path):
    match = self.PASSIVE_VERSION_SEGMENT_PATTERN.search((path or "").lower())
    if match:
        return match.group(1)
    return None

def _strip_version_segment(self, path, version_token):
    stripped = re.sub(
        r"/" + re.escape(version_token) + r"(?=/|$)",
        "",
        path or "",
        count=1,
    )
    return stripped if stripped else "/"

def _parse_version_value(self, version_token):
    token = (version_token or "").lower().lstrip("v")
    if not token:
        return None
    parts = token.split(".", 1)
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except (TypeError, ValueError):
        return None

def _format_passive_discovery_output(
    self, findings, scanned_count, total_available, mode
):
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    category_counts = {
        "API3": 0,
        "API4": 0,
        "API5": 0,
        "API6": 0,
        "API9": 0,
        "API10": 0,
    }
    for finding in findings:
        sev = self._ascii_safe(finding.get("severity", "info"), lower=True)
        cat = self._ascii_safe(finding.get("category", ""))
        if sev in severity_counts:
            severity_counts[sev] += 1
        if cat in category_counts:
            category_counts[cat] += 1

    lines = []
    lines.append("=" * 80)
    lines.append("PASSIVE DISCOVERY RESULTS")
    lines.append("=" * 80)
    lines.append("[*] Mode: {}".format(self._ascii_safe(mode)))
    lines.append("[*] Endpoints Scanned: {} (of {})".format(scanned_count, total_available))
    lines.append("[*] Findings: {}".format(len(findings)))
    lines.append(
        "[*] Severity: Critical={} High={} Medium={} Info={}".format(
            severity_counts["critical"],
            severity_counts["high"],
            severity_counts["medium"],
            severity_counts["info"],
        )
    )
    lines.append(
        "[*] Categories: API3={} API4={} API5={} API6={} API9={} API10={}".format(
            category_counts["API3"],
            category_counts["API4"],
            category_counts["API5"],
            category_counts["API6"],
            category_counts["API9"],
            category_counts["API10"],
        )
    )
    lines.append("")

    if not findings:
        lines.append("[+] No passive gap signals detected in current history")
        lines.append("[*] Capture more role/version traffic and rerun")
        return "\n".join(lines) + "\n"

    lines.append("TOP FINDINGS")
    lines.append("-" * 80)
    for finding in findings[:120]:
        severity = self._ascii_safe(
            finding.get("severity", "info"), lower=True
        ).upper()
        category = self._ascii_safe(finding.get("category", "GEN"))
        issue = self._ascii_safe(finding.get("issue", ""))
        endpoint = self._ascii_safe(finding.get("endpoint", ""))
        evidence = self._ascii_safe(finding.get("evidence", ""))
        lines.append(
            "[{}][{}] {}".format(
                severity,
                category,
                issue,
            )
        )
        lines.append("  Endpoint: {}".format(endpoint))
        lines.append("  Evidence: {}".format(evidence))
        lines.append("")
    if len(findings) > 120:
        lines.append("[*] {} more findings not shown".format(len(findings) - 120))

    return "\n".join(lines) + "\n"

def _export_passive_discovery_results(self):
    """Export passive findings to JSON."""
    with self.passive_discovery_lock:
        findings = list(self.passive_discovery_findings or [])
    if not findings:
        self.passive_area.append("\n[!] No passive findings to export\n")
        return

    import os

    export_dir = self._get_export_dir("PassiveDiscovery_Export")
    if not export_dir:
        return
    filepath = os.path.join(export_dir, "passive_discovery_findings.json")
    writer = None
    try:
        payload = {
            "metadata": {
                "timestamp": SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date()),
                "finding_count": len(findings),
                "source": "proxy_history_passive",
            },
            "findings": findings,
        }
        writer = FileWriter(filepath)
        writer.write(json.dumps(payload, indent=2))
        self.passive_area.append(
            "\n[+] Exported {} passive findings\n[+] Folder: {}\n[+] File: {}\n".format(
                len(findings), export_dir, filepath
            )
        )
        self.log_to_ui("[+] Exported passive discovery findings to: {}".format(export_dir))
    except Exception as e:
        self.passive_area.append("\n[!] Passive export failed: {}\n".format(str(e)))
        self.log_to_ui("[!] Passive export failed: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as close_err:
                self._callbacks.printError(
                    "Error closing passive discovery export file: {}".format(
                        str(close_err)
                    )
                )

def _export_sequence_invariant_ledger(self):
    """Export sequence-invariant findings and confidence ledger to JSON."""
    with self.sequence_invariant_lock:
        findings = list(self.sequence_invariant_findings or [])
        ledger = dict(self.sequence_invariant_ledger or {})
        meta = dict(self.sequence_invariant_meta or {})
    with self.golden_ticket_lock:
        golden_findings = list(self.golden_ticket_findings or [])
        golden_ledger = dict(self.golden_ticket_ledger or {})
        golden_meta = dict(self.golden_ticket_meta or {})
    with self.state_transition_lock:
        state_findings = list(self.state_transition_findings or [])
        state_ledger = dict(self.state_transition_ledger or {})
        state_meta = dict(self.state_transition_meta or {})
    with self.advanced_logic_lock:
        advanced_packages = dict(self.advanced_logic_packages or {})
    abuse_package = dict(advanced_packages.get("abuse_chains", {}) or {})
    proof_package = dict(advanced_packages.get("proof_mode", {}) or {})
    spec_package = dict(advanced_packages.get("spec_guardrails", {}) or {})
    role_package = dict(advanced_packages.get("role_delta", {}) or {})

    if (
        (not findings)
        and (not golden_findings)
        and (not state_findings)
        and (not abuse_package.get("findings"))
        and (not proof_package.get("packet_sets"))
        and (not spec_package.get("violations"))
        and (not role_package.get("findings"))
    ):
        self.passive_area.append(
            "\n[!] No invariant findings to export. Run 'Run Invariants' first.\n"
        )
        return

    import os

    export_dir = self._get_export_dir("SequenceInvariant_Export")
    if not export_dir:
        return

    files_to_write = []
    if findings:
        files_to_write.extend(
            [
                ("sequence_invariant_findings.json", {"metadata": meta, "findings": findings}),
                ("sequence_evidence_ledger.json", {"metadata": meta, "ledger": ledger}),
            ]
        )
    if golden_findings:
        files_to_write.extend(
            [
                ("golden_ticket_findings.json", {"metadata": golden_meta, "findings": golden_findings}),
                ("golden_ticket_ledger.json", {"metadata": golden_meta, "ledger": golden_ledger}),
            ]
        )
    if state_findings:
        files_to_write.extend(
            [
                ("state_transition_findings.json", {"metadata": state_meta, "findings": state_findings}),
                ("state_transition_ledger.json", {"metadata": state_meta, "ledger": state_ledger}),
            ]
        )
    abuse_findings = list(abuse_package.get("findings", []) or [])
    if abuse_findings:
        files_to_write.extend(
            [
                (
                    "abuse_chain_findings.json",
                    {
                        "metadata": {
                            "generated_at": abuse_package.get("generated_at"),
                            "source": advanced_packages.get("source"),
                            "scope": advanced_packages.get("scope"),
                            "target_count": advanced_packages.get("target_count"),
                        },
                        "findings": abuse_findings,
                    },
                ),
                (
                    "abuse_chain_ledger.json",
                    {
                        "metadata": {
                            "generated_at": abuse_package.get("generated_at"),
                            "source": advanced_packages.get("source"),
                            "scope": advanced_packages.get("scope"),
                            "target_count": advanced_packages.get("target_count"),
                        },
                        "ledger": dict(abuse_package.get("ledger", {}) or {}),
                    },
                ),
            ]
        )
    proof_sets = list(proof_package.get("packet_sets", []) or [])
    if proof_sets:
        files_to_write.append(
            (
                "proof_mode_packet_sets.json",
                {
                    "metadata": {
                        "generated_at": proof_package.get("generated_at"),
                        "source": advanced_packages.get("source"),
                        "scope": advanced_packages.get("scope"),
                        "target_count": advanced_packages.get("target_count"),
                        "source_finding_count": proof_package.get("source_finding_count", 0),
                    },
                    "packet_sets": proof_sets,
                },
            )
        )
    spec_rules = list(spec_package.get("rules", []) or [])
    spec_violations = list(spec_package.get("violations", []) or [])
    if spec_rules:
        files_to_write.append(
            (
                "spec_guardrails_rules.json",
                {
                    "metadata": {
                        "generated_at": spec_package.get("generated_at"),
                        "source": advanced_packages.get("source"),
                        "scope": advanced_packages.get("scope"),
                        "target_count": advanced_packages.get("target_count"),
                    },
                    "rules": spec_rules,
                },
            )
        )
    if spec_violations:
        files_to_write.append(
            (
                "spec_guardrails_violations.json",
                {
                    "metadata": {
                        "generated_at": spec_package.get("generated_at"),
                        "source": advanced_packages.get("source"),
                        "scope": advanced_packages.get("scope"),
                        "target_count": advanced_packages.get("target_count"),
                    },
                    "violations": spec_violations,
                    "ledger": dict(spec_package.get("ledger", {}) or {}),
                },
            )
        )
    role_findings = list(role_package.get("findings", []) or [])
    if role_findings:
        files_to_write.extend(
            [
                (
                    "role_delta_findings.json",
                    {
                        "metadata": {
                            "generated_at": role_package.get("generated_at"),
                            "source": advanced_packages.get("source"),
                            "scope": advanced_packages.get("scope"),
                            "target_count": advanced_packages.get("target_count"),
                        },
                        "findings": role_findings,
                    },
                ),
                (
                    "role_delta_ledger.json",
                    {
                        "metadata": {
                            "generated_at": role_package.get("generated_at"),
                            "source": advanced_packages.get("source"),
                            "scope": advanced_packages.get("scope"),
                            "target_count": advanced_packages.get("target_count"),
                        },
                        "ledger": dict(role_package.get("ledger", {}) or {}),
                    },
                ),
            ]
        )
    written = []

    for filename, payload in files_to_write:
        writer = None
        filepath = os.path.join(export_dir, filename)
        try:
            writer = FileWriter(filepath)
            writer.write(json.dumps(payload, indent=2))
            written.append(filepath)
        except Exception as e:
            self.passive_area.append(
                "\n[!] Sequence invariant export failed ({}): {}\n".format(
                    filename, self._ascii_safe(e)
                )
            )
            self.log_to_ui(
                "[!] Sequence invariant export failed ({}): {}".format(
                    filename, self._ascii_safe(e)
                )
            )
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as close_err:
                    self._callbacks.printError(
                        "Error closing sequence export file {}: {}".format(
                            filename, self._ascii_safe(close_err)
                        )
                    )

    if not written:
        return

    self.passive_area.append("\n[+] Exported invariant artifacts: {}\n".format(len(written)))
    self.passive_area.append("[+] Folder: {}\n".format(export_dir))
    for path in written:
        self.passive_area.append("[+] File: {}\n".format(path))
    self.log_to_ui("[+] Exported invariant ledgers to: {}".format(export_dir))

def _normalize_wayback_entry(self, line):
    """Normalize wayback line into: original | archive | timestamp."""
    cleaned = self._clean_url(line)
    if not cleaned:
        return None

    parts = [p.strip() for p in cleaned.split(" | ")]
    if len(parts) >= 3:
        return "{} | {} | {}".format(parts[0], parts[1], parts[2])

    return "{} | {} | custom".format(cleaned, cleaned)

def _run_httpx(self, event):
    """Run HTTPX on discovered URLs from Recon tab"""
    return heavy_runners._run_httpx(self, event)

def _export_list_to_file(self, data_list, export_type, output_area, list_name):
    """Helper to export list to file - only called on explicit export"""
    import os

    if not data_list:
        output_area.append("\n[!] No {} to export\n".format(list_name))
        return
    export_dir = self._get_export_dir(export_type)
    if not export_dir:
        return
    filepath = os.path.join(export_dir, "results.txt")
    writer = None
    try:
        writer = FileWriter(filepath)
        for item in data_list:
            writer.write(item + "\n")
        output_area.append(
            "\n[+] Exported {} {}\n[+] Folder: {}\n[+] File: {}\n".format(
                len(data_list), list_name, export_dir, filepath
            )
        )
        self.log_to_ui("[+] Exported {} to: {}".format(list_name, export_dir))
    except Exception as e:
        output_area.append("\n[!] Export failed: {}\n".format(str(e)))
        self.log_to_ui("[!] Export error: {}".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing file {}: {}".format(filepath, str(e))
                )

def _parse_positive_int(self, text, default_value, min_value, max_value):
    """Parse bounded positive integer from UI text fields."""
    try:
        value = int((text or "").strip())
    except (TypeError, ValueError):
        value = int(default_value)
    if value < min_value:
        value = min_value
    if value > max_value:
        value = max_value
    return value

def _collect_verify_targets(self, attack_types, max_targets):
    """Collect verification targets from fuzzer attacks, fallback to API-like endpoints."""
    targets = []
    seen_urls = set()
    wanted = set([self._ascii_safe(x, lower=True) for x in (attack_types or [])])
    with self.lock:
        data_snapshot = dict(self.api_data)
    attacks_snapshot = list(getattr(self, "fuzzing_attacks", []) or [])

    for endpoint_key, attack in attacks_snapshot:
        attack_type = self._ascii_safe((attack or {}).get("type"), lower=True)
        if wanted and attack_type not in wanted:
            continue
        entries = data_snapshot.get(endpoint_key)
        if not entries:
            continue
        entry = self._get_entry(entries)
        url, _, _, _, _ = self._build_entry_url(entry)
        if not url or url in seen_urls:
            continue
        params = []
        for param_name in (attack.get("params", []) or []):
            safe_param = self._ascii_safe(param_name).strip()
            if safe_param:
                params.append(safe_param)
        body_data = self._ascii_safe(entry.get("request_body") or "")
        candidate = {
            "endpoint_key": endpoint_key,
            "url": url,
            "method": self._ascii_safe(entry.get("method") or "GET").upper(),
            "params": params,
            "data": body_data,
        }
        targets.append(candidate)
        seen_urls.add(url)
        if len(targets) >= max_targets:
            return targets

    # Fallback: no fuzzing context yet, pick likely API endpoints.
    api_endpoints, _ = self._collect_fuzzer_targets()
    for endpoint_key, entries in sorted(api_endpoints.items(), key=lambda item: item[0]):
        entry = self._get_entry(entries)
        url, _, _, _, _ = self._build_entry_url(entry)
        if not url or url in seen_urls:
            continue
        method = self._ascii_safe(entry.get("method") or "GET").upper()
        if method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            continue
        params_block = entry.get("parameters", {}) or {}
        param_names = []
        for ptype in ["url", "body", "json"]:
            values = params_block.get(ptype, {})
            if isinstance(values, dict):
                param_names.extend([self._ascii_safe(k) for k in values.keys()])
            elif isinstance(values, list):
                param_names.extend([self._ascii_safe(v) for v in values])
        if method == "GET" and not param_names:
            continue
        candidate = {
            "endpoint_key": endpoint_key,
            "url": url,
            "method": method,
            "params": [p for p in param_names if p][:8],
            "data": self._ascii_safe(entry.get("request_body") or ""),
        }
        targets.append(candidate)
        seen_urls.add(url)
        if len(targets) >= max_targets:
            break
    return targets

def _extract_sqlmap_evidence(self, output_text):
    """Extract SQLMap positive evidence line from command output."""
    safe = self._ascii_safe(output_text or "", lower=True)
    for line in safe.splitlines():
        compact = line.strip()
        if not compact:
            continue
        if (
            "is vulnerable" in compact
            or "injectable" in compact
            or "sql injection vulnerability" in compact
        ):
            return self._ascii_safe(line).strip()
    return ""

def _extract_dalfox_evidence(self, output_text):
    """Extract Dalfox positive evidence line from output."""
    safe = self._ascii_safe(output_text or "", lower=True)
    for line in safe.splitlines():
        compact = line.strip()
        if not compact:
            continue
        if (
            "verified" in compact
            or "poc" in compact
            or "xss" in compact and "found" in compact
        ):
            return self._ascii_safe(line).strip()
    return ""

def _import_endpoint_candidates_to_recon(self, candidates, source_tag, output_area):
    """Import URL/method candidates to Recon tab and tag them by source."""
    if not candidates:
        output_area.append("\n[!] No candidates available to send\n")
        return

    imported = 0
    skipped = 0
    for candidate in candidates:
        try:
            method = self._ascii_safe(candidate.get("method") or "GET").upper()
            url = self._ascii_safe(candidate.get("url") or "").strip()
            if not url:
                skipped += 1
                continue
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
            parsed = URL(url)
            path = parsed.getPath() or "/"
            normalized = self._normalize_path(path)
            key = "{}:{}".format(method, normalized)

            with self.lock:
                if key in self.api_data:
                    skipped += 1
                    continue
                protocol = parsed.getProtocol() or "https"
                port = parsed.getPort()
                if port == -1:
                    port = 443 if protocol == "https" else 80
                entry = {
                    "method": method,
                    "path": path,
                    "normalized_path": normalized,
                    "host": parsed.getHost(),
                    "protocol": protocol,
                    "port": port,
                    "query_string": parsed.getQuery() or "",
                    "parameters": {"url": {}, "body": {}, "cookie": {}, "json": {}},
                    "headers": {},
                    "request_body": "",
                    "response_status": 200,
                    "response_headers": {},
                    "response_body": "",
                    "response_length": 0,
                    "response_time_ms": 0,
                    "source_tool": self._ascii_safe(source_tag),
                    "content_type": "unknown",
                    "auth_detected": ["None"],
                    "api_patterns": [self._ascii_safe(source_tag)],
                    "jwt_detected": None,
                    "encryption_indicators": {"likely_encrypted": False, "types": []},
                    "param_patterns": {"reflected": [], "param_types": {}},
                }
                self.api_data[key] = [entry]
                tags = set(self._auto_tag(entry))
                tags.add(self._ascii_safe(source_tag, lower=True))
                self.endpoint_tags[key] = sorted(tags)
                self.endpoint_times[key] = [0]
                imported += 1
        except Exception as e:
            skipped += 1
            self._callbacks.printError(
                "Import candidate failed ({}): {}".format(source_tag, str(e))
            )

    output_area.append(
        "\n[+] Imported {} new endpoints from {}\n".format(
            imported, self._ascii_safe(source_tag)
        )
    )
    output_area.append("[*] Skipped: {}\n".format(skipped))
    self.log_to_ui(
        "[+] Imported {} endpoints from {}".format(
            imported, self._ascii_safe(source_tag)
        )
    )
    SwingUtilities.invokeLater(
        lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
    )
    SwingUtilities.invokeLater(lambda: self._update_host_filter())
    SwingUtilities.invokeLater(lambda: self._update_stats())
    SwingUtilities.invokeLater(lambda: self.refresh_view())

def _run_sqlmap_verify(self, event):
    """Run SQLMap verification over SQLi candidates."""
    import os
    import subprocess
    import tempfile
    import time as time_module

    sqlmap_path = self.sqlmap_path_field.getText().strip()
    if not sqlmap_path:
        self.sqlmap_area.setText("[!] Configure SQLMap path first\n")
        return
    if not self.api_data:
        self.sqlmap_area.setText("[!] No endpoints captured. Capture/import first.\n")
        return
    if not self._validate_binary_signature(
        "SQLMap",
        sqlmap_path,
        self.sqlmap_area,
        required_tokens=["-u", "--batch", "--level"],
        forbidden_tokens=[],
        fix_hint="Set SQLMap path to your local sqlmap binary (for example: ~/.local/bin/sqlmap).",
    ):
        return

    max_targets = self._parse_positive_int(
        self.sqlmap_max_targets_field.getText(), 12, 1, 100
    )
    per_target_timeout = self._parse_positive_int(
        self.sqlmap_target_timeout_field.getText(), 45, 10, 300
    )
    profile_value = self._selected_profile_value(
        getattr(self, "sqlmap_profile_combo", None)
    )
    targets = self._collect_verify_targets(["sql injection"], max_targets)
    if not targets:
        self.sqlmap_area.setText(
            "[!] No SQLi verification targets.\n[*] Generate fuzzing attacks first.\n"
        )
        return

    self.sqlmap_area.setText("[*] SQLMap verification starting...\n")
    self.sqlmap_area.append("[*] Targets: {}\n".format(len(targets)))
    self.sqlmap_area.append("[*] Profile: {}\n".format(profile_value))
    self.sqlmap_area.append("[*] Timeout per target: {}s\n\n".format(per_target_timeout))
    self._clear_tool_cancel("sqlmap")

    def run_verify():
        findings = []
        verified_candidates = []
        checked = 0
        cancelled = False

        for idx, target in enumerate(targets):
            if self._is_tool_cancelled("sqlmap"):
                cancelled = True
                break

            checked += 1
            url = target["url"]
            endpoint_key = target["endpoint_key"]
            method = target.get("method", "GET")
            cmd = []
            profile_cfg = {"profile": profile_value}
            try:
                cmd, profile_cfg = self._build_sqlmap_command(
                    sqlmap_path, target, profile_value
                )
            except Exception as build_err:
                self._callbacks.printError(
                    "SQLMap profile builder fallback: {}".format(str(build_err))
                )
                cmd = [
                    sqlmap_path,
                    "-u",
                    url,
                    "--batch",
                    "--level",
                    "2",
                    "--risk",
                    "1",
                    "--threads",
                    "1",
                    "--timeout",
                    "8",
                    "--retries",
                    "1",
                    "--flush-session",
                ]
                if target.get("params"):
                    cmd.extend(["-p", ",".join(target.get("params", [])[:6])])
                data = target.get("data", "")
                if method in ["POST", "PUT", "PATCH", "DELETE"] and data:
                    cmd.extend(["--method", method, "--data", data[:1200]])
            if not profile_cfg:
                profile_cfg = {"profile": profile_value}
            display_cmd = " ".join(cmd)
            SwingUtilities.invokeLater(
                lambda i=idx + 1, t=len(targets), c=display_cmd, p=profile_cfg.get("profile", profile_value): self.sqlmap_area.append(
                    "[*] ({}/{}) [{}] {}\n".format(i, t, p, c)
                )
            )

            process = None
            timed_out = False
            capture_path = None
            try:
                capture_fd, capture_path = tempfile.mkstemp(
                    prefix="burp_sqlmap_", suffix=".log"
                )
                os.close(capture_fd)
                capture_handle = open(capture_path, "wb")
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=capture_handle,
                        stderr=subprocess.STDOUT,
                        shell=False,
                    )
                finally:
                    capture_handle.close()
                self._set_active_tool_process("sqlmap", process)
                start_wait = time_module.time()
                while process.poll() is None:
                    if self._is_tool_cancelled("sqlmap"):
                        cancelled = True
                        self._terminate_process_cross_platform(process, "SQLMap")
                        break
                    if (time_module.time() - start_wait) > per_target_timeout:
                        timed_out = True
                        self._terminate_process_cross_platform(process, "SQLMap")
                        break
                    time_module.sleep(0.2)
                if process.poll() is None:
                    process.wait()
                combined = ""
                if capture_path and os.path.exists(capture_path):
                    with open(capture_path, "rb") as capture_reader:
                        combined = self._decode_process_data(
                            capture_reader.read(), "SQLMap output"
                        )
                evidence = self._extract_sqlmap_evidence(combined)

                if evidence:
                    findings.append(
                        "[HIGH] {} | {} | {}".format(endpoint_key, url, evidence)
                    )
                    verified_candidates.append(
                        {"method": method, "url": url, "endpoint_key": endpoint_key}
                    )
                elif timed_out:
                    findings.append("[MEDIUM] {} | {} | timed out".format(endpoint_key, url))
            except Exception as e:
                findings.append(
                    "[MEDIUM] {} | {} | error: {}".format(
                        endpoint_key, url, self._ascii_safe(e)
                    )
                )
            finally:
                if capture_path and os.path.exists(capture_path):
                    try:
                        os.remove(capture_path)
                    except Exception as cleanup_err:
                        self._callbacks.printError(
                            "SQLMap capture cleanup error: {}".format(
                                str(cleanup_err)
                            )
                        )
                self._clear_active_tool_process("sqlmap", process)

            if cancelled:
                break

        with self.sqlmap_lock:
            self.sqlmap_findings = list(findings)
            self.sqlmap_verified_candidates = list(verified_candidates)

        summary = []
        summary.append("\n" + "=" * 80)
        summary.append("SQLMAP VERIFY RESULTS")
        summary.append("=" * 80)
        summary.append("[*] Checked: {}".format(checked))
        summary.append("[*] Verified: {}".format(len(verified_candidates)))
        summary.append("[*] Findings lines: {}".format(len(findings)))
        if cancelled:
            summary.append("[!] Run cancelled by user")
        summary.append("")
        summary.extend(findings[:60] if findings else ["[+] No SQLi confirmations"])
        if len(findings) > 60:
            summary.append("[*] {} more lines not shown".format(len(findings) - 60))

        SwingUtilities.invokeLater(
            lambda t="\n".join(summary) + "\n": self.sqlmap_area.append(t)
        )
        SwingUtilities.invokeLater(
            lambda: self.log_to_ui(
                "[+] SQLMap verify complete: {} checked, {} verified".format(
                    checked, len(verified_candidates)
                )
            )
        )
        self._clear_tool_cancel("sqlmap")

    worker = threading.Thread(target=run_verify)
    worker.daemon = True
    worker.start()

def _export_sqlmap_results(self):
    """Export SQLMap verification findings."""
    with self.sqlmap_lock:
        data = list(self.sqlmap_findings)
    self._export_list_to_file(
        data, "SQLMapVerify_Export", self.sqlmap_area, "sqlmap findings"
    )

def _send_sqlmap_to_recon(self):
    """Send SQLMap-verified candidates to Recon."""
    with self.sqlmap_lock:
        candidates = list(self.sqlmap_verified_candidates)
    if not candidates:
        self.sqlmap_area.append("\n[!] No SQLMap-verified endpoints to send\n")
        return
    self._import_endpoint_candidates_to_recon(
        candidates, "sqlmap-verified", self.sqlmap_area
    )

def _run_dalfox_verify(self, event):
    """Run Dalfox verification over reflected-XSS candidates."""
    import os
    import subprocess
    import tempfile
    import time as time_module

    dalfox_path = self.dalfox_path_field.getText().strip()
    if not dalfox_path:
        self.dalfox_area.setText("[!] Configure Dalfox path first\n")
        return
    if not self.api_data:
        self.dalfox_area.setText("[!] No endpoints captured. Capture/import first.\n")
        return
    if not self._validate_binary_signature(
        "Dalfox",
        dalfox_path,
        self.dalfox_area,
        required_tokens=["url", "--format", "--output"],
        forbidden_tokens=[],
        fix_hint="Set Dalfox path to your local dalfox binary (for example: ~/go/bin/dalfox).",
    ):
        return

    max_targets = self._parse_positive_int(
        self.dalfox_max_targets_field.getText(), 12, 1, 100
    )
    per_target_timeout = self._parse_positive_int(
        self.dalfox_target_timeout_field.getText(), 40, 10, 300
    )
    profile_value = self._selected_profile_value(
        getattr(self, "dalfox_profile_combo", None)
    )
    targets = self._collect_verify_targets(["xss"], max_targets)
    if not targets:
        self.dalfox_area.setText(
            "[!] No XSS verification targets.\n[*] Generate fuzzing attacks first.\n"
        )
        return

    self.dalfox_area.setText("[*] Dalfox verification starting...\n")
    self.dalfox_area.append("[*] Targets: {}\n".format(len(targets)))
    self.dalfox_area.append("[*] Profile: {}\n".format(profile_value))
    self.dalfox_area.append("[*] Timeout per target: {}s\n\n".format(per_target_timeout))
    self._clear_tool_cancel("dalfox")

    def run_verify():
        findings = []
        verified_candidates = []
        checked = 0
        cancelled = False
        temp_dir = tempfile.mkdtemp(prefix="burp_dalfox_")

        try:
            for idx, target in enumerate(targets):
                if self._is_tool_cancelled("dalfox"):
                    cancelled = True
                    break
                checked += 1
                url = target["url"]
                endpoint_key = target["endpoint_key"]
                out_file = os.path.join(temp_dir, "dalfox_{}.jsonl".format(idx))
                method = target.get("method", "GET")
                cmd = []
                profile_cfg = {"profile": profile_value}
                try:
                    cmd, profile_cfg = self._build_dalfox_command(
                        dalfox_path, target, out_file, profile_value
                    )
                except Exception as build_err:
                    self._callbacks.printError(
                        "Dalfox profile builder fallback: {}".format(str(build_err))
                    )
                    cmd = [
                        dalfox_path,
                        "url",
                        url,
                        "--format",
                        "jsonl",
                        "-o",
                        out_file,
                        "--no-color",
                        "--timeout",
                        "8",
                        "--worker",
                        "30",
                    ]
                    for param in target.get("params", [])[:4]:
                        cmd.extend(["-p", param])
                    data = target.get("data", "")
                    if method in ["POST", "PUT", "PATCH", "DELETE"] and data:
                        cmd.extend(["-X", method, "-d", data[:1200]])
                if not profile_cfg:
                    profile_cfg = {"profile": profile_value}

                SwingUtilities.invokeLater(
                    lambda i=idx + 1, t=len(targets), c=" ".join(cmd), p=profile_cfg.get("profile", profile_value): self.dalfox_area.append(
                        "[*] ({}/{}) [{}] {}\n".format(i, t, p, c)
                    )
                )

                process = None
                timed_out = False
                capture_path = None
                try:
                    capture_fd, capture_path = tempfile.mkstemp(
                        prefix="burp_dalfox_", suffix=".log"
                    )
                    os.close(capture_fd)
                    capture_handle = open(capture_path, "wb")
                    try:
                        process = subprocess.Popen(
                            cmd,
                            stdout=capture_handle,
                            stderr=subprocess.STDOUT,
                            shell=False,
                        )
                    finally:
                        capture_handle.close()
                    self._set_active_tool_process("dalfox", process)
                    start_wait = time_module.time()
                    while process.poll() is None:
                        if self._is_tool_cancelled("dalfox"):
                            cancelled = True
                            self._terminate_process_cross_platform(process, "Dalfox")
                            break
                        if (time_module.time() - start_wait) > per_target_timeout:
                            timed_out = True
                            self._terminate_process_cross_platform(process, "Dalfox")
                            break
                        time_module.sleep(0.2)

                    if process.poll() is None:
                        process.wait()
                    combined = ""
                    if capture_path and os.path.exists(capture_path):
                        with open(capture_path, "rb") as capture_reader:
                            combined = self._decode_process_data(
                                capture_reader.read(), "Dalfox output"
                            )
                    evidence = ""

                    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                        with open(out_file, "r") as reader:
                            first_line = reader.readline().strip()
                        evidence = self._ascii_safe(first_line)[:240]
                    if not evidence:
                        evidence = self._extract_dalfox_evidence(combined)

                    if evidence:
                        findings.append(
                            "[HIGH] {} | {} | {}".format(endpoint_key, url, evidence)
                        )
                        verified_candidates.append(
                            {"method": method, "url": url, "endpoint_key": endpoint_key}
                        )
                    elif timed_out:
                        findings.append("[MEDIUM] {} | {} | timed out".format(endpoint_key, url))
                except Exception as e:
                    findings.append(
                        "[MEDIUM] {} | {} | error: {}".format(
                            endpoint_key, url, self._ascii_safe(e)
                        )
                    )
                finally:
                    if capture_path and os.path.exists(capture_path):
                        try:
                            os.remove(capture_path)
                        except Exception as cleanup_err:
                            self._callbacks.printError(
                                "Dalfox capture cleanup error: {}".format(
                                    str(cleanup_err)
                                )
                            )
                    self._clear_active_tool_process("dalfox", process)

                if cancelled:
                    break
        finally:
            self._cleanup_temp_dir(temp_dir, "dalfox verify")

        with self.dalfox_lock:
            self.dalfox_findings = list(findings)
            self.dalfox_verified_candidates = list(verified_candidates)

        summary = []
        summary.append("\n" + "=" * 80)
        summary.append("DALFOX VERIFY RESULTS")
        summary.append("=" * 80)
        summary.append("[*] Checked: {}".format(checked))
        summary.append("[*] Verified: {}".format(len(verified_candidates)))
        summary.append("[*] Findings lines: {}".format(len(findings)))
        if cancelled:
            summary.append("[!] Run cancelled by user")
        summary.append("")
        summary.extend(findings[:60] if findings else ["[+] No XSS confirmations"])
        if len(findings) > 60:
            summary.append("[*] {} more lines not shown".format(len(findings) - 60))

        SwingUtilities.invokeLater(
            lambda t="\n".join(summary) + "\n": self.dalfox_area.append(t)
        )
        SwingUtilities.invokeLater(
            lambda: self.log_to_ui(
                "[+] Dalfox verify complete: {} checked, {} verified".format(
                    checked, len(verified_candidates)
                )
            )
        )
        self._clear_tool_cancel("dalfox")

    worker = threading.Thread(target=run_verify)
    worker.daemon = True
    worker.start()

def _export_dalfox_results(self):
    """Export Dalfox verification findings."""
    with self.dalfox_lock:
        data = list(self.dalfox_findings)
    self._export_list_to_file(
        data, "DalfoxVerify_Export", self.dalfox_area, "dalfox findings"
    )

def _send_dalfox_to_recon(self):
    """Send Dalfox-verified candidates to Recon."""
    with self.dalfox_lock:
        candidates = list(self.dalfox_verified_candidates)
    if not candidates:
        self.dalfox_area.append("\n[!] No Dalfox-verified endpoints to send\n")
        return
    self._import_endpoint_candidates_to_recon(
        candidates, "dalfox-verified", self.dalfox_area
    )

def _collect_asset_domain_candidates(self, max_candidates=50):
    """Collect ranked asset-domain candidates from explicit input and proxy history."""
    try:
        max_items = int(max_candidates)
    except Exception as e:
        self._callbacks.printError(
            "Asset candidate max parsing failed: {}".format(self._ascii_safe(e))
        )
        max_items = 50
    if max_items <= 0:
        max_items = 50

    candidate_scores = {}
    selected_host = "all"
    force_host = False
    scope_override = self._get_target_scope_override()
    try:
        if hasattr(self, "host_filter") and self.host_filter is not None:
            selected_host = self._ascii_safe(
                str(self.host_filter.getSelectedItem()), lower=True
            ).strip()
    except Exception as e:
        self._callbacks.printError(
            "Asset host-filter read error: {}".format(self._ascii_safe(e))
        )
        selected_host = "all"
    force_host = bool(selected_host and selected_host != "all")
    selected_base = self._infer_base_domain(selected_host) if force_host else ""

    explicit_values = []
    if hasattr(self, "asset_domains_field") and self.asset_domains_field is not None:
        explicit_values = self._parse_comma_newline_values(
            self.asset_domains_field.getText()
        )
    for raw in explicit_values:
        host = self._ascii_safe(raw, lower=True).strip()
        if "://" in host:
            host = self._extract_scope_host(host)
        host = self._ascii_safe(host, lower=True).strip().lstrip("*.").rstrip(".")
        if not host:
            continue
        base = self._infer_base_domain(host)
        if not base:
            continue
        candidate_scores[base] = candidate_scores.get(base, 0) + 30

    with self.lock:
        snapshot = list(self.api_data.values())

    for entries in snapshot:
        entry = self._get_entry(entries)
        host = self._ascii_safe(entry.get("host") or "", lower=True).strip()
        if not host:
            continue
        if scope_override.get("enabled") and not self._host_matches_target_scope(
            host, scope_override
        ):
            continue
        if force_host:
            host_base = self._infer_base_domain(host)
            if host != selected_host and host_base != selected_base:
                continue
        elif self._is_wayback_noise_host(host):
            continue
        base = self._infer_base_domain(host)
        if not base:
            continue
        weight = 2 if not self._ffuf_is_noise_host(host) else 1
        candidate_scores[base] = candidate_scores.get(base, 0) + weight

    ordered = sorted(
        candidate_scores.items(), key=lambda item: (-int(item[1]), item[0])
    )
    return [
        {"domain": domain, "score": int(score)}
        for domain, score in ordered[:max_items]
    ]

def _autopopulate_asset_domains_from_history(
    self, overwrite=False, append_output=False
):
    """Populate Subfinder domain textbox with selected proxy-history candidates."""
    if not hasattr(self, "asset_domains_field") or self.asset_domains_field is None:
        return []

    current_values = self._parse_comma_newline_values(
        self.asset_domains_field.getText()
    )
    if current_values and (not overwrite):
        self.asset_selected_domains = list(current_values)
        return list(current_values)

    candidates = self._collect_asset_domain_candidates(max_candidates=50)
    self.asset_target_candidates = list(candidates)
    candidate_domains = [item.get("domain") for item in candidates if item.get("domain")]
    if not candidate_domains:
        if append_output and hasattr(self, "asset_area") and self.asset_area is not None:
            self.asset_area.append("[!] No Subfinder targets found in proxy history\n")
        return []

    selected = []
    existing = list(getattr(self, "asset_selected_domains", []) or [])
    if existing and (not overwrite):
        selected = [d for d in existing if d in candidate_domains]
    if not selected:
        selected = list(candidate_domains)

    max_field_value = "8"
    if hasattr(self, "asset_max_domains_field") and self.asset_max_domains_field is not None:
        max_field_value = self.asset_max_domains_field.getText()
    max_domains = self._parse_positive_int(max_field_value, 8, 1, 50)
    selected = selected[:max_domains]
    self.asset_selected_domains = list(selected)
    self.asset_domains_field.setText(", ".join(selected))

    if append_output and hasattr(self, "asset_area") and self.asset_area is not None:
        self.asset_area.append(
            "[+] Subfinder targets selected from history: {}\n".format(
                len(selected)
            )
        )
    return list(selected)

def _show_asset_targets_popup(self, event):
    """Show selectable Subfinder target domains from proxy history."""
    candidates = self._collect_asset_domain_candidates(max_candidates=80)
    self.asset_target_candidates = list(candidates)
    if not candidates:
        if hasattr(self, "asset_area") and self.asset_area is not None:
            self.asset_area.setText(
                "[!] No Subfinder targets found in proxy history\n[*] Enter domains manually in textbox.\n"
            )
        return

    options = []
    for idx, item in enumerate(candidates):
        domain = self._ascii_safe(item.get("domain") or "").strip()
        if not domain:
            continue
        score = int(item.get("score") or 0)
        options.append(
            {
                "value": domain,
                "label": "#{:02d} [score {}] {}".format(idx + 1, score, domain),
            }
        )

    preselected = list(getattr(self, "asset_selected_domains", []) or [])
    if not preselected:
        preselected = [item.get("value") for item in options]

    selected = self._show_multi_select_targets_popup(
        "Subfinder Targets",
        options,
        preselected_values=preselected,
        footer_text=(
            "Default selection is all likely domains from proxy history. "
            "Deselect domains you do not want to scan."
        ),
    )
    if selected is None:
        return

    max_domains = self._parse_positive_int(
        self.asset_max_domains_field.getText(), 8, 1, 50
    )
    selected = list(selected[:max_domains])
    self.asset_selected_domains = list(selected)
    self.asset_domains_field.setText(", ".join(selected))

    if hasattr(self, "asset_area") and self.asset_area is not None:
        self.asset_area.append(
            "[+] Subfinder target selection updated: {} domains\n".format(
                len(selected)
            )
        )

def _extract_domains_for_asset_discovery(self, max_domains):
    """Collect unique root domains from input field or Recon hosts."""
    explicit = self._ascii_safe(self.asset_domains_field.getText()).strip()
    domains = []
    seen = set()
    source_counts = {"manual": 0, "selected": 0, "history": 0}
    dropped_noise = 0
    dropped_scope = 0
    selected_host = "all"
    force_host = False
    scope_override = self._get_target_scope_override()
    try:
        if hasattr(self, "host_filter") and self.host_filter is not None:
            selected_host = self._ascii_safe(
                str(self.host_filter.getSelectedItem()), lower=True
            ).strip()
    except Exception as e:
        self._callbacks.printError(
            "Asset host-filter read error: {}".format(self._ascii_safe(e))
        )
        selected_host = "all"
    force_host = bool(selected_host and selected_host != "all")
    selected_base = self._infer_base_domain(selected_host) if force_host else ""
    if explicit:
        normalized = explicit.replace(",", "\n")
        for raw in normalized.splitlines():
            domain = self._ascii_safe(raw, lower=True).strip()
            if not domain:
                continue
            if "://" in domain:
                domain = self._extract_scope_host(domain)
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
                source_counts["manual"] += 1
                if len(domains) >= max_domains:
                    self.asset_domain_meta = {
                        "source_counts": source_counts,
                        "dropped_noise": dropped_noise,
                        "dropped_scope": dropped_scope,
                        "selected_host": selected_host,
                        "scope_enabled": bool(scope_override.get("enabled")),
                    }
                    return domains

    selected_domains = list(getattr(self, "asset_selected_domains", []) or [])
    for domain in selected_domains:
        safe_domain = self._ascii_safe(domain, lower=True).strip()
        if not safe_domain or safe_domain in seen:
            continue
        seen.add(safe_domain)
        domains.append(safe_domain)
        source_counts["selected"] += 1
        if len(domains) >= max_domains:
            self.asset_domain_meta = {
                "source_counts": source_counts,
                "dropped_noise": dropped_noise,
                "dropped_scope": dropped_scope,
                "selected_host": selected_host,
                "scope_enabled": bool(scope_override.get("enabled")),
            }
            return domains

    with self.lock:
        hosts = [
            self._get_entry(entries).get("host", "")
            for entries in self.api_data.values()
        ]
    host_counter = {}
    for host in hosts:
        host_text = self._ascii_safe(host, lower=True).strip()
        if not host_text:
            continue
        if scope_override.get("enabled") and not self._host_matches_target_scope(
            host_text, scope_override
        ):
            dropped_scope += 1
            continue
        host_base = self._infer_base_domain(host_text) or host_text
        if force_host:
            if host_text != selected_host and host_base != selected_base:
                dropped_scope += 1
                continue
        elif self._is_wayback_noise_host(host_text):
            dropped_noise += 1
            continue
        base = self._infer_base_domain(host_text) or host_text
        host_counter[base] = host_counter.get(base, 0) + 1
    ranked = sorted(host_counter.items(), key=lambda item: (-item[1], item[0]))
    for domain, _ in ranked:
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
            source_counts["history"] += 1
            if len(domains) >= max_domains:
                break
    self.asset_domain_meta = {
        "source_counts": source_counts,
        "dropped_noise": dropped_noise,
        "dropped_scope": dropped_scope,
        "selected_host": selected_host,
        "scope_enabled": bool(scope_override.get("enabled")),
    }
    return domains

def _run_command_stage(
    self,
    tool_key,
    tool_name,
    cmd,
    output_area,
    timeout_seconds,
    heartbeat_seconds=0,
):
    """Run one subprocess stage with cancellation and timeout."""
    import subprocess
    import time as time_module

    process = None
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
        )
        self._set_active_tool_process(tool_key, process)
        start_wait = time_module.time()
        last_heartbeat = start_wait
        while process.poll() is None:
            if self._is_tool_cancelled(tool_key):
                self._terminate_process_cross_platform(process, tool_name)
                return False, True, "", "cancelled"
            elapsed = time_module.time() - start_wait
            if elapsed > timeout_seconds:
                self._terminate_process_cross_platform(process, tool_name)
                return False, False, "", "timeout"
            if (
                heartbeat_seconds
                and heartbeat_seconds > 0
                and (time_module.time() - last_heartbeat) >= heartbeat_seconds
            ):
                last_heartbeat = time_module.time()
                if output_area is not None:
                    SwingUtilities.invokeLater(
                        lambda e=int(elapsed), t=self._ascii_safe(tool_name): output_area.append(
                            "[*] {} still running... {}s elapsed\n".format(t, e)
                        )
                    )
            time_module.sleep(0.2)

        stdout_data = self._safe_pipe_read(process.stdout, "{} stdout".format(tool_name))
        stderr_data = self._safe_pipe_read(process.stderr, "{} stderr".format(tool_name))
        ok = process.returncode == 0
        err = stderr_data if stderr_data else stdout_data
        return ok, False, stdout_data, self._ascii_safe(err)[:1000]
    except Exception as e:
        return False, False, "", self._ascii_safe(e)
    finally:
        self._clear_active_tool_process(tool_key, process)

def _run_api_asset_discovery(self, event):
    """Run Subfinder to discover API-related asset domains."""
    import os
    import tempfile

    explicit_domains = self._ascii_safe(self.asset_domains_field.getText()).strip()
    if not explicit_domains:
        self._autopopulate_asset_domains_from_history(
            overwrite=False, append_output=False
        )
        explicit_domains = self._ascii_safe(
            self.asset_domains_field.getText()
        ).strip()
    if (not self.api_data) and (not explicit_domains):
        self.asset_area.setText(
            "[!] No endpoints captured and no domains provided.\n[*] Capture/import first or enter domains manually.\n"
        )
        return

    subfinder_path = self.asset_subfinder_path_field.getText().strip()
    if not subfinder_path:
        self.asset_area.setText("[!] Configure Subfinder path first\n")
        return
    if not self._validate_binary_signature(
        "Subfinder",
        subfinder_path,
        self.asset_area,
        required_tokens=["-d", "-silent"],
        forbidden_tokens=[],
        fix_hint="Set Subfinder Path to your local subfinder binary (for example: /home/teycir/go/bin/subfinder).",
    ):
        return

    max_domains = self._parse_positive_int(
        self.asset_max_domains_field.getText(), 8, 1, 50
    )
    profile_value = self._selected_profile_value(
        getattr(self, "asset_profile_combo", None)
    )
    domains = self._extract_domains_for_asset_discovery(max_domains)
    if not domains:
        self.asset_area.setText("[!] No candidate domains found for discovery\n")
        return

    self.asset_area.setText("[*] Subfinder discovery starting...\n")
    self.asset_area.append("[*] Profile: {}\n".format(profile_value))
    self.asset_area.append("[*] Domains: {}\n\n".format(", ".join(domains)))
    domain_meta = getattr(self, "asset_domain_meta", {}) or {}
    source_counts = domain_meta.get("source_counts", {}) or {}
    self.asset_area.append(
        "[*] Sources: manual={}, selected={}, history={}\n".format(
            int(source_counts.get("manual", 0) or 0),
            int(source_counts.get("selected", 0) or 0),
            int(source_counts.get("history", 0) or 0),
        )
    )
    self.asset_area.append(
        "[*] Filter: host={} scope_enabled={} dropped_noise={} dropped_scope={}\n\n".format(
            self._ascii_safe(domain_meta.get("selected_host") or "all"),
            bool(domain_meta.get("scope_enabled")),
            int(domain_meta.get("dropped_noise", 0) or 0),
            int(domain_meta.get("dropped_scope", 0) or 0),
        )
    )
    self._clear_tool_cancel("assetdiscovery")

    def run_discovery():
        temp_dir = tempfile.mkdtemp(prefix="burp_assets_")
        domains_file = os.path.join(temp_dir, "domains.txt")
        output_file = os.path.join(temp_dir, "subfinder.txt")
        discovered_domains = []

        try:
            with open(domains_file, "w") as writer:
                for domain in domains:
                    writer.write(domain + "\n")

            profile_cfg = {"profile": profile_value}
            timeout_seconds = 240
            try:
                profile_cfg = self._asset_profile_settings(profile_value)
                timeout_seconds = int(profile_cfg.get("subfinder_timeout", 240))
            except Exception as build_err:
                self._callbacks.printError(
                    "Asset profile builder fallback: {}".format(str(build_err))
                )
                timeout_seconds = 240

            use_custom_subfinder, custom_subfinder_command = self._resolve_custom_command(
                "Subfinder",
                self.asset_custom_cmd_checkbox,
                self.asset_custom_cmd_field,
                {
                    "subfinder_path": subfinder_path,
                    "domains_file": domains_file,
                    "output_file": output_file,
                },
                self.asset_area,
            )
            if use_custom_subfinder and not custom_subfinder_command:
                return

            if use_custom_subfinder and custom_subfinder_command:
                cmd = self._build_shell_command(custom_subfinder_command)
                display_cmd = custom_subfinder_command
                uses_output_file = output_file in custom_subfinder_command
                SwingUtilities.invokeLater(
                    lambda: self.asset_area.append(
                        "[*] Custom command override enabled\n"
                    )
                )
            else:
                cmd = [
                    subfinder_path,
                    "-dL",
                    domains_file,
                    "-silent",
                    "-o",
                    output_file,
                ]
                display_cmd = " ".join(cmd)
                uses_output_file = True

            SwingUtilities.invokeLater(
                lambda c=display_cmd, p=profile_cfg.get("profile", profile_value): self.asset_area.append(
                    "[*] [{}] Subfinder: {}\n".format(p, c)
                )
            )

            ok, was_cancelled, stdout_data, err = self._run_command_stage(
                "assetdiscovery",
                "Subfinder",
                cmd,
                self.asset_area,
                timeout_seconds,
                heartbeat_seconds=12,
            )
            if was_cancelled:
                SwingUtilities.invokeLater(
                    lambda: self.asset_area.append("[!] Asset discovery cancelled by user\n")
                )
                return
            if not ok:
                SwingUtilities.invokeLater(
                    lambda e=err: self.asset_area.append(
                        "[!] Subfinder failed: {}\n".format(e)
                    )
                )
            else:
                SwingUtilities.invokeLater(
                    lambda: self.asset_area.append(
                        "[+] Subfinder command completed successfully\n"
                    )
                )

            stdout_len = len(self._ascii_safe(stdout_data))
            stderr_preview = self._ascii_safe(err or "").strip()
            if stdout_len > 0:
                SwingUtilities.invokeLater(
                    lambda n=stdout_len: self.asset_area.append(
                        "[*] Subfinder stdout size: {} bytes\n".format(n)
                    )
                )
            if stderr_preview:
                SwingUtilities.invokeLater(
                    lambda p=stderr_preview[:320]: self.asset_area.append(
                        "[*] Subfinder stderr/stdout preview: {}\n".format(p)
                    )
                )

            if uses_output_file and os.path.exists(output_file):
                file_line_count = 0
                with open(output_file, "r") as reader:
                    for line in reader:
                        file_line_count += 1
                        host = self._ascii_safe(line, lower=True).strip().split(" ")[
                            0
                        ].strip()
                        host = host.lstrip("*.").rstrip(".")
                        if not host:
                            continue
                        discovered_domains.append(host)
                SwingUtilities.invokeLater(
                    lambda c=file_line_count: self.asset_area.append(
                        "[*] Subfinder output file lines: {}\n".format(c)
                    )
                )

            if not discovered_domains and stdout_data:
                for line in self._ascii_safe(stdout_data).splitlines():
                    host = self._ascii_safe(line, lower=True).strip().split(" ")[
                        0
                    ].strip()
                    host = host.lstrip("*.").rstrip(".")
                    if host and "." in host and "/" not in host:
                        discovered_domains.append(host)

            if (not discovered_domains) and (not ok):
                discovered_domains = sorted(set(domains))
                SwingUtilities.invokeLater(
                    lambda: self.asset_area.append(
                        "[!] Fallback: using input domains as seed assets\n"
                    )
                )

            discovered_domains = sorted(set(discovered_domains))
            discovered_urls = [
                "https://" + host for host in discovered_domains if host
            ]
            with self.asset_lock:
                self.asset_discovered = list(discovered_urls)

            out_lines = []
            out_lines.append("\n" + "=" * 80)
            out_lines.append("API ASSET DISCOVERY RESULTS")
            out_lines.append("=" * 80)
            out_lines.append("[*] Domains input: {}".format(len(domains)))
            out_lines.append(
                "[*] Asset domains discovered: {}".format(len(discovered_domains))
            )
            out_lines.append("[*] Asset URLs generated: {}".format(len(discovered_urls)))
            out_lines.append("")
            out_lines.extend(
                discovered_domains[:120]
                if discovered_domains
                else ["[+] No domains discovered"]
            )
            if len(discovered_domains) > 120:
                out_lines.append(
                    "[*] {} more domains not shown".format(
                        len(discovered_domains) - 120
                    )
                )
            if use_custom_subfinder and custom_subfinder_command and (not uses_output_file):
                out_lines.append("")
                out_lines.append(
                    "[*] Note: custom command does not reference {output_file}; parsed stdout/fallback."
                )
            out_lines.append("")
            out_lines.append("COPY-READY ASSET DOMAINS")
            out_lines.append("-" * 80)
            out_lines.extend(
                discovered_domains if discovered_domains else ["[+] No domains discovered"]
            )
            out_lines.append("")
            out_lines.append("COPY-READY ASSET URLS")
            out_lines.append("-" * 80)
            out_lines.extend(
                discovered_urls if discovered_urls else ["[+] No URLs generated"]
            )
            SwingUtilities.invokeLater(
                lambda t="\n".join(out_lines) + "\n": self.asset_area.append(t)
            )
            SwingUtilities.invokeLater(
                lambda: self.log_to_ui(
                    "[+] Subfinder complete: {} domains, {} URLs".format(
                        len(discovered_domains), len(discovered_urls)
                    )
                )
            )
        finally:
            self._clear_tool_cancel("assetdiscovery")
            self._cleanup_temp_dir(temp_dir, "api asset discovery")

    worker = threading.Thread(target=run_discovery)
    worker.daemon = True
    worker.start()

def _export_asset_discovery_results(self):
    """Export API asset discovery URLs."""
    with self.asset_lock:
        data = list(self.asset_discovered)
    self._export_list_to_file(
        data, "APIAssets_Export", self.asset_area, "asset URLs"
    )

def _send_asset_discovery_to_recon(self):
    """Send discovered API asset URLs to Recon."""
    with self.asset_lock:
        urls = list(self.asset_discovered)
    if not urls:
        self.asset_area.append("\n[!] No discovered asset URLs to send\n")
        return
    candidates = [{"method": "GET", "url": url} for url in urls]
    self._import_endpoint_candidates_to_recon(
        candidates, "asset-discovery", self.asset_area
    )

def _browse_openapi_spec_file(self):
    """Open file chooser for local OpenAPI spec path."""
    chooser = JFileChooser()
    chooser.setDialogTitle("Select OpenAPI/Swagger file")
    if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
        path = chooser.getSelectedFile().getAbsolutePath()
        self.openapi_spec_field.setText(path)

def _openapi_spec_candidate_score(self, path_lower):
    """Score likely OpenAPI/Swagger endpoints from observed paths."""
    safe_path = self._ascii_safe(path_lower, lower=True)
    score = 0

    if "openapi" in safe_path:
        score += 10
    if "swagger" in safe_path:
        score += 8
    if "api-docs" in safe_path:
        score += 7
    if safe_path.endswith(".json") or safe_path.endswith(".yaml") or safe_path.endswith(".yml"):
        score += 4
    if "/v3/api-docs" in safe_path or "/v2/api-docs" in safe_path:
        score += 3
    if "swagger-ui" in safe_path:
        score -= 4

    return score

def _collect_openapi_spec_candidates(self, max_candidates=15):
    """Collect likely OpenAPI/Swagger targets from observed proxy history."""
    try:
        max_items = int(max_candidates)
    except Exception as e:
        self._callbacks.printError(
            "OpenAPI candidate max parsing failed: {}".format(self._ascii_safe(e))
        )
        max_items = 15
    if max_items <= 0:
        max_items = 15

    with self.lock:
        snapshot = list(self.api_data.values())

    candidate_map = {}
    for entries in snapshot:
        entry = self._get_entry(entries)
        method = self._ascii_safe(entry.get("method"), lower=True).strip().upper()
        if method not in ["GET", "HEAD", "OPTIONS"]:
            continue

        host = self._ascii_safe(entry.get("host"), lower=True).strip()
        protocol = self._ascii_safe(entry.get("protocol"), lower=True).strip()
        path = self._ascii_safe(
            entry.get("path") or entry.get("normalized_path") or "/"
        ).strip()
        if not host or protocol not in ["http", "https"]:
            continue
        if not path.startswith("/"):
            path = "/" + path

        score = self._openapi_spec_candidate_score(path.lower())
        if score <= 0:
            continue

        query = self._ascii_safe(entry.get("query_string") or "").strip()
        candidate_url = "{}://{}{}".format(protocol, host, path)
        if query and any(
            token in query.lower() for token in ["url=", "format=", "spec=", "schema="]
        ):
            candidate_url = "{}?{}".format(candidate_url, query)

        existing = candidate_map.get(candidate_url)
        if (existing is None) or (score > existing.get("score", 0)):
            candidate_map[candidate_url] = {
                "url": candidate_url,
                "score": score,
                "path": path,
            }

    ordered = sorted(
        candidate_map.values(),
        key=lambda x: (-int(x.get("score", 0) or 0), self._ascii_safe(x.get("url"), lower=True)),
    )
    return ordered[:max_items]

def _show_openapi_spec_targets_popup(self, event):
    """Show selectable OpenAPI/Swagger targets from proxy history."""
    candidates = self._collect_openapi_spec_candidates(max_candidates=30)
    self.openapi_spec_candidates = list(candidates)
    if not candidates:
        if hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.setText(
                "[!] No OpenAPI/Swagger candidates found in proxy history\n"
            )
        return

    options = []
    for idx, item in enumerate(candidates):
        url = self._ascii_safe(item.get("url") or "").strip()
        if not url:
            continue
        score = int(item.get("score") or 0)
        options.append(
            {
                "value": url,
                "label": "#{:02d} [score {}] {}".format(idx + 1, score, url),
            }
        )

    preselected = list(getattr(self, "openapi_selected_spec_targets", []) or [])
    if not preselected:
        preselected = [item.get("value") for item in options]

    selected = self._show_multi_select_targets_popup(
        "OpenAPI Targets",
        options,
        preselected_values=preselected,
        footer_text=(
            "Default selection is all likely OpenAPI/Swagger targets from proxy history. "
            "Run Drift uses the first selected item in the field."
        ),
    )
    if selected is None:
        return

    self.openapi_selected_spec_targets = list(selected)
    if selected:
        self.openapi_spec_field.setText(self._ascii_safe(selected[0]))
        if hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.append(
                "[+] OpenAPI targets selected: {} (run target: {})\n".format(
                    len(selected), self._ascii_safe(selected[0])
                )
            )
    else:
        self.openapi_spec_field.setText("")
        if hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.append("[!] No OpenAPI targets selected\n")

def _autoselect_openapi_spec_from_history(self, append_output=False, overwrite=False):
    """Preselect best OpenAPI candidate from proxy history."""
    if not hasattr(self, "openapi_spec_field") or self.openapi_spec_field is None:
        return None

    candidates = self._collect_openapi_spec_candidates()
    self.openapi_spec_candidates = list(candidates)
    if not candidates:
        if append_output and hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.append("[!] No OpenAPI/Swagger candidates found in proxy history\n")
        return None

    candidate_urls = [
        self._ascii_safe(item.get("url") or "").strip()
        for item in candidates
        if self._ascii_safe(item.get("url") or "").strip()
    ]
    existing_selected = list(
        getattr(self, "openapi_selected_spec_targets", []) or []
    )
    if existing_selected and (not overwrite):
        selected_urls = [u for u in existing_selected if u in candidate_urls]
        if not selected_urls:
            selected_urls = list(candidate_urls)
        self.openapi_selected_spec_targets = list(selected_urls)
    else:
        self.openapi_selected_spec_targets = list(candidate_urls)

    if (not overwrite) and self.openapi_spec_field.getText().strip():
        return self._ascii_safe(self.openapi_spec_field.getText()).strip()

    selected = (
        self._ascii_safe(self.openapi_selected_spec_targets[0]).strip()
        if self.openapi_selected_spec_targets
        else self._ascii_safe(candidates[0].get("url") or "").strip()
    )
    if selected:
        self.openapi_spec_field.setText(selected)
        if append_output and hasattr(self, "openapi_area") and self.openapi_area is not None:
            self.openapi_area.append("[+] Auto-selected OpenAPI target: {}\n".format(selected))
            if len(candidates) > 1:
                self.openapi_area.append("[*] Alternate candidates:\n")
                for item in candidates[1:6]:
                    self.openapi_area.append("  - {}\n".format(self._ascii_safe(item.get("url") or "")))
        return selected
    return None

def _detect_openapi_spec_from_history(self, event):
    """Manual refresh for OpenAPI candidate auto-selection from history."""
    selected = self._autoselect_openapi_spec_from_history(
        append_output=True, overwrite=True
    )
    if selected:
        self.log_to_ui("[+] OpenAPI candidate selected from proxy history")
    else:
        self.log_to_ui("[!] No OpenAPI candidate detected in proxy history")

def _normalize_spec_path(self, path):
    """Normalize spec path placeholders to match Recon normalization."""
    raw = self._ascii_safe(path or "/").strip()
    if not raw.startswith("/"):
        raw = "/" + raw
    raw = re.sub(r"\{[^}]+\}", "{id}", raw)
    return self._normalize_path(raw)

def _load_openapi_spec_text(self, source):
    """Load OpenAPI text from local file or URL."""
    src = self._ascii_safe(source).strip()
    if src.startswith("http://") or src.startswith("https://"):
        fetch_error = None
        try:
            import urllib2

            response = urllib2.urlopen(src, timeout=20)
            return self._ascii_safe(response.read())
        except ImportError as import_err:
            fetch_error = import_err
        except Exception as url_err:
            fetch_error = url_err

        try:
            import urllib.request as urllib_request

            response = urllib_request.urlopen(src, timeout=20)
            return self._ascii_safe(response.read())
        except Exception as url_err:
            message = "OpenAPI URL fetch failed: {}".format(self._ascii_safe(url_err))
            if fetch_error:
                message = "{} (fallback after: {})".format(
                    message, self._ascii_safe(fetch_error)
                )
            raise RuntimeError(message)
    with open(src, "r") as reader:
        return self._ascii_safe(reader.read())

def _parse_openapi_json_doc(self, doc):
    """Parse OpenAPI JSON structure into endpoint/params metadata."""
    endpoints = set()
    params_map = {}
    server_urls = []
    methods = set(["get", "post", "put", "patch", "delete", "options", "head"])

    for server in (doc.get("servers", []) or []):
        url = self._ascii_safe((server or {}).get("url") or "").strip()
        if url:
            server_urls.append(url)

    paths = doc.get("paths", {}) or {}
    for raw_path, path_item in paths.items():
        normalized_path = self._normalize_spec_path(raw_path)
        if not isinstance(path_item, dict):
            continue
        common_params = []
        for p in (path_item.get("parameters", []) or []):
            if isinstance(p, dict):
                name = self._ascii_safe(p.get("name") or "").strip()
                if name:
                    common_params.append(name)
        for method, operation in path_item.items():
            method_l = self._ascii_safe(method, lower=True).strip()
            if method_l not in methods:
                continue
            endpoint_key = "{}:{}".format(method_l.upper(), normalized_path)
            endpoints.add(endpoint_key)
            op_params = list(common_params)
            if isinstance(operation, dict):
                for p in (operation.get("parameters", []) or []):
                    if isinstance(p, dict):
                        name = self._ascii_safe(p.get("name") or "").strip()
                        if name:
                            op_params.append(name)
                request_body = operation.get("requestBody", {}) or {}
                content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
                app_json = content.get("application/json", {}) if isinstance(content, dict) else {}
                schema = app_json.get("schema", {}) if isinstance(app_json, dict) else {}
                properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                if isinstance(properties, dict):
                    for name in properties.keys():
                        safe_name = self._ascii_safe(name).strip()
                        if safe_name:
                            op_params.append(safe_name)
            params_map[endpoint_key] = sorted(set(op_params))
    return endpoints, params_map, server_urls

def _parse_openapi_yaml_text(self, text):
    """Parse basic OpenAPI YAML path/method entries (lightweight fallback)."""
    endpoints = set()
    params_map = {}
    server_urls = []
    methods = set(["get", "post", "put", "patch", "delete", "options", "head"])
    current_path = ""
    in_paths = False

    for raw_line in self._ascii_safe(text).splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "paths:":
            in_paths = True
            continue
        if stripped.startswith("servers:"):
            in_paths = False
            continue
        if stripped.startswith("- url:"):
            server_url = self._ascii_safe(stripped.split(":", 1)[1]).strip()
            if server_url:
                server_urls.append(server_url)
            continue
        if not in_paths:
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent <= 2 and stripped.endswith(":") and stripped.startswith("/"):
            current_path = stripped[:-1]
            continue
        if current_path and indent >= 4 and stripped.endswith(":"):
            method_name = self._ascii_safe(stripped[:-1], lower=True).strip()
            if method_name in methods:
                endpoint_key = "{}:{}".format(
                    method_name.upper(), self._normalize_spec_path(current_path)
                )
                endpoints.add(endpoint_key)
                params_map[endpoint_key] = []

    return endpoints, params_map, server_urls

def _choose_openapi_base_url(self, server_urls):
    """Pick base URL for generating missing-endpoint candidates."""
    if server_urls:
        first = self._ascii_safe(server_urls[0]).strip()
        if first.startswith("http://") or first.startswith("https://"):
            return first.rstrip("/")

    preferred_host = ""
    try:
        if hasattr(self, "host_filter") and self.host_filter is not None:
            host_selected = self._ascii_safe(
                str(self.host_filter.getSelectedItem()), lower=True
            ).strip()
            if host_selected and host_selected != "all":
                preferred_host = host_selected
    except Exception as e:
        self._callbacks.printError(
            "OpenAPI base host selection error: {}".format(self._ascii_safe(e))
        )
        preferred_host = ""

    if not preferred_host:
        with self.lock:
            host_counts = {}
            for entries in self.api_data.values():
                host = self._ascii_safe(self._get_entry(entries).get("host") or "", lower=True).strip()
                if host:
                    host_counts[host] = host_counts.get(host, 0) + 1
        if host_counts:
            preferred_host = sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]

    if preferred_host:
        return "https://{}".format(preferred_host)
    return "https://example.com"

def _run_openapi_drift(self, event):
    """Compare observed traffic with OpenAPI spec and report drift."""
    spec_source = self.openapi_spec_field.getText().strip()
    if not spec_source:
        selected = self._autoselect_openapi_spec_from_history(
            append_output=False, overwrite=False
        )
        spec_source = self.openapi_spec_field.getText().strip()
        if selected:
            self.openapi_area.setText(
                "[+] Auto-selected OpenAPI target from proxy history: {}\n".format(
                    spec_source
                )
            )
        else:
            self.openapi_area.setText("[!] Select OpenAPI/Swagger file or URL first\n")
            return
    if not self.api_data:
        self.openapi_area.setText("[!] No endpoints captured. Capture/import first.\n")
        return

    self.openapi_area.setText("[*] OpenAPI drift analysis starting...\n")
    self.openapi_area.append("[*] Source: {}\n\n".format(spec_source))
    self._clear_tool_cancel("openapidrift")

    def run_drift():
        try:
            text = self._load_openapi_spec_text(spec_source)
            if self._is_tool_cancelled("openapidrift"):
                return

            parsed = None
            parse_error = None
            try:
                doc = json.loads(text)
                parsed = self._parse_openapi_json_doc(doc)
            except Exception as json_err:
                parse_error = self._ascii_safe(json_err)

            if parsed is None:
                parsed = self._parse_openapi_yaml_text(text)
            spec_endpoints, spec_params_map, server_urls = parsed

            with self.lock:
                observed_snapshot = dict(self.api_data)
            observed_endpoints = set(observed_snapshot.keys())
            observed_params_map = {}
            for endpoint_key, entries in observed_snapshot.items():
                entry = self._get_entry(entries)
                param_names = set()
                params = entry.get("parameters", {}) or {}
                for ptype in ["url", "body", "json", "cookie"]:
                    values = params.get(ptype, {})
                    if isinstance(values, dict):
                        for name in values.keys():
                            safe_name = self._ascii_safe(name).strip()
                            if safe_name:
                                param_names.add(safe_name)
                    elif isinstance(values, list):
                        for name in values:
                            safe_name = self._ascii_safe(name).strip()
                            if safe_name:
                                param_names.add(safe_name)
                observed_params_map[endpoint_key] = sorted(param_names)

            undocumented_observed = sorted(observed_endpoints - spec_endpoints)
            missing_observed = sorted(spec_endpoints - observed_endpoints)
            shared = sorted(observed_endpoints & spec_endpoints)
            param_drift = []
            for endpoint_key in shared:
                spec_params = set(spec_params_map.get(endpoint_key, []) or [])
                if not spec_params:
                    continue
                observed_params = set(observed_params_map.get(endpoint_key, []) or [])
                unexpected = sorted(observed_params - spec_params)
                missing_params = sorted(spec_params - observed_params)
                if unexpected or missing_params:
                    detail = "{} | unexpected={} | missing={}".format(
                        endpoint_key,
                        ",".join(unexpected[:6]) if unexpected else "-",
                        ",".join(missing_params[:6]) if missing_params else "-",
                    )
                    param_drift.append(detail)

            base_url = self._choose_openapi_base_url(server_urls)
            missing_candidates = []
            for endpoint_key in missing_observed:
                if ":" not in endpoint_key:
                    continue
                method, normalized_path = endpoint_key.split(":", 1)
                path = self._ascii_safe(normalized_path).replace("{id}", "1")
                if not path.startswith("/"):
                    path = "/" + path
                missing_candidates.append(
                    {"method": method, "url": base_url + path, "endpoint_key": endpoint_key}
                )

            lines = []
            lines.append("=" * 80)
            lines.append("OPENAPI DRIFT RESULTS")
            lines.append("=" * 80)
            lines.append("[*] Spec Endpoints: {}".format(len(spec_endpoints)))
            lines.append("[*] Observed Endpoints: {}".format(len(observed_endpoints)))
            lines.append("[*] Observed not in spec: {}".format(len(undocumented_observed)))
            lines.append("[*] Spec missing in observed: {}".format(len(missing_observed)))
            lines.append("[*] Shared Endpoints: {}".format(len(shared)))
            lines.append("[*] Param Drift Findings: {}".format(len(param_drift)))
            if parse_error:
                lines.append("[*] JSON parse fallback used (YAML mode): {}".format(parse_error))
            lines.append("")
            lines.append("UNDOCUMENTED OBSERVED ENDPOINTS")
            lines.append("-" * 80)
            lines.extend(undocumented_observed[:80] if undocumented_observed else ["[+] None"])
            if len(undocumented_observed) > 80:
                lines.append("[*] {} more not shown".format(len(undocumented_observed) - 80))
            lines.append("")
            lines.append("SPEC ENDPOINTS MISSING IN OBSERVED TRAFFIC")
            lines.append("-" * 80)
            lines.extend(missing_observed[:80] if missing_observed else ["[+] None"])
            if len(missing_observed) > 80:
                lines.append("[*] {} more not shown".format(len(missing_observed) - 80))
            lines.append("")
            lines.append("PARAMETER DRIFT")
            lines.append("-" * 80)
            lines.extend(param_drift[:80] if param_drift else ["[+] None"])
            if len(param_drift) > 80:
                lines.append("[*] {} more not shown".format(len(param_drift) - 80))

            with self.openapi_lock:
                self.openapi_drift_results = list(lines)
                self.openapi_missing_candidates = list(missing_candidates)

            if self._is_tool_cancelled("openapidrift"):
                return
            SwingUtilities.invokeLater(
                lambda t="\n".join(lines) + "\n": self.openapi_area.setText(t)
            )
            SwingUtilities.invokeLater(
                lambda: self.log_to_ui(
                    "[+] OpenAPI drift complete: undocumented={} missing={} param-drift={}".format(
                        len(undocumented_observed),
                        len(missing_observed),
                        len(param_drift),
                    )
                )
            )
        except Exception as e:
            SwingUtilities.invokeLater(
                lambda m=self._ascii_safe(e): self.openapi_area.append(
                    "[!] OpenAPI drift failed: {}\n".format(m)
                )
            )
            SwingUtilities.invokeLater(
                lambda m=self._ascii_safe(e): self.log_to_ui(
                    "[!] OpenAPI drift error: {}".format(m)
                )
            )
        finally:
            self._clear_tool_cancel("openapidrift")

    worker = threading.Thread(target=run_drift)
    worker.daemon = True
    worker.start()

def _export_openapi_drift_results(self):
    """Export OpenAPI drift analysis output."""
    with self.openapi_lock:
        data = list(self.openapi_drift_results)
    self._export_list_to_file(
        data, "OpenAPI_Drift_Export", self.openapi_area, "openapi drift lines"
    )

def _send_openapi_to_recon(self):
    """Send missing spec endpoints to Recon for active probing."""
    with self.openapi_lock:
        candidates = list(self.openapi_missing_candidates)
    if not candidates:
        self.openapi_area.append("\n[!] No missing spec endpoints to send\n")
        return
    self._import_endpoint_candidates_to_recon(
        candidates, "openapi-drift", self.openapi_area
    )

def _export_katana_results(self):
    """Export Katana discovered endpoints - only saves when user clicks Export"""
    with self.katana_lock:
        data = list(self.katana_discovered)
    self._export_list_to_file(
        data, "Katana_Export", self.katana_area, "discovered URLs"
    )

def _import_katana_to_recon(self):
    """Import Katana discovered endpoints to Recon tab"""
    with self.katana_lock:
        urls = list(self.katana_discovered)
    if not urls:
        self.katana_area.append(
            "\n[!] No discovered endpoints. Run crawler first\n"
        )
        return

    imported = 0
    for url in urls:
        try:
            # Ensure URL has protocol
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url

            parsed = URL(url)
            method = "GET"
            path = parsed.getPath() or "/"
            normalized = self._normalize_path(path)
            key = "{}:{}".format(method, normalized)

            with self.lock:
                if key not in self.api_data:
                    protocol = parsed.getProtocol() or "http"
                    port = parsed.getPort()
                    if port == -1:
                        port = 443 if protocol == "https" else 80

                    entry = {
                        "method": method,
                        "path": path,
                        "normalized_path": normalized,
                        "host": parsed.getHost(),
                        "protocol": protocol,
                        "port": port,
                        "query_string": parsed.getQuery() or "",
                        "parameters": {
                            "url": {},
                            "body": {},
                            "cookie": {},
                            "json": {},
                        },
                        "headers": {},
                        "request_body": "",
                        "response_status": 200,
                        "response_headers": {},
                        "response_body": "",
                        "response_length": 0,
                        "response_time_ms": 0,
                        "content_type": "unknown",
                        "auth_detected": ["None"],
                        "api_patterns": ["Discovered"],
                        "jwt_detected": None,
                        "encryption_indicators": {
                            "likely_encrypted": False,
                            "types": [],
                        },
                        "param_patterns": {"reflected": [], "param_types": {}},
                    }
                    self.api_data[key] = [entry]
                    self.endpoint_tags[key] = ["katana"]
                    self.endpoint_times[key] = [0]
                    imported += 1
        except Exception as e:
            self._callbacks.printError(
                "Error importing Katana URL: {}".format(str(e))
            )

    self.katana_area.append(
        "\n[+] Imported {} new endpoints to Recon tab\n".format(imported)
    )
    self.log_to_ui("[+] Imported {} Katana endpoints".format(imported))
    SwingUtilities.invokeLater(
        lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
    )
    SwingUtilities.invokeLater(lambda: self._update_host_filter())
    SwingUtilities.invokeLater(lambda: self._update_stats())
    SwingUtilities.invokeLater(lambda: self.refresh_view())

def _collect_katana_seed_urls(self):
    """Collect scoped Katana seed URLs from first-party Recon hosts."""
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
            self._callbacks.printError("Katana host-filter read error: {}".format(str(e)))
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
    inspected_entries = 0
    candidates = {}
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

        clean_url = self._clean_url(self._build_url(entry, False))
        if not clean_url:
            continue
        score = 1
        normalized_path = self._ascii_safe(
            entry.get("normalized_path") or "/", lower=True
        )
        if "/api/" in normalized_path or "/graphql" in normalized_path:
            score += 3
        if normalized_path.startswith("/v1") or normalized_path.startswith("/v2"):
            score += 2
        previous = candidates.get(clean_url)
        if previous is None or score > previous:
            candidates[clean_url] = score

    ordered = sorted(candidates.items(), key=lambda item: (-item[1], item[0]))
    raw_candidates = len(ordered)
    truncated = 0
    if raw_candidates > self.KATANA_MAX_TARGETS:
        truncated = raw_candidates - self.KATANA_MAX_TARGETS
        ordered = ordered[: self.KATANA_MAX_TARGETS]

    seeds = [url for url, _ in ordered]
    meta = {
        "inspected_entries": inspected_entries,
        "raw_candidates": raw_candidates,
        "dropped_noise_host": dropped_noise_host,
        "dropped_scope_host": dropped_scope_host,
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
    return seeds, meta

def _katana_result_in_scope(self, url, target_meta):
    """Keep Katana output focused on scoped first-party hosts."""
    text = self._ascii_safe(url).strip()
    if not text.lower().startswith(("http://", "https://")):
        return False
    try:
        parsed = URL(text)
        host = self._ascii_safe(parsed.getHost(), lower=True).strip()
    except Exception as e:
        self._callbacks.printError("Katana result parse error: {}".format(str(e)))
        return False
    if not host:
        return False

    if target_meta.get("force_host"):
        return host == target_meta.get("selected_host")

    if target_meta.get("manual_scope_enabled"):
        allowed_bases = set(target_meta.get("allowed_bases", []))
        if not allowed_bases:
            return True
        return self._infer_base_domain(host) in allowed_bases

    if self._ffuf_is_noise_host(host):
        return False
    allowed_bases = set(target_meta.get("allowed_bases", []))
    if not allowed_bases:
        return True
    return self._infer_base_domain(host) in allowed_bases

def _run_katana(self, event):
    """Run Katana crawler on discovered domains"""
    return heavy_runners._run_katana(self, event)

def _export_ffuf_results(self):
    """Export FFUF discovered paths - only saves when user clicks Export"""
    with self.ffuf_lock:
        data = list(self.ffuf_results)
    self._export_list_to_file(data, "FFUF_Export", self.ffuf_area, "results")

def _send_ffuf_to_intruder(self):
    """Send FFUF results to Burp Intruder"""
    with self.ffuf_lock:
        results = list(self.ffuf_results)
    if not results:
        self.ffuf_area.append("\n[!] No results. Run fuzzer first\n")
        return

    self.ffuf_area.append("\n" + "=" * 80 + "\n")
    self.ffuf_area.append("[*] Sending to Burp Intruder...\n")

    try:
        sent = 0
        for result in results[:10]:
            parts = result.split()
            if len(parts) < 1:
                continue

            # Try to find URL in FFUF output line
            url = None
            for part in parts:
                if part.startswith("http://") or part.startswith("https://"):
                    url = part
                    break

            if not url:
                continue

            parsed = URL(url)
            request = "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n".format(
                parsed.getPath(), parsed.getHost()
            )

            self._callbacks.sendToIntruder(
                parsed.getHost(),
                (
                    parsed.getPort()
                    if parsed.getPort() != -1
                    else (443 if parsed.getProtocol() == "https" else 80)
                ),
                parsed.getProtocol() == "https",
                self._helpers.stringToBytes(request),
            )
            sent += 1

        self.ffuf_area.append("[+] Sent {} requests to Intruder\n".format(sent))
        self.log_to_ui("[+] Sent {} FFUF results to Intruder".format(sent))
    except Exception as e:
        self.ffuf_area.append("[!] Error: {}\n".format(str(e)))
        self.log_to_ui("[!] FFUF Intruder error: {}".format(str(e)))

def _infer_base_domain(self, host):
    """Infer coarse base domain without external dependencies."""
    text = self._ascii_safe(host, lower=True).strip()
    if not text:
        return ""
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text):
        return text
    parts = [p for p in text.split(".") if p]
    if len(parts) < 2:
        return text
    second_level = parts[-2]
    if len(parts) >= 3 and second_level in ["co", "com", "org", "net", "gov", "edu", "ac"]:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def _ffuf_is_noise_host(self, host):
    """Detect common third-party/tracker/CDN hosts to avoid FFUF noise."""
    text = self._ascii_safe(host, lower=True).strip()
    if not text:
        return True
    return any(pattern in text for pattern in self.FFUF_NOISE_HOST_PATTERNS)

def _is_wayback_noise_host(self, host):
    """Wayback-specific host noise filter (adtech/tracker heavy domains)."""
    text = self._ascii_safe(host, lower=True).strip()
    if not text:
        return True
    if self._ffuf_is_noise_host(text):
        return True
    if any(pattern in text for pattern in self.WAYBACK_NOISE_HOST_PATTERNS):
        return True
    labels = [label for label in text.split(".") if label]
    if not labels:
        return True
    first_label = labels[0]
    if first_label in self.WAYBACK_NOISE_LABELS:
        return True
    if any(label.endswith("ads") or label.startswith("ads") for label in labels[:2]):
        return True
    return False

def _ffuf_is_noise_path_segment(self, first_part):
    """Detect noisy/static-like first path segment for FFUF targeting."""
    seg = self._ascii_safe(first_part, lower=True).strip()
    if not seg:
        return True
    if any(noise in seg for noise in self.FFUF_NOISE_PATH_PARTS):
        return True
    if "{" in seg or "}" in seg:
        return True
    return False

def _collect_ffuf_targets(self):
    return jython_size_helpers.collect_ffuf_targets(self)

def _run_ffuf(self, event):
    """Run FFUF fuzzer on discovered endpoints"""
    return heavy_runners._run_ffuf(self, event)

def _collect_wayback_queries(self):
    return jython_size_helpers.collect_wayback_queries(self)

def _run_wayback(self):
    """Discover historical endpoints using Wayback Machine API"""
    return heavy_runners._run_wayback(self)

def _export_wayback_results(self):
    """Export Wayback discovered snapshots to JSON, TXT, and endpoints list"""
    import os

    with self.wayback_lock:
        data = list(self.wayback_discovered)

    if not data:
        self.wayback_area.append("\n[!] No snapshots to export\n")
        return

    export_dir = self._get_export_dir("Wayback_Export")
    if not export_dir:
        return

    json_file = os.path.join(export_dir, "wayback_results.json")
    txt_file = os.path.join(export_dir, "wayback_urls.txt")
    endpoints_file = os.path.join(export_dir, "discovered_endpoints.txt")

    # Parse and structure data
    structured = []
    unique_endpoints = set()
    for entry in data:
        parts = entry.split(" | ")
        if len(parts) >= 3:
            original_url = parts[0]
            structured.append({
                "original_url": original_url,
                "archive_url": parts[1],
                "timestamp": parts[2],
                "score": self._score_wayback_url(original_url)
            })
            # Extract unique endpoint
            try:
                if not original_url.startswith("http"):
                    original_url = "http://" + original_url
                parsed = URL(original_url)
                endpoint = "{}://{}{}".format(parsed.getProtocol(), parsed.getHost(), parsed.getPath() or "/")
                if parsed.getQuery():
                    endpoint += "?" + parsed.getQuery()
                unique_endpoints.add(endpoint)
            except Exception as e:
                self._callbacks.printError(
                    "Wayback export endpoint parse error: {}".format(str(e))
                )

    structured.sort(key=lambda x: x["score"], reverse=True)

    export_data = {
        "metadata": {
            "total_snapshots": len(structured),
            "unique_endpoints": len(unique_endpoints),
            "api_endpoints": sum(1 for s in structured if s["score"] >= 10),
            "export_time": SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())
        },
        "snapshots": structured,
        "unique_endpoints": sorted(unique_endpoints)
    }

    writer = None
    try:
        writer = FileWriter(json_file)
        writer.write(json.dumps(export_data, indent=2))
        writer.close()

        writer = FileWriter(txt_file)
        for item in structured:
            writer.write(item["original_url"] + "\n")
        writer.close()

        writer = FileWriter(endpoints_file)
        filtered_endpoints = []
        for endpoint in sorted(unique_endpoints):
            ep_lower = endpoint.lower()
            # Filter useful API endpoints only
            if any(pattern in ep_lower for pattern in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']):
                # Skip noise
                if not any(noise in ep_lower for noise in ['?q=', '?rdt=', '/r/$', 'search', 'query']):
                    filtered_endpoints.append(endpoint)
                    writer.write(endpoint + "\n")
        writer.close()
        
        # Update metadata
        export_data["metadata"]["filtered_endpoints"] = len(filtered_endpoints)

        filtered_count = export_data["metadata"].get("filtered_endpoints", 0)
        self.wayback_area.append("\n[+] Exported {} snapshots\n".format(len(data)))
        self.wayback_area.append("[+] Unique Endpoints: {}\n".format(len(unique_endpoints)))
        self.wayback_area.append("[+] Filtered API Endpoints: {}\n".format(filtered_count))
        self.wayback_area.append("[+] JSON: {}\n".format(json_file))
        self.wayback_area.append("[+] URLs: {}\n".format(txt_file))
        self.wayback_area.append("[+] Endpoints: {}\n".format(endpoints_file))
        self.wayback_area.append("[+] Folder: {}\n".format(export_dir))
        self.log_to_ui("[+] Wayback export: {} endpoints".format(len(unique_endpoints)))
    except Exception as e:
        self.wayback_area.append("\n[!] Export failed: {}\n".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as close_err:
                self._callbacks.printError(
                    "Error closing wayback export file: {}".format(str(close_err))
                )

def _score_wayback_url(self, url):
    """Score URL by relevance for prioritization"""
    score = 0
    url_lower = url.lower()
    if '/api/' in url_lower:
        score += 10
    if any(v in url_lower for v in ['/v1/', '/v2/', '/v3/']):
        score += 5
    if any(ext in url_lower for ext in ['.js', '.css', '.png', '.jpg']):
        score -= 5
    return score

__all__ = [
    "_stop_asset_discovery",
    "_stop_openapi_drift",
    "_stop_graphql",
    "_stop_auth_replay",
    "_parse_auth_profile_header",
    "_get_auth_profile_field",
    "_extract_endpoint_key_from_recon_value",
    "_get_recon_view_key",
    "_recon_selected_indices",
    "_get_recon_selected_index",
    "_get_selected_endpoint_key",
    "_recon_set_detail_redirect_text",
    "_recon_show_selected_endpoint_detail",
    "_show_selected_recon_endpoint_details",
    "_entry_matches_profile_hint",
    "_extract_profile_header_candidates_from_headers",
    "_extract_profile_header_from_headers",
    "_find_profile_header_candidates_in_entries",
    "_build_auth_header_choice_label",
    "_choose_auth_profile_header_candidate",
    "_parse_comma_newline_values",
    "_show_multi_select_targets_popup",
    "_extract_auth_profile_header",
    "_build_auth_replay_request",
    "_perform_auth_replay_request",
    "_auth_replay_preview_similar",
    "_parse_auth_replay_status_codes",
    "_compile_optional_regex",
    "_auth_replay_detector_for_role",
    "_auth_replay_response_is_enforced",
    "_evaluate_auth_replay_findings",
    "_collect_auth_replay_targets",
    "_run_auth_replay",
    "_run_passive_discovery",
    "_run_sequence_invariants",
    "_build_sequence_invariant_package",
    "_build_golden_ticket_package",
    "_build_state_transition_package",
    "_sort_and_store_sequence_invariant_payload",
    "_sort_and_store_golden_ticket_payload",
    "_sort_and_store_state_transition_payload",
    "_format_sequence_invariant_output",
    "_format_golden_ticket_output",
    "_format_state_transition_output",
    "_collect_passive_snapshot",
    "_build_passive_filter_config",
    "_passive_entry_is_api_like",
    "_passive_entry_allowed",
    "_run_passive_mode_handlers",
    "_sort_and_store_passive_findings",
    "_passive_discover_api5",
    "_passive_discover_api3",
    "_entry_param_names_lower",
    "_entry_header_names_lower",
    "_entry_limit_values",
    "_passive_discover_api4",
    "_passive_discover_api6",
    "_passive_discover_api10",
    "_passive_context_json_fields",
    "_passive_discover_api9",
    "_passive_union_json_fields",
    "_has_success_response",
    "_passive_auth_fingerprint",
    "_passive_jwt_identity",
    "_passive_body_signature",
    "_parse_json_loose",
    "_flatten_json_paths",
    "_field_is_sensitive",
    "_extract_version_segment",
    "_strip_version_segment",
    "_parse_version_value",
    "_format_passive_discovery_output",
    "_export_passive_discovery_results",
    "_export_sequence_invariant_ledger",
    "_normalize_wayback_entry",
    "_run_httpx",
    "_export_list_to_file",
    "_parse_positive_int",
    "_collect_verify_targets",
    "_extract_sqlmap_evidence",
    "_extract_dalfox_evidence",
    "_import_endpoint_candidates_to_recon",
    "_run_sqlmap_verify",
    "_export_sqlmap_results",
    "_send_sqlmap_to_recon",
    "_run_dalfox_verify",
    "_export_dalfox_results",
    "_send_dalfox_to_recon",
    "_collect_asset_domain_candidates",
    "_autopopulate_asset_domains_from_history",
    "_show_asset_targets_popup",
    "_extract_domains_for_asset_discovery",
    "_run_command_stage",
    "_run_api_asset_discovery",
    "_export_asset_discovery_results",
    "_send_asset_discovery_to_recon",
    "_browse_openapi_spec_file",
    "_openapi_spec_candidate_score",
    "_collect_openapi_spec_candidates",
    "_show_openapi_spec_targets_popup",
    "_autoselect_openapi_spec_from_history",
    "_detect_openapi_spec_from_history",
    "_normalize_spec_path",
    "_load_openapi_spec_text",
    "_parse_openapi_json_doc",
    "_parse_openapi_yaml_text",
    "_choose_openapi_base_url",
    "_run_openapi_drift",
    "_export_openapi_drift_results",
    "_send_openapi_to_recon",
    "_export_katana_results",
    "_import_katana_to_recon",
    "_collect_katana_seed_urls",
    "_katana_result_in_scope",
    "_run_katana",
    "_export_ffuf_results",
    "_send_ffuf_to_intruder",
    "_infer_base_domain",
    "_ffuf_is_noise_host",
    "_is_wayback_noise_host",
    "_ffuf_is_noise_path_segment",
    "_collect_ffuf_targets",
    "_run_ffuf",
    "_collect_wayback_queries",
    "_run_wayback",
    "_export_wayback_results",
    "_score_wayback_url",
]
