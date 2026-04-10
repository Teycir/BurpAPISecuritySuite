# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Wayback-to-Recon import flow and shared UI logging helpers."""
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

def _import_wayback_to_recon(self):
    """Send Wayback snapshots to Recon tab"""
    with self.wayback_lock:
        snapshots = list(self.wayback_discovered)
    if not snapshots:
        self.wayback_area.append(
            "\n[!] No snapshots discovered. Run discovery first\n"
        )
        return

    self.wayback_area.append("\n[*] Sending snapshots to Recon tab...\n")
    imported = 0
    skipped = 0
    for snapshot in snapshots:
        try:
            parts = snapshot.split(" | ")
            if len(parts) < 1:
                continue
            original_url = parts[0]

            # Ensure URL has protocol
            if not original_url.startswith(
                "http://"
            ) and not original_url.startswith("https://"):
                original_url = "http://" + original_url

            parsed = URL(original_url)
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
                        "api_patterns": ["Wayback"],
                        "jwt_detected": None,
                        "encryption_indicators": {
                            "likely_encrypted": False,
                            "types": [],
                        },
                        "param_patterns": {"reflected": [], "param_types": {}},
                    }
                    self.api_data[key] = [entry]
                    self.endpoint_tags[key] = ["wayback", "historical"]
                    self.endpoint_times[key] = [0]
                    imported += 1
                else:
                    skipped += 1
        except Exception as e:
            self._callbacks.printError(
                "Error importing Wayback URL: {}".format(str(e))
            )

    summary = "\n" + "=" * 60 + "\n"
    summary += "IMPORT COMPLETE\n"
    summary += "=" * 60 + "\n"
    summary += "[+] New Endpoints: {}\n".format(imported)
    summary += "[+] Skipped (duplicates): {}\n".format(skipped)
    summary += "[+] Total Processed: {}\n".format(len(snapshots))
    summary += "=" * 60 + "\n"

    self.wayback_area.append(summary)
    self.log_to_ui("[+] Wayback: {} new, {} skipped".format(imported, skipped))
    self._schedule_capture_ui_refresh(force=True)

def log_to_ui(self, message):
    timestamp = SimpleDateFormat("HH:mm:ss").format(Date())
    timestamped = "[{}] {}".format(timestamp, message)
    self._callbacks.printOutput(timestamped)
    if not hasattr(self, "_ui_log_lock"):
        self._ui_log_lock = threading.Lock()
    if not hasattr(self, "_ui_log_buffer"):
        self._ui_log_buffer = []
    if not hasattr(self, "_ui_log_flush_delay_ms"):
        self._ui_log_flush_delay_ms = 700
    if not hasattr(self, "_ui_log_max_lines"):
        self._ui_log_max_lines = int(
            getattr(self, "logger_max_rows", 10000) or 10000
        )

    with self._ui_log_lock:
        self._ui_log_buffer.append(timestamped)
        existing_timer = getattr(self, "_ui_log_flush_timer", None)
        if existing_timer is not None:
            try:
                existing_timer.cancel()
            except Exception as cancel_err:
                self._callbacks.printError(
                    "UI log timer cancel error: {}".format(str(cancel_err))
                )

        def _queue_flush():
            with self._ui_log_lock:
                self._ui_log_flush_timer = None
            SwingUtilities.invokeLater(lambda: self._flush_ui_log_buffer())

        timer = threading.Timer(
            float(self._ui_log_flush_delay_ms) / 1000.0, _queue_flush
        )
        timer.daemon = True
        self._ui_log_flush_timer = timer
        timer.start()

def _flush_ui_log_buffer(self):
    if getattr(self, "log_area", None) is None:
        return
    with self._ui_log_lock:
        pending = list(getattr(self, "_ui_log_buffer", []) or [])
        self._ui_log_buffer = []
    if not pending:
        return
    self._append_log("\n".join(pending))

def _append_log(self, message):
    if not message:
        return
    payload = self._ascii_safe(message)
    if not payload.endswith("\n"):
        payload += "\n"
    self.log_area.append(payload)
    max_lines = int(
        getattr(
            self,
            "_ui_log_max_lines",
            int(getattr(self, "logger_max_rows", 10000) or 10000),
        )
        or 0
    )
    if max_lines <= 0:
        max_lines = int(getattr(self, "logger_max_rows", 10000) or 10000)
    if max_lines <= 0:
        max_lines = 1
    line_count = int(self.log_area.getLineCount() or 0)
    if line_count > max_lines:
        trim_lines = line_count - max_lines
        try:
            trim_offset = int(self.log_area.getLineEndOffset(trim_lines - 1))
            self.log_area.replaceRange("", 0, trim_offset)
        except Exception as trim_err:
            self._callbacks.printError(
                "UI log trim error: {}".format(str(trim_err))
            )
    self.log_area.setCaretPosition(self.log_area.getDocument().getLength())

__all__ = [
    "_import_wayback_to_recon",
    "log_to_ui",
    "_flush_ui_log_buffer",
    "_append_log",
]
