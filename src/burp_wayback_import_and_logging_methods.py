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
    SwingUtilities.invokeLater(
        lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
    )
    SwingUtilities.invokeLater(lambda: self._update_host_filter())
    SwingUtilities.invokeLater(lambda: self._update_stats())
    SwingUtilities.invokeLater(lambda: self.refresh_view())

def log_to_ui(self, message):
    timestamp = SimpleDateFormat("HH:mm:ss").format(Date())
    timestamped = "[{}] {}".format(timestamp, message)
    self._callbacks.printOutput(timestamped)
    SwingUtilities.invokeLater(lambda: self._append_log(timestamped))

def _append_log(self, message):
    self.log_area.append(message + "\n")
    self.log_area.setCaretPosition(self.log_area.getDocument().getLength())

__all__ = [
    "_import_wayback_to_recon",
    "log_to_ui",
    "_append_log",
]
