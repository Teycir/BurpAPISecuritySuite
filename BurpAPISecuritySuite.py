# -*- coding: utf-8 -*-
# pylint: disable=import-error
import json
import os
import re
import shlex
import sys
import threading
import time

def _discover_root_dir():
    """Resolve extension root dir even when __file__ is missing in Burp/Jython."""
    candidates = []
    file_value = globals().get("__file__")
    if file_value:
        candidates.append(file_value)

    frame_getter = getattr(sys, "_getframe", None)
    if frame_getter is not None:
        frame_file = frame_getter(0).f_code.co_filename
        if frame_file:
            candidates.append(frame_file)

    argv = getattr(sys, "argv", None) or []
    if len(argv) > 0 and argv[0]:
        candidates.append(argv[0])

    for entry in (getattr(sys, "path", None) or []):
        if entry:
            candidates.append(entry)

    seen = set()
    for candidate in candidates:
        abs_path = os.path.abspath(candidate)
        root = abs_path if os.path.isdir(abs_path) else os.path.dirname(abs_path)
        root = os.path.abspath(root or ".")
        if (not root) or (root in seen):
            continue
        seen.add(root)
        if os.path.isfile(os.path.join(root, "BurpAPISecuritySuite.py")):
            return root
        if os.path.isdir(os.path.join(root, "src")):
            return root

    raise RuntimeError(
        "Could not resolve extension root directory from candidates: {}".format(
            repr(candidates[:12])
        )
    )

_ROOT_DIR = _discover_root_dir()
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
if os.path.isdir(_SRC_DIR) and (_SRC_DIR not in sys.path):
    sys.path.insert(0, _SRC_DIR)

import ai_prep_layer
import behavior_analysis
import heavy_runners
import jython_size_helpers
import recon_param_intel

from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IProxyListener, ITab
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


class SearchListener(DocumentListener):
    def __init__(self, extender, delay_ms=300):
        self.extender = extender
        self.timer = None
        self.delay_ms = delay_ms

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
            lambda: SwingUtilities.invokeLater(self.extender.refresh_view),
        )
        self.timer.daemon = True
        self.timer.start()


class BurpExtender(
    IBurpExtender, ITab, IHttpListener, IProxyListener, IContextMenuFactory
):
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_JSON = 6
    AI_PREP_LAYER_ENV_VAR = "AI_PREP_LAYER"
    AI_PREP_LAYER_DEFAULT_ENABLED = True

    # Pre-compiled regex patterns for performance
    NUMERIC_ID_PATTERN = re.compile(r"/\d+")
    UUID_PATTERN = re.compile(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE
    )
    OBJECTID_PATTERN = re.compile(r"/[0-9a-f]{24}")
    BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    HEX_PATTERN = re.compile(r"[0-9a-fA-F]{32,}")
    ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[mK]")
    PASSIVE_ADMIN_PATH_PATTERN = re.compile(
        r"/(admin|internal|manage|role|roles|permission|permissions|billing|finance|staff|config|debug)(/|$)",
        re.IGNORECASE,
    )
    PASSIVE_RESOURCE_PATH_PATTERN = re.compile(
        r"/(search|list|export|report|download|upload|bulk|import|sync|query|graphql|analytics|history)(/|$)",
        re.IGNORECASE,
    )
    PASSIVE_FLOW_PATH_PATTERN = re.compile(
        r"/(checkout|payment|payout|transfer|withdraw|redeem|coupon|order|purchase|refund|approve|mfa|verify|reset|invite|subscription|billing)(/|$)",
        re.IGNORECASE,
    )
    PASSIVE_WEBHOOK_PATH_PATTERN = re.compile(
        r"/(webhook|callback|integration|notify)(/|$)",
        re.IGNORECASE,
    )
    PASSIVE_VERSION_SEGMENT_PATTERN = re.compile(r"/(v\d+(?:\.\d+)?)(?=/|$)", re.IGNORECASE)
    PASSIVE_LIMIT_QUERY_PATTERN = re.compile(
        r"(?:^|&)(?:limit|page_size|pagesize|max|size)=([0-9]{1,7})(?:&|$)",
        re.IGNORECASE,
    )
    PASSIVE_CALLBACK_PARAM_KEYWORDS = (
        "url",
        "uri",
        "link",
        "target",
        "dest",
        "destination",
        "callback",
        "redirect",
        "return",
        "next",
        "webhook",
        "endpoint",
        "proxy",
        "source",
        "image",
        "avatar",
        "file",
    )
    PASSIVE_SIGNATURE_HEADER_HINTS = (
        "x-signature",
        "x-hub-signature",
        "x-hub-signature-256",
        "stripe-signature",
        "x-webhook-signature",
        "x-slack-signature",
        "x-twilio-signature",
    )
    PASSIVE_UPSTREAM_ERROR_HINTS = (
        "upstream",
        "econnrefused",
        "etimedout",
        "timed out",
        "connection refused",
        "socket hang up",
        "certificate verify failed",
        "unable to resolve host",
        "dns",
    )
    PASSIVE_SENSITIVE_FIELD_KEYWORDS = (
        "ssn",
        "social",
        "dob",
        "birth",
        "salary",
        "wage",
        "tax",
        "passport",
        "national",
        "identity",
        "iban",
        "bank",
        "account",
        "credit",
        "card",
        "cvv",
        "email",
        "phone",
        "address",
        "location",
        "token",
        "secret",
        "password",
    )
    PASSIVE_STATIC_EXTENSIONS = (
        ".js",
        ".mjs",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp4",
        ".webm",
        ".avi",
        ".mov",
        ".pdf",
    )
    PASSIVE_STATIC_PATH_PARTS = (
        "js",
        "css",
        "static",
        "dist",
        "assets",
        "images",
        "img",
        "fonts",
        "sdk",
        "library",
        "safeframe",
        "gtag",
        "gtm",
        "pagead",
        "analytics",
        "ads",
        "sodar",
        "prebid",
        "rtv",
    )
    PASSIVE_API_PATTERN_HINTS = (
        "rest api",
        "graphql",
        "json api",
        "xml api",
    )
    FUZZER_STATIC_PATH_PARTS = PASSIVE_STATIC_PATH_PARTS + (
        "xjs",
        "pixels",
        "pixel",
        "sync",
        "usersync",
        "user-sync",
        "cookie-sync",
        "cookie_sync",
        "rmkt",
        "tr",
        "ac",
    )
    FUZZER_STRICT_NOISE_PATH_MARKERS = (
        "/cdn-cgi",
        "/__cf_chl_",
        "/captcha",
        "/recaptcha",
        "/sodar",
        "/_/js",
        "/_/tvty",
    )
    FUZZER_SQLI_PARAM_KEYWORDS = (
        "id",
        "user",
        "account",
        "email",
        "name",
        "search",
        "query",
        "q",
        "filter",
        "sort",
        "order",
        "where",
        "page",
        "limit",
        "offset",
    )
    FUZZER_SSRF_PARAM_KEYWORDS = (
        "url",
        "uri",
        "dest",
        "destination",
        "target",
        "redirect",
        "endpoint",
        "webhook",
        "proxy",
        "image",
        "file",
        "download",
        "fetch",
        "callback_url",
    )
    FUZZER_SSTI_PARAM_KEYWORDS = (
        "template",
        "tpl",
        "view",
        "render",
        "content",
        "message",
        "body",
        "subject",
        "html",
        "markdown",
        "text",
    )
    PARAM_MINER_NOISE_PATH_MARKERS = (
        "/openrtb",
        "/prebid",
        "/bidder",
        "/header-bidding",
        "/cookie-sync",
        "/cookie_sync",
        "/usersync",
        "/user-sync",
        "/pixel",
        "/collect",
        "/rum",
        "/sodar",
        "/pagead",
        "/adserver",
        "/sync",
    )
    PARAM_MINER_STRICT_NOISE_PATH_MARKERS = (
        "/cdn-cgi",
        "/__cf_chl_",
        "/captcha",
        "/recaptcha",
        "/sodar",
    )
    VERSION_SCANNER_NOISE_PATH_MARKERS = (
        "/cdn-cgi",
        "/__cf_chl_",
        "/captcha",
        "/recaptcha",
        "/sodar",
    )
    FFUF_NOISE_HOST_PATTERNS = (
        "google.com",
        "googletagmanager.com",
        "googleadservices.com",
        "doubleclick.net",
        "googlesyndication.com",
        "google-analytics.com",
        "googleusercontent.com",
        "gstatic.com",
        "recaptcha.net",
        "facebook.com",
        "fbcdn.net",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "cdn.",
        "cloudfront.net",
        "fastly.net",
        "akamai",
        "sentry.io",
        "segment.io",
        "datadog",
        "newrelic",
        "ad4m.at",
        "batch.com",
        "ampproject.org",
        "dailymotion.com",
        "dmcdn.net",
        "instagram.com",
        "cdninstagram.com",
        "youtube.com",
        "ytimg.com",
        "vimeo.com",
        "tiktok.com",
        "tiktokcdn.com",
    )
    WAYBACK_NOISE_HOST_PATTERNS = (
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "googletagmanager.com",
        "ad4m.at",
        "batch.com",
        "ampproject.org",
        "acuityplatform.com",
        "33across.com",
        "indexww.com",
        "liadm.com",
        "deepintent.com",
        "onetag-sys.com",
        "adnxs.com",
        "rubiconproject.com",
        "pubmatic.com",
        "outbrain.com",
        "criteo.com",
        "openx.net",
        "teads.tv",
        "smartadserver.com",
        "everesttech.net",
        "rfihub.com",
        "sharethis.com",
        "adform.net",
        "taboola.com",
        "bidswitch.net",
        "demdex.net",
        "casalemedia.com",
        "zemanta.com",
        "connatix.com",
        "id5-sync.com",
        "adscale.de",
        "semasio.net",
        "servenobid.com",
        "pbstck.com",
        "mediarithmics.com",
        "seedtag.com",
        "audion.fm",
        "aps.amazon-adsystem.com",
        "amazon-adsystem.com",
        "scorecardresearch.com",
        "adsrvr.org",
    )
    WAYBACK_NOISE_LABELS = (
        "ad",
        "ads",
        "sync",
        "pixel",
        "tracker",
        "tracking",
        "analytics",
        "metric",
        "metrics",
        "telemetry",
        "beacon",
        "tag",
        "tags",
        "prebid",
        "bid",
    )
    FFUF_NOISE_PATH_PARTS = (
        "pagead",
        "ads",
        "adservice",
        "analytics",
        "collect",
        "pixel",
        "beacon",
        "telemetry",
        "track",
        "gtm",
        "tag",
    )
    FFUF_MAX_TARGETS = 120
    FFUF_THREADS = 16
    FFUF_REQUEST_TIMEOUT_SECONDS = 8
    FFUF_RATE_LIMIT = 35
    FFUF_TARGET_TIMEOUT_SECONDS = 45
    NUCLEI_MAX_TARGETS = 800
    NUCLEI_REQUEST_TIMEOUT_SECONDS = 8
    NUCLEI_RETRIES = 1
    NUCLEI_RATE_LIMIT = 100
    NUCLEI_CONCURRENCY = 20
    NUCLEI_BULK_SIZE = 8
    NUCLEI_MAX_HOST_ERROR = 8
    NUCLEI_SCAN_STRATEGY = "host-spray"
    NUCLEI_MAX_SCAN_SECONDS = 900
    KATANA_MAX_TARGETS = 40
    WAYBACK_MAX_QUERIES = 160
    APIHUNTER_MAX_TARGETS = 220
    APIHUNTER_MAX_SCAN_SECONDS = 300
































































    # ============================================================================
    # PAYLOAD GENERATORS - NAVIGATION: Search "PAYLOAD GENERATORS" to jump here
    # ============================================================================
















    # ============================================================================
    # WAF BYPASS PAYLOADS - NAVIGATION: Search "WAF BYPASS" to jump here
    # ============================================================================






    # ============================================================================
    # DATA ACCESS HELPERS - NAVIGATION: Search "DATA ACCESS" to jump here
    # ============================================================================


    # ============================================================================
    # FUZZER CORE LOGIC - NAVIGATION: Search "FUZZER CORE" to jump here
    # ============================================================================





























    

    # Advanced WAF bypass techniques from waf_bypass_advanced.py











    # ============================================================================
    # UI INTEGRATION - NAVIGATION: Search "UI INTEGRATION" to jump here
    # ============================================================================








































































































































































































































































































































































class EndpointClickListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    @staticmethod
    def _extract_endpoint_key(value):
        if "x]" in value and not value.startswith("==="):
            parts = value.split("] ", 1)
            if len(parts) > 1:
                return parts[1].split(" @ ")[0]
        return None

    def mouseClicked(self, event):
        if event is None or event.isPopupTrigger():
            return
        endpoint_list = event.getSource()
        index = endpoint_list.locationToIndex(event.getPoint())
        if index >= 0:
            try:
                if not endpoint_list.isSelectedIndex(index):
                    endpoint_list.setSelectedIndex(index)
            except Exception as selection_err:
                self.extender._callbacks.printError(
                    "Recon click selection sync error: {}".format(str(selection_err))
                )
                endpoint_list.setSelectedIndex(index)

    def mousePressed(self, event):
        self._show_popup(event)

    def mouseReleased(self, event):
        self._show_popup(event)

    def _show_popup(self, event):
        if event.isPopupTrigger():
            endpoint_list = event.getSource()
            index = endpoint_list.locationToIndex(event.getPoint())
            if index >= 0:
                endpoint_list.setSelectedIndex(index)
                endpoint_key = None
                if hasattr(self.extender, "_get_recon_view_key"):
                    endpoint_key = self.extender._get_recon_view_key(index)
                if not endpoint_key:
                    value = str(endpoint_list.getModel().getElementAt(index))
                    if hasattr(self.extender, "_extract_endpoint_key_from_recon_value"):
                        endpoint_key = self.extender._extract_endpoint_key_from_recon_value(
                            value
                        )
                    else:
                        endpoint_key = self._extract_endpoint_key(value)
                if endpoint_key:
                    popup = JPopupMenu()
                    detail_item = JMenuItem("Show Detail (Logger)")
                    detail_item.addActionListener(
                        lambda e: self.extender._recon_show_selected_in_logger()
                    )
                    popup.add(detail_item)
                    repeater_item = JMenuItem("Send to Repeater")
                    repeater_item.addActionListener(
                        lambda e: self.extender._send_endpoint_to_repeater(endpoint_key)
                    )
                    popup.add(repeater_item)
                    turbo_item = JMenuItem("Export Turbo Pack (Selected Endpoint)")
                    turbo_item.addActionListener(
                        lambda e: self.extender._export_recon_turbo_pack_selected(
                            endpoint_key
                        )
                    )
                    popup.add(turbo_item)
                    hidden_param_item = JMenuItem("Hidden Params (Selected Endpoint)")
                    hidden_param_item.addActionListener(
                        lambda e: self.extender._run_recon_hidden_params_selected(
                            endpoint_key
                        )
                    )
                    popup.add(hidden_param_item)
                    ai_item = JMenuItem("Send to AI Analysis")
                    ai_item.addActionListener(
                        lambda e: self.extender._send_endpoint_to_ai(endpoint_key)
                    )
                    popup.add(ai_item)
                    popup.show(event.getComponent(), event.getX(), event.getY())


class EndpointSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if event is None:
            return
        try:
            if event.getValueIsAdjusting():
                return
        except Exception as adjust_err:
            self.extender._callbacks.printError(
                "Recon selection adjust-state check error: {}".format(str(adjust_err))
            )
            return
        try:
            if hasattr(self.extender, "_recon_show_selected_endpoint_detail"):
                self.extender._recon_show_selected_endpoint_detail()
            elif hasattr(self.extender, "_show_selected_recon_endpoint_details"):
                self.extender._show_selected_recon_endpoint_details(event=event)
        except Exception as selection_err:
            self.extender._callbacks.printError(
                "Recon endpoint detail refresh error: {}".format(str(selection_err))
            )


class EndpointRenderer(ListCellRenderer):
    def __init__(self, extender):
        self.extender = extender
        self.severity_cache = {}

    def invalidate_cache(self):
        self.severity_cache.clear()

    def getListCellRendererComponent(
        self, list, value, index, isSelected, cellHasFocus
    ):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.setOpaque(True)

        text_label = JLabel(str(value))
        text_label.setFont(Font("Monospaced", Font.PLAIN, 12))
        panel.add(text_label)
        panel.add(Box.createHorizontalGlue())

        # Extract endpoint key from display text
        endpoint_key = EndpointClickListener._extract_endpoint_key(str(value))

        # Determine severity using cache to avoid lock on every render
        severity = None
        if endpoint_key:
            severity = self.severity_cache.get(endpoint_key)
            if severity is None:
                with self.extender.lock:
                    if endpoint_key in self.extender.api_data:
                        entries = self.extender.api_data[endpoint_key]
                        severity = self.extender._get_severity(endpoint_key, entries)
                        self.severity_cache[endpoint_key] = severity

        if severity:

            severity_label = JLabel()
            severity_label.setFont(Font("Monospaced", Font.BOLD, 11))

            if severity == "critical":
                panel.setBackground(
                    Color(220, 53, 69) if not isSelected else Color(180, 43, 59)
                )
                text_label.setForeground(Color.WHITE)
                severity_label.setText("[CRITICAL]")
                severity_label.setForeground(Color.WHITE)
            elif severity == "high":
                panel.setBackground(
                    Color(255, 193, 7) if not isSelected else Color(215, 163, 0)
                )
                text_label.setForeground(Color.BLACK)
                severity_label.setText("[HIGH]")
                severity_label.setForeground(Color(139, 0, 0))
            elif severity == "medium":
                panel.setBackground(
                    Color(255, 235, 170) if not isSelected else Color(215, 195, 130)
                )
                text_label.setForeground(Color.BLACK)
                severity_label.setText("[MEDIUM]")
                severity_label.setForeground(Color(139, 69, 0))
            else:
                if isSelected:
                    panel.setBackground(Color(220, 220, 220))
                elif index % 2 == 0:
                    panel.setBackground(Color.WHITE)
                else:
                    panel.setBackground(Color(245, 245, 245))
                text_label.setForeground(Color.BLACK)

            if severity in ["critical", "high", "medium"]:
                panel.add(severity_label)
        else:
            # Group headers or non-endpoint lines
            if isSelected:
                panel.setBackground(Color(220, 220, 220))
            elif index % 2 == 0:
                panel.setBackground(Color.WHITE)
            else:
                panel.setBackground(Color(245, 245, 245))
            text_label.setForeground(Color.BLACK)

        return panel



# BurpExtender methods are loaded from split helper modules for Jython compile-size safety.
import burp_core_ui_and_fuzz_methods
import burp_recon_logger_sync_methods
import burp_advanced_logic_methods
import burp_counterfactual_methods
import burp_fuzz_detection_and_capture_methods
import burp_capture_export_and_tooling_methods
import burp_auth_passive_and_scanner_methods
import burp_wayback_import_and_logging_methods

_BURP_METHOD_MODULES = [
    burp_core_ui_and_fuzz_methods,
    burp_recon_logger_sync_methods,
    burp_advanced_logic_methods,
    burp_counterfactual_methods,
    burp_fuzz_detection_and_capture_methods,
    burp_capture_export_and_tooling_methods,
    burp_auth_passive_and_scanner_methods,
    burp_wayback_import_and_logging_methods,
]
for _burp_module in _BURP_METHOD_MODULES:
    _burp_module.SearchListener = SearchListener
    _burp_module.EndpointClickListener = EndpointClickListener
    _burp_module.EndpointSelectionListener = EndpointSelectionListener
    _burp_module.EndpointRenderer = EndpointRenderer
    for _burp_name in _burp_module.__all__:
        setattr(BurpExtender, _burp_name, getattr(_burp_module, _burp_name))

del _BURP_METHOD_MODULES
del _burp_module
del _burp_name
