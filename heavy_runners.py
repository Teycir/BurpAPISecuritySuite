# -*- coding: utf-8 -*-
"""Heavy external-tool runner methods extracted to reduce Jython method size pressure."""

import json
import os
import re
import subprocess
import tempfile
import threading
import time

from java.io import FileWriter
from java.net import URL
from javax.swing import SwingUtilities

def _run_graphql_analysis(self, event):
    """Run GraphQL-focused analysis using available external tools."""
    import os
    import tempfile

    max_targets = self._parse_positive_int(
        self.graphql_max_targets_field.getText(), 12, 1, 50
    )
    targets = self._collect_graphql_targets(max_targets)
    if not targets:
        self.graphql_area.setText(
            "[!] No GraphQL targets found.\n[*] Enter targets manually or capture GraphQL traffic in Recon first.\n"
        )
        return

    self.graphql_area.setText("[*] GraphQL analysis starting...\n")
    self.graphql_area.append("[*] Targets: {}\n".format(len(targets)))
    for target in targets:
        self.graphql_area.append("  - {}\n".format(target))
    self.graphql_area.append("\n")
    self._clear_tool_cancel("graphqlanalysis")

    def run_analysis():
        temp_dir = tempfile.mkdtemp(prefix="burp_graphql_")
        discovered_urls = set(targets)
        findings = []
        recon_candidates = []
        tool_available = {}
        available_tools = []
        missing_tools = []

        def append_line(text):
            SwingUtilities.invokeLater(
                lambda t=self._ascii_safe(text): self.graphql_area.append(t)
            )

        def check_tool(name, path, required_tokens, forbidden_tokens=None):
            forbidden_tokens = forbidden_tokens or []
            if not path:
                append_line("[MISSING] {} path not configured\n".format(name))
                missing_tools.append(name)
                return False
            probe_ok, help_text, probe_error = self._probe_binary_help(path)
            if not probe_ok:
                append_line(
                    "[MISSING] {} -> {} ({})\n".format(
                        name,
                        path,
                        self._ascii_safe(probe_error or "binary probe failed"),
                    )
                )
                missing_tools.append(name)
                return False
            sig = self._evaluate_help_text(
                help_text,
                required_tokens=required_tokens,
                forbidden_tokens=forbidden_tokens,
            )
            if not sig.get("healthy"):
                append_line(
                    "[MISSING] {} incompatible: missing={} forbidden={}\n".format(
                        name,
                        ",".join(sig.get("missing") or []),
                        ",".join(sig.get("forbidden_found") or []),
                    )
                )
                missing_tools.append(name)
                return False
            append_line("[USED] {} -> {}\n".format(name, path))
            available_tools.append(name)
            return True

        try:
            append_line("=" * 80 + "\n")
            append_line("GRAPHQL ANALYSIS - TOOL STATUS\n")
            append_line("=" * 80 + "\n")

            subfinder_path = self._resolve_graphql_tool_path(
                "asset_subfinder_path_field",
                [
                    os.path.expanduser("~/go/bin/subfinder"),
                    "subfinder",
                ],
            )
            httpx_path = self._resolve_graphql_tool_path(
                "httpx_path_field",
                [
                    os.path.expanduser("~/go/bin/httpx"),
                    "httpx",
                ],
            )
            katana_path = self._resolve_graphql_tool_path(
                "katana_path_field",
                [
                    os.path.expanduser("~/go/bin/katana"),
                    "katana",
                ],
            )
            ffuf_path = self._resolve_graphql_tool_path(
                "ffuf_path_field",
                [
                    os.path.expanduser("~/go/bin/ffuf"),
                    "ffuf",
                ],
            )
            wayback_path = self._resolve_graphql_tool_path(
                "",
                [
                    os.path.expanduser("~/go/bin/waybackurls"),
                    "waybackurls",
                ],
            )
            nuclei_path = self._resolve_graphql_tool_path(
                "nuclei_path_field",
                [
                    os.path.expanduser("~/go/bin/nuclei"),
                    "nuclei",
                ],
            )
            dalfox_path = self._resolve_graphql_tool_path(
                "dalfox_path_field",
                [
                    os.path.expanduser("~/go/bin/dalfox"),
                    "dalfox",
                ],
            )
            sqlmap_path = self._resolve_graphql_tool_path(
                "sqlmap_path_field",
                [
                    os.path.expanduser("~/.local/bin/sqlmap"),
                    "sqlmap",
                ],
            )

            tool_available["Subfinder"] = check_tool(
                "Subfinder", subfinder_path, ["-d", "-silent"]
            )
            tool_available["HTTPX"] = check_tool(
                "HTTPX",
                httpx_path,
                ["-l", "-status-code", "-silent"],
                [
                    "a next generation http client",
                    "usage: httpx <url> [options]",
                ],
            )
            tool_available["Katana"] = check_tool(
                "Katana", katana_path, ["-u", "-d"]
            )
            tool_available["FFUF"] = check_tool("FFUF", ffuf_path, ["-u", "-w"])
            tool_available["Wayback"] = check_tool(
                "Wayback", wayback_path, ["-dates", "-no-subs"]
            )
            tool_available["Nuclei"] = check_tool(
                "Nuclei", nuclei_path, ["-list", "-tags", "-etags", "-jsonl"]
            )
            tool_available["Dalfox"] = check_tool(
                "Dalfox", dalfox_path, ["url", "--format", "-o"]
            )
            tool_available["SQLMap"] = check_tool(
                "SQLMap", sqlmap_path, ["-u", "--batch", "--level"]
            )
            append_line(
                "[*] Available: {}\n".format(
                    ", ".join(available_tools) if available_tools else "none"
                )
            )
            append_line(
                "[*] Missing: {}\n\n".format(
                    ", ".join(missing_tools) if missing_tools else "none"
                )
            )

            # Stage 1: Subfinder domain expansion
            base_domains = []
            for base in self._graphql_base_urls(targets):
                try:
                    parsed = URL(base)
                    host = self._ascii_safe(parsed.getHost(), lower=True).strip()
                    root = self._infer_base_domain(host) or host
                    if root and root not in base_domains:
                        base_domains.append(root)
                except Exception as parse_err:
                    self._callbacks.printError(
                        "GraphQL domain parse error: {}".format(str(parse_err))
                    )
                    continue
            if tool_available.get("Subfinder") and base_domains:
                domains_file = os.path.join(temp_dir, "domains.txt")
                subfinder_file = os.path.join(temp_dir, "subfinder.txt")
                with open(domains_file, "w") as writer:
                    for domain in base_domains[:10]:
                        writer.write(domain + "\n")
                cmd = [
                    subfinder_path,
                    "-dL",
                    domains_file,
                    "-silent",
                    "-o",
                    subfinder_file,
                ]
                append_line("[*] Tool: Subfinder\n")
                append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                ok, cancelled, _, err = self._run_command_stage(
                    "graphqlanalysis", "Subfinder", cmd, self.graphql_area, 150
                )
                if cancelled:
                    append_line("[!] GraphQL analysis cancelled by user\n")
                    return
                if not ok:
                    append_line("[!] Subfinder error: {}\n".format(self._ascii_safe(err)))
                if os.path.exists(subfinder_file):
                    with open(subfinder_file, "r") as reader:
                        for line in reader:
                            host = self._ascii_safe(line, lower=True).strip().strip(".")
                            if host and "." in host:
                                discovered_urls.add("https://{}/graphql".format(host))

            # Stage 2: HTTPX validation
            alive_urls = []
            if tool_available.get("HTTPX"):
                httpx_targets_file = os.path.join(temp_dir, "httpx_targets.txt")
                httpx_json = os.path.join(temp_dir, "httpx.jsonl")
                with open(httpx_targets_file, "w") as writer:
                    for url in sorted(discovered_urls):
                        writer.write(url + "\n")
                cmd = [
                    httpx_path,
                    "-l",
                    httpx_targets_file,
                    "-silent",
                    "-sc",
                    "-title",
                    "-json",
                    "-timeout",
                    "12",
                    "-o",
                    httpx_json,
                ]
                append_line("[*] Tool: HTTPX\n")
                append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                ok, cancelled, _, err = self._run_command_stage(
                    "graphqlanalysis", "HTTPX", cmd, self.graphql_area, 180
                )
                if cancelled:
                    append_line("[!] GraphQL analysis cancelled by user\n")
                    return
                if not ok:
                    append_line("[!] HTTPX error: {}\n".format(self._ascii_safe(err)))
                if os.path.exists(httpx_json):
                    with open(httpx_json, "r") as reader:
                        for line in reader:
                            safe_line = self._ascii_safe(line).strip()
                            if not safe_line:
                                continue
                            try:
                                row = json.loads(safe_line)
                            except Exception as parse_err:
                                self._callbacks.printError(
                                    "GraphQL HTTPX JSON parse error: {}".format(
                                        str(parse_err)
                                    )
                                )
                                continue
                            url_value = self._ascii_safe(row.get("url") or "").strip()
                            status_code = int(row.get("status_code") or 0)
                            if url_value and status_code >= 200 and status_code < 500:
                                alive_urls.append(url_value)
                                discovered_urls.add(url_value)
                                recon_candidates.append(
                                    {"method": "GET", "url": url_value}
                                )

            # Stage 3: Katana crawl
            katana_found = []
            if tool_available.get("Katana"):
                for idx, base in enumerate(self._graphql_base_urls(alive_urls or targets)[:5]):
                    katana_out = os.path.join(temp_dir, "katana_{}.txt".format(idx))
                    cmd = [
                        katana_path,
                        "-u",
                        base,
                        "-silent",
                        "-d",
                        "1",
                        "-c",
                        "5",
                        "-p",
                        "5",
                        "-rl",
                        "5",
                        "-o",
                        katana_out,
                    ]
                    append_line("[*] Tool: Katana\n")
                    append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                    ok, cancelled, _, err = self._run_command_stage(
                        "graphqlanalysis", "Katana", cmd, self.graphql_area, 120
                    )
                    if cancelled:
                        append_line("[!] GraphQL analysis cancelled by user\n")
                        return
                    if not ok:
                        append_line("[!] Katana error: {}\n".format(self._ascii_safe(err)))
                    if os.path.exists(katana_out):
                        with open(katana_out, "r") as reader:
                            for line in reader:
                                url_value = self._clean_url(line)
                                low = self._ascii_safe(url_value, lower=True)
                                if not url_value:
                                    continue
                                if any(
                                    marker in low
                                    for marker in [
                                        "graphql",
                                        "graphiql",
                                        "playground",
                                        "swagger",
                                        "openapi",
                                        "api-docs",
                                    ]
                                ):
                                    katana_found.append(url_value)
                                    discovered_urls.add(url_value)
                                    recon_candidates.append(
                                        {"method": "GET", "url": url_value}
                                    )

            # Stage 4: FFUF GraphQL path probing
            ffuf_found = []
            if tool_available.get("FFUF"):
                words_file = os.path.join(temp_dir, "graphql_words.txt")
                with open(words_file, "w") as writer:
                    writer.write(
                        "\n".join(
                            [
                                "graphql",
                                "api/graphql",
                                "v1/graphql",
                                "v2/graphql",
                                "graphiql",
                                "playground",
                                "api-docs",
                                "swagger.json",
                                "openapi.json",
                            ]
                        )
                    )
                for idx, base in enumerate(self._graphql_base_urls(alive_urls or targets)[:5]):
                    ffuf_json = os.path.join(temp_dir, "ffuf_{}.json".format(idx))
                    cmd = [
                        ffuf_path,
                        "-u",
                        base.rstrip("/") + "/FUZZ",
                        "-w",
                        words_file,
                        "-mc",
                        "200,204,301,302,307,401,403",
                        "-s",
                        "-timeout",
                        "5",
                        "-rate",
                        "20",
                        "-of",
                        "json",
                        "-o",
                        ffuf_json,
                    ]
                    append_line("[*] Tool: FFUF\n")
                    append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                    ok, cancelled, _, err = self._run_command_stage(
                        "graphqlanalysis", "FFUF", cmd, self.graphql_area, 80
                    )
                    if cancelled:
                        append_line("[!] GraphQL analysis cancelled by user\n")
                        return
                    if not ok:
                        append_line("[!] FFUF error: {}\n".format(self._ascii_safe(err)))
                    if os.path.exists(ffuf_json):
                        try:
                            with open(ffuf_json, "r") as reader:
                                data = json.loads(self._ascii_safe(reader.read()))
                            for item in data.get("results", []):
                                url_value = self._clean_url(item.get("url") or "")
                                if url_value:
                                    ffuf_found.append(url_value)
                                    discovered_urls.add(url_value)
                                    recon_candidates.append(
                                        {"method": "GET", "url": url_value}
                                    )
                        except Exception as parse_err:
                            append_line(
                                "[!] FFUF parse error: {}\n".format(
                                    self._ascii_safe(parse_err)
                                )
                            )

            # Stage 5: Wayback archived GraphQL URLs
            wayback_found = []
            if tool_available.get("Wayback"):
                domains = []
                for base in self._graphql_base_urls(alive_urls or targets):
                    try:
                        host = self._ascii_safe(URL(base).getHost(), lower=True).strip()
                        domain = self._infer_base_domain(host) or host
                        if domain and domain not in domains:
                            domains.append(domain)
                    except Exception as parse_err:
                        self._callbacks.printError(
                            "GraphQL wayback domain parse error: {}".format(
                                str(parse_err)
                            )
                        )
                        continue
                for domain in domains[:5]:
                    cmd = [
                        "bash",
                        "-lc",
                        "echo '{}' | {} | head -n 200".format(
                            domain.replace("'", ""),
                            wayback_path,
                        ),
                    ]
                    append_line("[*] Tool: Wayback\n")
                    append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                    ok, cancelled, stdout_data, err = self._run_command_stage(
                        "graphqlanalysis", "Wayback", cmd, self.graphql_area, 60
                    )
                    if cancelled:
                        append_line("[!] GraphQL analysis cancelled by user\n")
                        return
                    if not ok:
                        append_line("[!] Wayback error: {}\n".format(self._ascii_safe(err)))
                    for line in self._ascii_safe(stdout_data).splitlines():
                        url_value = self._clean_url(line)
                        if url_value and "graphql" in self._ascii_safe(
                            url_value, lower=True
                        ):
                            wayback_found.append(url_value)
                            discovered_urls.add(url_value)
                            recon_candidates.append({"method": "GET", "url": url_value})

            # Stage 6: Focused Nuclei
            nuclei_lines = []
            if tool_available.get("Nuclei"):
                nuclei_targets = sorted(
                    [
                        url
                        for url in discovered_urls
                        if any(
                            token in self._ascii_safe(url, lower=True)
                            for token in ["graphql", "graphiql", "playground"]
                        )
                    ]
                )
                if not nuclei_targets:
                    nuclei_targets = list(sorted(set(alive_urls or targets)))
                nuclei_targets_file = os.path.join(temp_dir, "nuclei_targets.txt")
                nuclei_txt = os.path.join(temp_dir, "nuclei.txt")
                nuclei_json = os.path.join(temp_dir, "nuclei.jsonl")
                with open(nuclei_targets_file, "w") as writer:
                    for url in nuclei_targets[:40]:
                        writer.write(url + "\n")
                cmd = [
                    nuclei_path,
                    "-list",
                    nuclei_targets_file,
                    "-tags",
                    "swagger,openapi,graphql,auth,jwt",
                    "-etags",
                    "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
                    "-timeout",
                    "10",
                    "-retries",
                    "1",
                    "-rate-limit",
                    "40",
                    "-c",
                    "8",
                    "-silent",
                    "-disable-update-check",
                    "-no-httpx",
                    "-jsonl-export",
                    nuclei_json,
                    "-o",
                    nuclei_txt,
                ]
                append_line("[*] Tool: Nuclei\n")
                append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                ok, cancelled, _, err = self._run_command_stage(
                    "graphqlanalysis", "Nuclei", cmd, self.graphql_area, 240
                )
                if cancelled:
                    append_line("[!] GraphQL analysis cancelled by user\n")
                    return
                if not ok:
                    append_line("[!] Nuclei error: {}\n".format(self._ascii_safe(err)))
                if os.path.exists(nuclei_txt):
                    with open(nuclei_txt, "r") as reader:
                        for line in reader:
                            clean_line = self._ascii_safe(line).strip()
                            if clean_line:
                                nuclei_lines.append(clean_line)
                                findings.append("[NUCLEI] {}".format(clean_line))

            # Stage 7: Dalfox/SQLMap on query targets
            query_targets = [
                url for url in sorted(discovered_urls) if "?" in self._ascii_safe(url)
            ][:3]
            if tool_available.get("Dalfox"):
                if not query_targets:
                    append_line("[SKIP] Dalfox: no query-string targets available\n")
                else:
                    for idx, url_value in enumerate(query_targets):
                        dalfox_out = os.path.join(temp_dir, "dalfox_{}.jsonl".format(idx))
                        cmd = [
                            dalfox_path,
                            "url",
                            url_value,
                            "--format",
                            "jsonl",
                            "-o",
                            dalfox_out,
                            "-S",
                            "--no-color",
                            "--timeout",
                            "8",
                            "--worker",
                            "20",
                            "--skip-bav",
                            "--skip-mining-all",
                            "--skip-mining-dom",
                            "--skip-headless",
                        ]
                        append_line("[*] Tool: Dalfox\n")
                        append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                        ok, cancelled, _, err = self._run_command_stage(
                            "graphqlanalysis", "Dalfox", cmd, self.graphql_area, 120
                        )
                        if cancelled:
                            append_line("[!] GraphQL analysis cancelled by user\n")
                            return
                        if not ok:
                            append_line("[!] Dalfox error: {}\n".format(self._ascii_safe(err)))
                        if os.path.exists(dalfox_out) and os.path.getsize(dalfox_out) > 0:
                            with open(dalfox_out, "r") as reader:
                                for line in reader:
                                    clean_line = self._ascii_safe(line).strip()
                                    if clean_line:
                                        findings.append("[DALFOX] {}".format(clean_line[:300]))

            if tool_available.get("SQLMap"):
                if not query_targets:
                    append_line("[SKIP] SQLMap: no query-string targets available\n")
                else:
                    for url_value in query_targets[:2]:
                        cmd = [
                            sqlmap_path,
                            "-u",
                            url_value,
                            "--batch",
                            "--level",
                            "1",
                            "--risk",
                            "1",
                            "--threads",
                            "1",
                            "--timeout",
                            "6",
                            "--retries",
                            "0",
                            "--flush-session",
                        ]
                        append_line("[*] Tool: SQLMap\n")
                        append_line("[*] CMD: {}\n".format(" ".join(cmd)))
                        ok, cancelled, stdout_data, err = self._run_command_stage(
                            "graphqlanalysis", "SQLMap", cmd, self.graphql_area, 120
                        )
                        if cancelled:
                            append_line("[!] GraphQL analysis cancelled by user\n")
                            return
                        evidence = self._extract_sqlmap_evidence(
                            "{}\n{}".format(stdout_data or "", err or "")
                        )
                        if evidence:
                            findings.append(
                                "[SQLMAP] {} | {}".format(url_value, evidence)
                            )

            # Final summary
            cleaned_candidates = []
            candidate_seen = set()
            for candidate in recon_candidates:
                url_value = self._clean_url(candidate.get("url") or "")
                if not url_value or url_value in candidate_seen:
                    continue
                candidate_seen.add(url_value)
                cleaned_candidates.append({"method": "GET", "url": url_value})

            summary_lines = []
            summary_lines.append("\n" + "=" * 80)
            summary_lines.append("GRAPHQL ANALYSIS RESULTS")
            summary_lines.append("=" * 80)
            summary_lines.append("[*] Targets input: {}".format(len(targets)))
            summary_lines.append("[*] Tools available: {}".format(len(available_tools)))
            summary_lines.append("[*] Tools missing: {}".format(len(missing_tools)))
            summary_lines.append("[*] HTTPX alive URLs: {}".format(len(alive_urls)))
            summary_lines.append("[*] Katana GraphQL-like URLs: {}".format(len(katana_found)))
            summary_lines.append("[*] FFUF hits: {}".format(len(ffuf_found)))
            summary_lines.append("[*] Wayback GraphQL URLs: {}".format(len(wayback_found)))
            summary_lines.append("[*] Nuclei findings: {}".format(len(nuclei_lines)))
            summary_lines.append("[*] Total findings lines: {}".format(len(findings)))
            summary_lines.append(
                "[*] Recon candidates prepared: {}".format(len(cleaned_candidates))
            )
            summary_lines.append("")
            if missing_tools:
                summary_lines.append("[!] Missing tools: {}".format(", ".join(missing_tools)))
                summary_lines.append("")
            summary_lines.extend(
                findings[:80] if findings else ["[+] No findings from focused checks"]
            )
            if len(findings) > 80:
                summary_lines.append(
                    "[*] {} more findings lines not shown".format(len(findings) - 80)
                )

            with self.graphql_lock:
                self.graphql_results = list(summary_lines)
                self.graphql_recon_candidates = list(cleaned_candidates)

            append_line("\n".join(summary_lines) + "\n")
            SwingUtilities.invokeLater(
                lambda: self.log_to_ui(
                    "[+] GraphQL analysis complete: {} findings, {} recon candidates".format(
                        len(findings), len(cleaned_candidates)
                    )
                )
            )
        except Exception as e:
            append_line("[!] GraphQL analysis error: {}\n".format(self._ascii_safe(e)))
            err_msg = self._ascii_safe(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui(
                    "[!] GraphQL analysis error: {}".format(m)
                )
            )
        finally:
            self._clear_tool_cancel("graphqlanalysis")
            self._cleanup_temp_dir(temp_dir, "graphql analysis")

    worker = threading.Thread(target=run_analysis)
    worker.daemon = True
    worker.start()

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
    if not self._validate_binary_signature(
        "Nuclei",
        nuclei_path,
        self.nuclei_area,
        required_tokens=["-list", "-jsonl", "-tags", "-etags"],
        forbidden_tokens=[],
        fix_hint="Set Nuclei Path to your local ProjectDiscovery nuclei binary (for example: /home/teycir/go/bin/nuclei).",
    ):
        return

    # Create temp file in /tmp instead of auto-saving to user directory
    import tempfile

    temp_dir = tempfile.mkdtemp(prefix="burp_nuclei_")
    targets_file = os.path.join(temp_dir, "targets.txt")
    output_file = os.path.join(temp_dir, "results.txt")
    json_file = os.path.join(temp_dir, "results.json")

    targets, target_meta = self._collect_nuclei_targets()
    if not targets:
        self._cleanup_temp_dir(temp_dir, "nuclei empty target set")
        self.nuclei_area.setText(
            "[!] No Nuclei targets after filtering. Capture more first-party API traffic or adjust host filter.\n"
        )
        return

    # Write scoped targets for endpoint discovery
    writer = None
    try:
        writer = FileWriter(targets_file)
        for target in targets:
            writer.write(target + "\n")
    finally:
        if writer:
            try:
                writer.close()
            except Exception as e:
                self._callbacks.printError(
                    "Error closing nuclei scan targets file: {}".format(str(e))
                )
    target_count = len(targets)
    profile_value = self._selected_profile_value(
        getattr(self, "nuclei_profile_combo", None)
    )
    nuclei_profile_cfg = self._nuclei_profile_settings(profile_value)

    use_custom_nuclei, custom_nuclei_command = self._resolve_custom_command(
        "Nuclei",
        self.nuclei_custom_cmd_checkbox,
        self.nuclei_custom_cmd_field,
        {
            "nuclei_path": nuclei_path,
            "targets_file": targets_file,
            "output_file": output_file,
            "json_file": json_file,
        },
        self.nuclei_area,
    )
    if use_custom_nuclei and not custom_nuclei_command:
        self._cleanup_temp_dir(temp_dir, "nuclei custom command validation")
        return

    probe_ok, help_text, _ = self._probe_binary_help(nuclei_path)
    supports_jsonl_export = bool(
        probe_ok and "-jsonl-export" in (help_text or "").lower()
    )
    help_text_lower = (help_text or "").lower()
    supports_max_host_error = bool(probe_ok and "-max-host-error" in help_text_lower)
    supports_bulk_size = bool(probe_ok and "-bulk-size" in help_text_lower)
    supports_scan_strategy = bool(probe_ok and "-scan-strategy" in help_text_lower)
    supports_no_httpx = bool(probe_ok and "-no-httpx" in help_text_lower)
    supports_project_mode = bool(probe_ok and "-project" in help_text_lower)

    self.log_to_ui("[*] Nuclei discovery: {} scoped targets".format(target_count))
    self.log_to_ui("[*] Targets: {}".format(targets_file))
    self.log_to_ui("[*] Output: {}".format(output_file))
    self.nuclei_area.setText("[*] Initializing Nuclei (WAF EVASION MODE)...\n")
    self.nuclei_area.append(
        "[*] Profile: {}\n".format(nuclei_profile_cfg.get("profile", profile_value))
    )
    self.nuclei_area.append(
        "[*] Discovery targets: {} (scoped first-party hosts/paths)\n".format(
            target_count
        )
    )
    if target_meta.get("manual_scope_enabled"):
        self.nuclei_area.append(
            "[*] Target base scope: {} lines | hosts={} | bases={}\n".format(
                target_meta.get("manual_scope_line_count", 0),
                target_meta.get("manual_scope_host_count", 0),
                target_meta.get("manual_scope_base_count", 0),
            )
        )
        preview = target_meta.get("manual_scope_preview", [])
        if preview:
            self.nuclei_area.append(
                "[*] Scope preview: {}\n".format(", ".join(preview))
            )
    elif target_meta.get("force_host"):
        self.nuclei_area.append(
            "[*] Host scope: {}\n".format(target_meta.get("selected_host", "unknown"))
        )
    else:
        allowed_bases = target_meta.get("allowed_bases", [])
        if allowed_bases:
            self.nuclei_area.append(
                "[*] First-party base scope: {}\n".format(", ".join(allowed_bases))
            )
    self.nuclei_area.append(
        "[*] Filtered out: noise-host={} scope-host={} path-noise={}\n".format(
            target_meta.get("dropped_noise_host", 0),
            target_meta.get("dropped_scope_host", 0),
            target_meta.get("dropped_path", 0),
        )
    )
    if target_meta.get("truncated", 0) > 0:
        self.nuclei_area.append(
            "[*] Target cap applied: {} skipped (max {})\n".format(
                target_meta.get("truncated", 0), self.NUCLEI_MAX_TARGETS
            )
        )
    self.nuclei_area.append(
        "[*] Tags: {}\n".format(nuclei_profile_cfg.get("include_tags", ""))
    )
    self.nuclei_area.append(
        "[*] Excluding: {}\n".format(nuclei_profile_cfg.get("exclude_tags", ""))
    )
    self.nuclei_area.append(
        "[*] Timeout: {}s, Retries: {} (resilient mode)\n".format(
            nuclei_profile_cfg.get("request_timeout", self.NUCLEI_REQUEST_TIMEOUT_SECONDS),
            nuclei_profile_cfg.get("retries", self.NUCLEI_RETRIES),
        )
    )
    self.nuclei_area.append(
        "[*] Rate: {} req/s, Concurrency: {} (balanced mode)\n".format(
            nuclei_profile_cfg.get("rate_limit", self.NUCLEI_RATE_LIMIT),
            nuclei_profile_cfg.get("concurrency", self.NUCLEI_CONCURRENCY),
        )
    )
    self.nuclei_area.append(
        "[*] Scan strategy: {} | Bulk size: {} | Max host errors: {}\n".format(
            nuclei_profile_cfg.get("scan_strategy", self.NUCLEI_SCAN_STRATEGY),
            nuclei_profile_cfg.get("bulk_size", self.NUCLEI_BULK_SIZE),
            nuclei_profile_cfg.get("max_host_error", self.NUCLEI_MAX_HOST_ERROR),
        )
    )
    self.nuclei_area.append("[*] Evasion: Header-based spoofing (X-Forwarded-For)\n\n")
    self._clear_tool_cancel("nuclei")

    def run_scan():
        process = None
        try:
            include_tags = nuclei_profile_cfg.get(
                "include_tags", "swagger,openapi,graphql,auth,jwt"
            )
            exclude_tags = nuclei_profile_cfg.get(
                "exclude_tags", "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force"
            )
            parse_file = json_file

            if use_custom_nuclei and custom_nuclei_command:
                cmd = self._build_shell_command(custom_nuclei_command)
                display_cmd = custom_nuclei_command
                SwingUtilities.invokeLater(
                    lambda: self.nuclei_area.append(
                        "[*] Custom command override enabled\n"
                    )
                )
            else:
                cmd = [
                    nuclei_path,
                    "-list",
                    targets_file,
                    "-o",
                    output_file,
                    "-tags",
                    include_tags,
                    "-etags",
                    exclude_tags,
                    "-no-color",
                    "-timeout",
                    str(
                        nuclei_profile_cfg.get(
                            "request_timeout",
                            self.NUCLEI_REQUEST_TIMEOUT_SECONDS,
                        )
                    ),
                    "-retries",
                    str(nuclei_profile_cfg.get("retries", self.NUCLEI_RETRIES)),
                    "-rate-limit",
                    str(
                        nuclei_profile_cfg.get(
                            "rate_limit", self.NUCLEI_RATE_LIMIT
                        )
                    ),
                    "-c",
                    str(
                        nuclei_profile_cfg.get(
                            "concurrency", self.NUCLEI_CONCURRENCY
                        )
                    ),
                    "-disable-update-check",
                    "-silent",
                    "-header",
                    "X-Forwarded-For: 127.0.0.1",
                ]
                if supports_bulk_size:
                    cmd.extend(
                        [
                            "-bs",
                            str(
                                nuclei_profile_cfg.get(
                                    "bulk_size", self.NUCLEI_BULK_SIZE
                                )
                            ),
                        ]
                    )
                if supports_max_host_error:
                    cmd.extend(
                        [
                            "-mhe",
                            str(
                                nuclei_profile_cfg.get(
                                    "max_host_error",
                                    self.NUCLEI_MAX_HOST_ERROR,
                                )
                            ),
                        ]
                    )
                if supports_scan_strategy:
                    cmd.extend(
                        [
                            "-ss",
                            nuclei_profile_cfg.get(
                                "scan_strategy", self.NUCLEI_SCAN_STRATEGY
                            ),
                        ]
                    )
                if supports_no_httpx:
                    cmd.append("-no-httpx")
                if supports_project_mode:
                    cmd.extend(["-project", "-project-path", temp_dir])
                if supports_jsonl_export:
                    cmd.extend(["-jsonl-export", json_file])
                else:
                    cmd.append("-jsonl")
                    parse_file = output_file
                    SwingUtilities.invokeLater(
                        lambda: self.nuclei_area.append(
                            "[*] Compatibility: using -jsonl fallback (upgrade nuclei for -jsonl-export)\n"
                        )
                    )
                display_cmd = " ".join(cmd)
            SwingUtilities.invokeLater(
                lambda: self.nuclei_area.append(
                    "[*] Command: {}\n\n".format(display_cmd)
                )
            )
            SwingUtilities.invokeLater(
                lambda: self.log_to_ui("[*] Nuclei cmd: {}".format(display_cmd))
            )
            SwingUtilities.invokeLater(
                lambda: self.nuclei_area.append(
                    "[*] Discovery mode: Scanning scoped targets to find NEW endpoints\n\n"
                )
            )

            import time as time_module

            start_time = time_module.time()
            timed_out = False
            capture_path = os.path.join(temp_dir, "nuclei_runtime.log")
            try:
                capture_handle = open(capture_path, "wb")
                try:
                    process = subprocess.Popen(  # nosec B603
                        cmd,
                        stdout=capture_handle,
                        stderr=subprocess.STDOUT,
                        shell=False,
                    )
                finally:
                    capture_handle.close()
                self._set_active_tool_process("nuclei", process)
            except Exception as e:
                err_msg = str(e)
                SwingUtilities.invokeLater(
                    lambda m=err_msg: self.nuclei_area.append(
                        "[!] Failed to start nuclei: {}\n".format(m)
                    )
                )
                return

            adaptive_timeout = max(360, target_count * 30)
            max_timeout = min(
                nuclei_profile_cfg.get(
                    "max_scan_seconds", self.NUCLEI_MAX_SCAN_SECONDS
                ),
                adaptive_timeout,
            )

            SwingUtilities.invokeLater(
                lambda t=max_timeout, c=target_count: self.nuclei_area.append(
                    "[*] Scanning (max {}s for {} targets)...\n\n".format(t, c)
                )
            )

            # Wait with minimal progress updates
            start_wait = time_module.time()
            last_update = start_wait
            cancelled_by_user = False
            while process.poll() is None:
                current = time_module.time()
                elapsed = int(current - start_wait)
                if self._is_tool_cancelled("nuclei"):
                    cancelled_by_user = True
                    self._terminate_process_cross_platform(process, "Nuclei")
                    break
                if elapsed > max_timeout:
                    timed_out = True
                    try:
                        process.kill()
                        process.wait()
                    except Exception as e:
                        self._callbacks.printError("Kill failed: {}".format(str(e)))
                    SwingUtilities.invokeLater(
                        lambda t=max_timeout: self.nuclei_area.append(
                            "\n[!] Timeout after {}s\n".format(
                                t
                            )
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
            combined_output = ""
            if os.path.exists(capture_path):
                try:
                    with open(capture_path, "rb") as capture_reader:
                        combined_output = self._decode_process_data(
                            capture_reader.read(), "Nuclei output"
                        )
                except Exception as capture_err:
                    self._callbacks.printError(
                        "Nuclei output read error: {}".format(str(capture_err))
                    )

            if cancelled_by_user:
                SwingUtilities.invokeLater(
                    lambda: self.nuclei_area.append(
                        "\n[!] Nuclei run cancelled by user\n"
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] Nuclei cancelled by user")
                )
                return

            output_preview = self._ascii_safe(combined_output or "").strip()

            SwingUtilities.invokeLater(
                lambda: self.log_to_ui(
                    "[*] Nuclei: {}s, exit code {}".format(
                        elapsed, process.returncode
                    )
                )
            )

            partial_results_mode = False
            if process.returncode != 0:
                partial_parse_file = None
                try:
                    if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
                        partial_parse_file = json_file
                    elif os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        partial_parse_file = output_file
                except Exception as partial_err:
                    self._callbacks.printError(
                        "Nuclei partial-results check failed: {}".format(str(partial_err))
                    )

                can_timeout_recover = bool(
                    timed_out or process.returncode in [137, 143]
                )
                can_parse_partial = bool(
                    partial_parse_file and can_timeout_recover
                )
                if can_parse_partial:
                    partial_results_mode = True
                    parse_file = partial_parse_file
                    partial_notice = [
                        "",
                        "[!] Nuclei did not exit cleanly (code: {})".format(
                            process.returncode
                        ),
                        "[*] Continuing with partial results from: {}".format(
                            parse_file
                        ),
                    ]
                    SwingUtilities.invokeLater(
                        lambda t="\n".join(partial_notice) + "\n": self.nuclei_area.append(t)
                    )
                    SwingUtilities.invokeLater(
                        lambda: self.log_to_ui(
                            "[*] Nuclei partial-parse mode enabled (exit {})".format(
                                process.returncode
                            )
                        )
                    )
                elif can_timeout_recover:
                    synthesized_partial_file = os.path.join(
                        temp_dir, "partial_results.jsonl"
                    )
                    recovered_count = self._write_nuclei_partial_results_jsonl(
                        combined_output, synthesized_partial_file
                    )
                    if os.path.exists(synthesized_partial_file):
                        partial_results_mode = True
                        parse_file = synthesized_partial_file
                        partial_notice = [
                            "",
                            "[!] Nuclei did not exit cleanly (code: {})".format(
                                process.returncode
                            ),
                            "[*] Recovered {} plain-output findings into partial JSONL".format(
                                recovered_count
                            ),
                            "[*] Continuing with synthesized partial results: {}".format(
                                parse_file
                            ),
                        ]
                        SwingUtilities.invokeLater(
                            lambda t="\n".join(partial_notice)
                            + "\n": self.nuclei_area.append(t)
                        )
                        SwingUtilities.invokeLater(
                            lambda: self.log_to_ui(
                                "[*] Nuclei synthesized partial mode enabled (exit {})".format(
                                    process.returncode
                                )
                            )
                        )
                    else:
                        fail_lines = [
                            "",
                            "[!] Nuclei command failed",
                            "[!] Exit code: {}".format(process.returncode),
                            "[!] Command: {}".format(display_cmd),
                            "[*] Timeout recovery was attempted but no parseable output was produced.",
                        ]
                        fail_text = "\n".join(fail_lines) + "\n"
                        SwingUtilities.invokeLater(
                            lambda t=fail_text: self.nuclei_area.append(t)
                        )
                        return
                else:
                    fail_lines = [
                        "",
                        "[!] Nuclei command failed",
                        "[!] Exit code: {}".format(process.returncode),
                        "[!] Command: {}".format(display_cmd),
                    ]
                    if output_preview:
                        fail_lines.append("[!] Output:")
                        fail_lines.append(output_preview[:3000])
                    if "flag provided but not defined" in combined_output:
                        fail_lines.append(
                            "[*] Tip: your Nuclei version does not support one of these flags."
                        )
                        fail_lines.append(
                            "[*] Try removing unsupported flags from Custom Cmd (for example: -random-agent)."
                        )
                    if use_custom_nuclei:
                        fail_lines.append(
                            "[*] Tip: ensure custom command writes JSON lines to {json_file}"
                        )
                    fail_text = "\n".join(fail_lines) + "\n"
                    SwingUtilities.invokeLater(
                        lambda t=fail_text: self.nuclei_area.append(t)
                    )
                    SwingUtilities.invokeLater(
                        lambda: self.log_to_ui(
                            "[!] Nuclei failed with exit code {}".format(
                                process.returncode
                            )
                        )
                    )
                    return

            if not partial_results_mode:
                if os.path.exists(json_file):
                    parse_file = json_file
                elif os.path.exists(output_file):
                    parse_file = output_file
                    SwingUtilities.invokeLater(
                        lambda: self.nuclei_area.append(
                            "[*] Using output fallback parser: {}\n".format(output_file)
                        )
                    )
                else:
                    warn_lines = [
                        "",
                        "[!] Nuclei completed but expected results file was not created",
                        "[!] Expected JSON file: {}".format(json_file),
                        "[!] Fallback output file: {}".format(output_file),
                        "[!] Command: {}".format(display_cmd),
                    ]
                    if output_preview:
                        warn_lines.append("[!] Output:")
                        warn_lines.append(output_preview[:3000])
                    if use_custom_nuclei:
                        warn_lines.append(
                            "[*] Tip: include {json_file} in Custom Cmd and make nuclei write json output there"
                        )
                    warn_text = "\n".join(warn_lines) + "\n"
                    SwingUtilities.invokeLater(
                        lambda t=warn_text: self.nuclei_area.append(t)
                    )
                    SwingUtilities.invokeLater(
                        lambda: self.log_to_ui(
                            "[!] Nuclei produced no parseable results file"
                        )
                    )
                    return

            # Parse JSON results and group by severity
            findings_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
            vuln_count = 0
            json_parse_errors = 0

            try:
                with open(parse_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                vuln_count += 1
                                severity = vuln.get('info', {}).get('severity', 'info').lower()
                                template = vuln.get('template-id', 'unknown')
                                matched = vuln.get('matched-at', vuln.get('host', ''))
                                findings_by_severity.get(severity, findings_by_severity['info']).append(
                                    "[{}] {}".format(template, matched)
                                )
                            except Exception as json_err:
                                json_parse_errors += 1
                                self._callbacks.printError(
                                    "Nuclei JSON parse error: {}".format(str(json_err))
                                )
            except Exception as e:
                self._callbacks.printError("Error reading JSON: {}".format(str(e)))
                read_fail = (
                    "\n[!] Failed to read Nuclei JSON results from {}: {}\n".format(
                        parse_file, str(e)
                    )
                )
                SwingUtilities.invokeLater(
                    lambda t=read_fail: self.nuclei_area.append(t)
                )
                return

            uses_recon_target_list = (not use_custom_nuclei) or (
                targets_file in display_cmd
            )
            target_summary = (
                str(target_count)
                if uses_recon_target_list
                else "Custom command (not using generated target list)"
            )
            result = ["\n" + "=" * 80, "NUCLEI SCAN RESULTS", "=" * 80, ""]
            result.append("[*] Scan Time: {}s".format(elapsed))
            result.append("[*] Targets: {}".format(target_summary))
            result.append("[*] Total Findings: {}".format(vuln_count))
            result.append("[*] Parsed results file: {}".format(parse_file))
            if partial_results_mode:
                result.append(
                    "[*] Run status: partial results (process exited {})".format(
                        process.returncode
                    )
                )
            if json_parse_errors > 0:
                result.append(
                    "[*] Ignored non-JSON lines: {}".format(json_parse_errors)
                )
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
                result.append("    - Full results: {}".format(parse_file))

                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[+] Found {} vulnerabilities".format(vuln_count))
                )
            else:
                result.append("[+] No vulnerabilities found")
                if uses_recon_target_list:
                    result.append(
                        "[*] All {} targets scanned successfully".format(
                            target_count
                        )
                    )
                else:
                    result.append(
                        "[*] Custom command completed successfully"
                    )
                    result.append(
                        "[*] Note: target count is defined by your custom command"
                    )
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
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] Error: {}".format(m))
            )
        finally:
            self._clear_active_tool_process("nuclei", process)
            self._clear_tool_cancel("nuclei")
            self._cleanup_temp_dir(temp_dir, "nuclei scan")

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

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
    if not self._validate_binary_signature(
        "HTTPX",
        httpx_path,
        self.httpx_area,
        required_tokens=["-status-code", "-tech-detect", "-title"],
        forbidden_tokens=[
            "a next generation http client",
            "usage: httpx <url> [options]",
        ],
        fix_hint="Use ProjectDiscovery httpx (for example: /home/teycir/go/bin/httpx), not the Python httpx client CLI.",
    ):
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

    use_custom_httpx, custom_httpx_command = self._resolve_custom_command(
        "HTTPX",
        self.httpx_custom_cmd_checkbox,
        self.httpx_custom_cmd_field,
        {"httpx_path": httpx_path, "urls_file": urls_file},
        self.httpx_area,
    )
    if use_custom_httpx and not custom_httpx_command:
        self._cleanup_temp_dir(temp_dir, "httpx custom command validation")
        return

    self.httpx_area.setText("[*] Initializing HTTPX...\n")
    self.httpx_area.append("[*] Targets: {} URLs\n".format(target_count))
    self.log_to_ui("[*] HTTPX: Starting scan on {} URLs".format(target_count))
    self._clear_tool_cancel("httpx")

    def run_scan():
        process = None
        try:
            if use_custom_httpx and custom_httpx_command:
                cmd = self._build_shell_command(custom_httpx_command)
                display_cmd = custom_httpx_command
                SwingUtilities.invokeLater(
                    lambda: self.httpx_area.append(
                        "[*] Custom command override enabled\n"
                    )
                )
            else:
                cmd = [
                    httpx_path,
                    "-l",
                    urls_file,
                    "-status-code",
                    "-nc",
                    "-silent",
                ]
                display_cmd = " ".join(cmd)
            SwingUtilities.invokeLater(
                lambda: self.httpx_area.append(
                    "[*] Command: {}\n\n".format(display_cmd)
                )
            )

            start_time = time_module.time()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                shell=False,
            )
            self._set_active_tool_process("httpx", process)

            # Collect results grouped by status
            results_by_status = {'2xx': [], '3xx': [], '4xx': [], '5xx': []}
            last_update = start_time
            cancelled_by_user = False

            while True:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    if self._is_tool_cancelled("httpx"):
                        cancelled_by_user = True
                        self._terminate_process_cross_platform(process, "HTTPX")
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

                line_text = self._decode_process_data(line, "HTTPX stdout line")
                clean_line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line_text).strip()
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
            if cancelled_by_user:
                SwingUtilities.invokeLater(
                    lambda: self.httpx_area.append(
                        "\n[!] HTTPX run cancelled by user\n"
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] HTTPX cancelled by user")
                )
                return
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
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] HTTPX error: {}".format(m))
            )
        finally:
            self._clear_active_tool_process("httpx", process)
            self._clear_tool_cancel("httpx")
            self._cleanup_temp_dir(temp_dir, "httpx scan")

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

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
    if not self._validate_binary_signature(
        "Katana",
        katana_path,
        self.katana_area,
        required_tokens=["-depth", "-js-crawl", "-silent"],
        forbidden_tokens=[],
        fix_hint="Set Katana Path to your local ProjectDiscovery katana binary (for example: /home/teycir/go/bin/katana).",
    ):
        return

    # Use temp directory instead of auto-saving
    temp_dir = tempfile.mkdtemp(prefix="burp_katana_")
    urls_file = os.path.join(temp_dir, "urls.txt")

    seed_urls, target_meta = self._collect_katana_seed_urls()
    if not seed_urls:
        self._cleanup_temp_dir(temp_dir, "katana empty target set")
        self.katana_area.setText(
            "[!] No Katana targets after filtering. Capture more first-party API traffic or adjust host filter.\n"
        )
        return

    writer = None
    try:
        writer = FileWriter(urls_file)
        for seed in seed_urls:
            writer.write(seed + "\n")
    finally:
        if writer:
            writer.close()

    use_custom_katana, custom_katana_command = self._resolve_custom_command(
        "Katana",
        self.katana_custom_cmd_checkbox,
        self.katana_custom_cmd_field,
        {"katana_path": katana_path, "urls_file": urls_file},
        self.katana_area,
    )
    if use_custom_katana and not custom_katana_command:
        self._cleanup_temp_dir(temp_dir, "katana custom command validation")
        return
    uses_recon_host_list = (not use_custom_katana) or (urls_file in custom_katana_command)

    self.katana_area.setText("[*] Initializing Katana...\n")
    self.katana_area.append(
        "[*] Targets: {} hosts ({} raw candidates)\n".format(
            len(seed_urls), target_meta.get("raw_candidates", len(seed_urls))
        )
    )
    if target_meta.get("manual_scope_enabled"):
        self.katana_area.append(
            "[*] Target base scope: {} lines | hosts={} | bases={}\n".format(
                target_meta.get("manual_scope_line_count", 0),
                target_meta.get("manual_scope_host_count", 0),
                target_meta.get("manual_scope_base_count", 0),
            )
        )
        preview = target_meta.get("manual_scope_preview", [])
        if preview:
            self.katana_area.append(
                "[*] Scope preview: {}\n".format(", ".join(preview))
            )
    elif target_meta.get("force_host"):
        self.katana_area.append(
            "[*] Host scope: {}\n".format(target_meta.get("selected_host", "unknown"))
        )
    else:
        allowed_bases = target_meta.get("allowed_bases", [])
        if allowed_bases:
            self.katana_area.append(
                "[*] First-party base scope: {}\n".format(", ".join(allowed_bases))
            )
    self.katana_area.append(
        "[*] Filtered out: noise-host={} scope-host={}\n".format(
            target_meta.get("dropped_noise_host", 0),
            target_meta.get("dropped_scope_host", 0),
        )
    )
    if target_meta.get("truncated", 0) > 0:
        self.katana_area.append(
            "[*] Target cap applied: {} skipped (max {})\n".format(
                target_meta.get("truncated", 0), self.KATANA_MAX_TARGETS
            )
        )
    if use_custom_katana and not uses_recon_host_list:
        self.katana_area.append(
            "[*] Note: custom command defines target scope (generated host list not referenced)\n"
        )
    self.log_to_ui("[*] Katana: Starting crawl on {} hosts".format(len(seed_urls)))
    self._clear_tool_cancel("katana")

    def run_scan():
        process = None
        try:
            if use_custom_katana and custom_katana_command:
                cmd = self._build_shell_command(custom_katana_command)
                display_cmd = custom_katana_command
                SwingUtilities.invokeLater(
                    lambda: self.katana_area.append(
                        "[*] Custom command override enabled\n"
                    )
                )
            else:
                cmd = [
                    katana_path,
                    "-list",
                    urls_file,
                    "-d",
                    "1",
                    "-jc",
                    "-silent",
                ]
                display_cmd = " ".join(cmd)
            SwingUtilities.invokeLater(
                lambda: self.katana_area.append(
                    "[*] Command: {}\n\n".format(display_cmd)
                )
            )

            start_time = time_module.time()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                shell=False,
            )
            self._set_active_tool_process("katana", process)

            line_count = 0
            last_update = start_time
            results = []
            while True:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    if self._is_tool_cancelled("katana"):
                        self._terminate_process_cross_platform(process, "Katana")
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
                line_text = self._decode_process_data(line, "Katana stdout line")
                clean_line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line_text.strip())
                if clean_line:
                    if uses_recon_host_list and not self._katana_result_in_scope(
                        clean_line, target_meta
                    ):
                        continue
                    results.append(clean_line)
                    SwingUtilities.invokeLater(
                        lambda l=clean_line: self.katana_area.append(l + "\n")
                    )
                    line_count += 1

            process.wait()
            elapsed = int(time_module.time() - start_time)
            if self._is_tool_cancelled("katana"):
                SwingUtilities.invokeLater(
                    lambda: self.katana_area.append(
                        "\n[!] Katana run cancelled by user\n"
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] Katana cancelled by user")
                )
                return
            stderr_data = process.stderr.read() if process.stderr else ""
            if not isinstance(stderr_data, str):
                try:
                    stderr_data = stderr_data.decode("utf-8", errors="ignore")
                except Exception as e:
                    self._callbacks.printError(
                        "Katana stderr decode error: {}".format(str(e))
                    )
                    stderr_data = str(stderr_data)

            # Store results in memory only - don't auto-save
            with self.katana_lock:
                self.katana_discovered = results

            if process.returncode != 0:
                fail_lines = [
                    "",
                    "[!] Katana command failed",
                    "[!] Exit code: {}".format(process.returncode),
                    "[!] Command: {}".format(display_cmd),
                ]
                if results:
                    fail_lines.append(
                        "[!] Partial output captured: {} URLs".format(len(results))
                    )
                if stderr_data and stderr_data.strip():
                    fail_lines.append("[!] STDERR:")
                    fail_lines.append(stderr_data.strip()[:3000])
                fail_text = "\n".join(fail_lines) + "\n"
                SwingUtilities.invokeLater(
                    lambda t=fail_text: self.katana_area.append(t)
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[!] Katana failed with exit code {}".format(
                            process.returncode
                        )
                    )
                )
                return

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
            if uses_recon_host_list:
                summary += "[*] Targets: {} hosts\n".format(len(seed_urls))
            else:
                summary += "[*] Targets: Custom command (scope defined by command)\n"
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
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] Katana error: {}".format(m))
            )
        finally:
            self._clear_active_tool_process("katana", process)
            self._clear_tool_cancel("katana")
            self._cleanup_temp_dir(temp_dir, "katana scan")

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

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
    if not self._validate_binary_signature(
        "FFUF",
        ffuf_path,
        self.ffuf_area,
        required_tokens=["fuzz faster u fool", "-json", "-noninteractive"],
        forbidden_tokens=[],
        fix_hint="Set FFUF Path to your local ffuf binary (for example: /home/teycir/go/bin/ffuf).",
    ):
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

    targets, target_meta = self._collect_ffuf_targets()
    if not targets:
        self.ffuf_area.setText(
            "[!] No FFUF targets after filtering. Capture more first-party API traffic or adjust host filter.\n"
        )
        return

    self.ffuf_area.setText("[*] Initializing FFUF...\n")
    self.ffuf_area.append(
        "[*] Targets: {} (from Recon tab; {} raw candidates)\n".format(
            len(targets), target_meta.get("raw_candidates", len(targets))
        )
    )
    if target_meta.get("manual_scope_enabled"):
        self.ffuf_area.append(
            "[*] Target base scope: {} lines | hosts={} | bases={}\n".format(
                target_meta.get("manual_scope_line_count", 0),
                target_meta.get("manual_scope_host_count", 0),
                target_meta.get("manual_scope_base_count", 0),
            )
        )
        preview = target_meta.get("manual_scope_preview", [])
        if preview:
            self.ffuf_area.append(
                "[*] Scope preview: {}\n".format(", ".join(preview))
            )
    elif target_meta.get("force_host"):
        self.ffuf_area.append(
            "[*] Host scope: {}\n".format(target_meta.get("selected_host", "unknown"))
        )
    else:
        allowed_bases = target_meta.get("allowed_bases", [])
        if allowed_bases:
            self.ffuf_area.append(
                "[*] First-party base scope: {}\n".format(", ".join(allowed_bases[:3]))
            )
    self.ffuf_area.append(
        "[*] Filtered out: noise-host={} scope-host={} path-noise={}\n".format(
            target_meta.get("dropped_noise_host", 0),
            target_meta.get("dropped_scope_host", 0),
            target_meta.get("dropped_path", 0),
        )
    )
    if target_meta.get("truncated", 0) > 0:
        self.ffuf_area.append(
            "[*] Target cap applied: {} skipped (max {})\n".format(
                target_meta.get("truncated", 0), self.FFUF_MAX_TARGETS
            )
        )
    # Count wordlist size
    try:
        with open(wordlist, 'r') as f:
            word_count = sum(1 for line in f if line.strip())
        self.ffuf_area.append("[*] Wordlist: {} ({} words)\n".format(wordlist, word_count))
    except (IOError, OSError) as e:
        self._callbacks.printError(
            "FFUF wordlist count failed for {}: {}".format(wordlist, str(e))
        )
        self.ffuf_area.append("[*] Wordlist: {}\n".format(wordlist))
    self.ffuf_area.append(
        "[*] Threads: {}, Timeout: {}s, Rate: {}/s, Max: {}s/target\n".format(
            self.FFUF_THREADS,
            self.FFUF_REQUEST_TIMEOUT_SECONDS,
            self.FFUF_RATE_LIMIT,
            self.FFUF_TARGET_TIMEOUT_SECONDS
        )
    )
    self.ffuf_area.append(
        "[*] Filtering: static paths + tracker/ad paths + third-party hosts\n\n"
    )
    self.log_to_ui("[*] FFUF: {} targets from Recon".format(len(targets)))
    self._clear_tool_cancel("ffuf")

    def run_scan():
        process = None
        try:
            all_matches = []
            total_start = time_module.time()
            cancelled_by_user = False

            # Batch UI update - accumulate messages
            progress_msg = "\n[*] Scanning {} targets...\n\n".format(len(targets))
            SwingUtilities.invokeLater(
                lambda: self.ffuf_area.append(progress_msg)
            )

            idx = 0
            for target in targets:
                if self._is_tool_cancelled("ffuf"):
                    cancelled_by_user = True
                    break
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
                        str(self.FFUF_THREADS),
                        "-timeout",
                        str(self.FFUF_REQUEST_TIMEOUT_SECONDS),
                        "-rate",
                        str(self.FFUF_RATE_LIMIT),
                        "-json",
                        "-noninteractive",
                        "-H",
                        "User-Agent: Mozilla/5.0",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                )
                self._set_active_tool_process("ffuf", process)

                # Thread-safe output gobbler
                stdout_lines = []
                output_lock = threading.Lock()

                def stream_reader(pipe, output_list, lock=output_lock):
                    try:
                        while True:
                            line = pipe.readline()
                            if not line:
                                break
                            line_text = self._decode_process_data(
                                line, "FFUF stdout line"
                            )
                            if line_text:
                                with lock:
                                    output_list.append(line_text)
                    finally:
                        pipe.close()

                stdout_thread = threading.Thread(
                    target=stream_reader, args=(process.stdout, stdout_lines)
                )
                stdout_thread.daemon = True
                stdout_thread.start()

                target_matches = []
                timeout = self.FFUF_TARGET_TIMEOUT_SECONDS
                timed_out = False

                # Pure timeout loop
                start_wait = time_module.time()
                while process.poll() is None:
                    if self._is_tool_cancelled("ffuf"):
                        cancelled_by_user = True
                        self._terminate_process_cross_platform(process, "FFUF")
                        break
                    if time_module.time() - start_wait > timeout:
                        timed_out = True
                        try:
                            process.kill()
                            process.wait()
                        except Exception as e:
                            self._callbacks.printError(
                                "FFUF process kill failed: {}".format(str(e))
                            )
                        SwingUtilities.invokeLater(
                            lambda t=target: self.ffuf_area.append(
                                "[!] Timeout after {}s ({})\n".format(timeout, t)
                            )
                        )
                        break
                    time_module.sleep(0.5)

                stdout_thread.join(timeout=2)
                process.wait()
                self._clear_active_tool_process("ffuf", process)

                if cancelled_by_user:
                    break

                # Parse JSON output
                if not timed_out:
                    with output_lock:
                        lines_snapshot = list(stdout_lines)

                    invalid_json_lines = 0
                    for line in lines_snapshot:
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
                            invalid_json_lines += 1

                    if invalid_json_lines > 0:
                        SwingUtilities.invokeLater(
                            lambda c=invalid_json_lines: self.ffuf_area.append(
                                "[!] FFUF parse warnings: {} invalid JSON lines\n".format(
                                    c
                                )
                            )
                        )
                        self._callbacks.printError(
                            "FFUF parse warnings: {} invalid JSON lines".format(
                                invalid_json_lines
                            )
                        )

                elapsed = time_module.time() - start
                all_matches.extend(target_matches)

                SwingUtilities.invokeLater(
                    lambda e=elapsed, m=len(target_matches): self.ffuf_area.append(
                        "[+] Complete: {:.1f}s | {} matches\n\n".format(e, m)
                    )
                )

            if cancelled_by_user:
                with self.ffuf_lock:
                    self.ffuf_results = all_matches
                SwingUtilities.invokeLater(
                    lambda: self.ffuf_area.append(
                        "\n[!] FFUF run cancelled by user\n"
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] FFUF cancelled by user")
                )
                return

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
                except (IndexError, ValueError):
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
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] FFUF error: {}".format(m))
            )
        finally:
            self._clear_active_tool_process("ffuf", process)
            self._clear_tool_cancel("ffuf")

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

def _run_wayback(self):
    """Discover historical endpoints using Wayback Machine API"""
    import os
    import subprocess
    import threading
    import tempfile
    import time as time_module

    if not self.api_data:
        self.wayback_area.setText(
            "[!] No endpoints in Recon tab. Capture or import first\n"
        )
        return

    queries, query_meta = self._collect_wayback_queries()

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
            limit = "50"
    except ValueError:
        from_year = "2020"
        to_year = current_year
        limit = "50"

    if not queries:
        self.wayback_area.setText("[!] No hosts found in Recon tab\n")
        return

    wayback_temp_dir = None
    wayback_targets_file = None
    use_custom_wayback = False
    custom_wayback_command = None

    if self.wayback_custom_cmd_checkbox.isSelected():
        wayback_temp_dir = tempfile.mkdtemp(prefix="burp_wayback_")
        wayback_targets_file = os.path.join(wayback_temp_dir, "targets.txt")
        writer = None
        try:
            writer = FileWriter(wayback_targets_file)
            for host, path in queries:
                target = host + path if path else host
                writer.write(target + "\n")
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError(
                        "Wayback target file close error: {}".format(str(e))
                    )

        use_custom_wayback, custom_wayback_command = self._resolve_custom_command(
            "Wayback",
            self.wayback_custom_cmd_checkbox,
            self.wayback_custom_cmd_field,
            {
                "targets_file": wayback_targets_file,
                "from_year": from_year,
                "to_year": to_year,
                "limit": limit,
            },
            self.wayback_area,
        )
        if use_custom_wayback and not custom_wayback_command:
            self._cleanup_temp_dir(
                wayback_temp_dir, "wayback custom command validation"
            )
            return
        if use_custom_wayback and custom_wayback_command:
            if not self._validate_wayback_custom_command_tools(
                custom_wayback_command, self.wayback_area
            ):
                self._cleanup_temp_dir(
                    wayback_temp_dir, "wayback custom command tool validation"
                )
                return
    uses_recon_query_list = (not use_custom_wayback) or (
        wayback_targets_file and wayback_targets_file in custom_wayback_command
    )

    self.wayback_area.setText("[*] Querying Wayback Machine...\n")
    self.wayback_area.append(
        "[*] Targets: {} hosts + {} paths\n".format(
            query_meta.get("host_count", 0), query_meta.get("path_count", 0)
        )
    )
    if query_meta.get("manual_scope_enabled"):
        self.wayback_area.append(
            "[*] Target base scope: {} lines | hosts={} | bases={}\n".format(
                query_meta.get("manual_scope_line_count", 0),
                query_meta.get("manual_scope_host_count", 0),
                query_meta.get("manual_scope_base_count", 0),
            )
        )
        preview = query_meta.get("manual_scope_preview", [])
        if preview:
            self.wayback_area.append(
                "[*] Scope preview: {}\n".format(", ".join(preview))
            )
    elif query_meta.get("force_host"):
        self.wayback_area.append(
            "[*] Host scope: {}\n".format(query_meta.get("selected_host", "unknown"))
        )
    else:
        allowed_bases = query_meta.get("allowed_bases", [])
        if allowed_bases:
            self.wayback_area.append(
                "[*] First-party base scope: {}\n".format(", ".join(allowed_bases))
            )
    self.wayback_area.append(
        "[*] Filtered out: noise-host={} scope-host={} path-noise={}\n".format(
            query_meta.get("dropped_noise_host", 0),
            query_meta.get("dropped_scope_host", 0),
            query_meta.get("dropped_path", 0),
        )
    )
    if query_meta.get("truncated", 0) > 0:
        self.wayback_area.append(
            "[*] Query cap applied: {} skipped (max {})\n".format(
                query_meta.get("truncated", 0), self.WAYBACK_MAX_QUERIES
            )
        )
    self.wayback_area.append("[*] Date Range: {}-{}\n".format(from_year, to_year))
    self.wayback_area.append("[*] Limit: {} per target\n\n".format(limit))
    if use_custom_wayback and custom_wayback_command:
        self.wayback_area.append("[*] Mode: Custom command override\n")
        self.wayback_area.append("[*] Command: {}\n\n".format(custom_wayback_command))
        if not uses_recon_query_list:
            self.wayback_area.append(
                "[*] Note: custom command defines query scope (generated target list not referenced)\n\n"
            )
    self.log_to_ui(
        "[*] Wayback: {} queries ({}-{})".format(len(queries), from_year, to_year)
    )
    self._clear_tool_cancel("wayback")

    def run_discovery():
        process = None
        try:
            import json

            import urllib2  # type: ignore

            all_urls = []
            seen_urls = set()
            start_time = time_module.time()
            error_count = 0
            backoff_time = 3.0  # Start with 3s delay
            custom_warning_lines = []
            cancelled_by_user = False

            if use_custom_wayback and custom_wayback_command:
                cmd = self._build_shell_command(custom_wayback_command)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    shell=False,
                )
                self._set_active_tool_process("wayback", process)
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui(
                        "[*] Wayback custom cmd: {}".format(custom_wayback_command)
                    )
                )

                while True:
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        if self._is_tool_cancelled("wayback"):
                            cancelled_by_user = True
                            self._terminate_process_cross_platform(
                                process, "Wayback"
                            )
                            break
                        time_module.sleep(0.1)
                        continue

                    line = self._decode_process_data(line, "Wayback stdout line")

                    normalized = self._normalize_wayback_entry(line)
                    if not normalized:
                        continue

                    original_url = normalized.split(" | ", 1)[0]
                    if original_url in seen_urls:
                        continue

                    seen_urls.add(original_url)
                    all_urls.append(normalized)
                    SwingUtilities.invokeLater(
                        lambda u=original_url: self.wayback_area.append(
                            "  [+] {}\n".format(u)
                        )
                        )

                stderr_data = process.stderr.read() if process.stderr else ""
                process.wait()
                if self._is_tool_cancelled("wayback"):
                    cancelled_by_user = True
                if not isinstance(stderr_data, str):
                    try:
                        stderr_data = stderr_data.decode("utf-8", errors="ignore")
                    except Exception as e:
                        self._callbacks.printError(
                            "Wayback stderr decode error: {}".format(str(e))
                        )
                        stderr_data = str(stderr_data)

                if process.returncode != 0:
                    err_preview = (stderr_data or "").strip()
                    if len(err_preview) > 300:
                        err_preview = err_preview[:300] + "..."
                    if all_urls:
                        warning = (
                            "[!] Custom command exited with code {} after producing {} snapshots".format(
                                process.returncode, len(all_urls)
                            )
                        )
                        custom_warning_lines.append(warning)
                        if err_preview:
                            custom_warning_lines.append(
                                "[!] STDERR: {}".format(err_preview)
                            )
                        SwingUtilities.invokeLater(
                            lambda w=warning: self.wayback_area.append(w + "\n")
                        )
                        SwingUtilities.invokeLater(
                            lambda: self.log_to_ui(
                                "[!] Wayback custom command partial failure (exit {})".format(
                                    process.returncode
                                )
                            )
                        )
                    else:
                        error_count = len(queries)
                        raise Exception(
                            "Custom command failed (exit {}): {}".format(
                                process.returncode,
                                err_preview or "no stderr output",
                            )
                        )
            else:
                idx = 0
                for host, path in queries:
                    if self._is_tool_cancelled("wayback"):
                        cancelled_by_user = True
                        break
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
                            except Exception as retry_err:
                                if attempt == max_retries:
                                    raise
                                self._callbacks.printError(
                                    "Wayback transient attempt {} failed: {}".format(
                                        attempt, str(retry_err)
                                    )
                                )
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
                    if self._is_tool_cancelled("wayback"):
                        cancelled_by_user = True
                        break
                    time_module.sleep(4.0)  # 15 req/min (safe rate limiting)

            if cancelled_by_user:
                with self.wayback_lock:
                    self.wayback_discovered = all_urls
                SwingUtilities.invokeLater(
                    lambda c=len(all_urls): self.wayback_area.append(
                        "\n[!] Wayback run cancelled by user (partial snapshots: {})\n".format(
                            c
                        )
                    )
                )
                SwingUtilities.invokeLater(
                    lambda: self.log_to_ui("[!] Wayback cancelled by user")
                )
                return

            elapsed = int(time_module.time() - start_time)

            # Store results
            with self.wayback_lock:
                self.wayback_discovered = all_urls

            summary = "\n" + "=" * 80 + "\n"
            summary += "WAYBACK DISCOVERY RESULTS\n"
            summary += "=" * 80 + "\n"
            summary += "[*] Query Time: {}s (~{}min)\n".format(elapsed, elapsed // 60)
            if uses_recon_query_list:
                summary += "[*] Queries: {} (hosts + paths)\n".format(len(queries))
            else:
                summary += "[*] Queries: Custom command (scope defined by command)\n"
            summary += "[*] Snapshots Found: {}\n".format(len(all_urls))
            if uses_recon_query_list:
                summary += "[*] Success Rate: {}%\n".format(
                    int((len(queries) - error_count) * 100.0 / len(queries)) if len(queries) > 0 else 0
                )
            else:
                summary += "[*] Success Rate: N/A (custom mode)\n"
            if custom_warning_lines:
                summary += "\n" + "\n".join(custom_warning_lines) + "\n"
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
                    except Exception as e:
                        self._callbacks.printError(
                            "Wayback endpoint parse error: {}".format(str(e))
                        )
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
            err_msg = str(e)
            SwingUtilities.invokeLater(
                lambda m=err_msg: self.log_to_ui("[!] Wayback error: {}".format(m))
            )
        finally:
            self._clear_active_tool_process("wayback", process)
            self._clear_tool_cancel("wayback")
            if wayback_temp_dir:
                self._cleanup_temp_dir(wayback_temp_dir, "wayback scan")

    thread = threading.Thread(target=run_discovery)
    thread.daemon = True
    thread.start()
