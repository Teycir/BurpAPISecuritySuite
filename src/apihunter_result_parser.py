# -*- coding: utf-8 -*-
"""ApiHunter NDJSON result parser for BurpAPISecuritySuite."""

import json
import re

def parse_apihunter_ndjson(results_file, callbacks, ascii_safe_fn, top_findings_min_severity="medium"):
    """Parse ApiHunter NDJSON output and return formatted summary."""
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    min_rank = severity_order.get(top_findings_min_severity.lower(), 3)
    
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    scanner_counts = {}
    
    try:
        with open(results_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    severity = ascii_safe_fn(entry.get("severity", "info"), lower=True).strip()
                    scanner = ascii_safe_fn(entry.get("scanner", "unknown")).strip()
                    target = ascii_safe_fn(entry.get("target", "")).strip()
                    title = ascii_safe_fn(entry.get("title", "")).strip()
                    evidence = ascii_safe_fn(entry.get("evidence", "")).strip()
                    remediation = ascii_safe_fn(entry.get("remediation", "")).strip()
                    
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
                    
                    findings.append({
                        "severity": severity,
                        "scanner": scanner,
                        "target": target,
                        "title": title,
                        "evidence": evidence,
                        "remediation": remediation,
                        "rank": severity_order.get(severity, 0)
                    })
                except (ValueError, TypeError) as parse_err:
                    callbacks.printError("ApiHunter NDJSON parse error: {}".format(str(parse_err)))
                    continue
    except (IOError, OSError) as e:
        return "[!] Failed to read results file: {}\n".format(str(e))
    
    total = sum(severity_counts.values())
    
    summary = ["\n" + "=" * 80, "APIHUNTER SCAN RESULTS", "=" * 80, ""]
    summary.append("[*] Total Findings: {}".format(total))
    summary.append("[*] Critical: {}".format(severity_counts["critical"]))
    summary.append("[*] High: {}".format(severity_counts["high"]))
    summary.append("[*] Medium: {}".format(severity_counts["medium"]))
    summary.append("[*] Low: {}".format(severity_counts["low"]))
    summary.append("[*] Info: {}".format(severity_counts["info"]))
    summary.append("")
    
    if scanner_counts:
        summary.append("Top checks:")
        for scanner, count in sorted(scanner_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            summary.append("  {}: {}".format(scanner, count))
        summary.append("")
    
    findings.sort(key=lambda x: x["rank"], reverse=True)
    filtered_findings = [f for f in findings if f["rank"] >= min_rank]
    
    if filtered_findings:
        summary.append("=" * 80)
        summary.append("TOP FINDINGS (>= {})".format(top_findings_min_severity.upper()))
        summary.append("=" * 80)
        for finding in filtered_findings[:20]:
            summary.append("")
            summary.append("[{}] {}".format(finding["severity"].upper(), finding["title"]))
            summary.append("  Scanner: {}".format(finding["scanner"]))
            summary.append("  Target: {}".format(finding["target"]))
            if finding["evidence"]:
                summary.append("  Evidence: {}".format(finding["evidence"][:200]))
            if finding["remediation"]:
                summary.append("  Remediation: {}".format(finding["remediation"][:200]))
        if len(filtered_findings) > 20:
            summary.append("")
            summary.append("... ({} more findings not shown)".format(len(filtered_findings) - 20))
    
    summary.append("")
    summary.append("=" * 80)
    summary.append("SUMMARY")
    summary.append("=" * 80)
    summary.append("[*] Findings displayed: {} (filtered by min severity: {})".format(
        len(filtered_findings), top_findings_min_severity.upper()
    ))
    summary.append("[*] Total findings in scan: {}".format(total))
    
    return "\n".join(summary) + "\n", findings

__all__ = ["parse_apihunter_ndjson"]
