# Documentation Index

**BurpAPISecuritySuite Documentation**

## Quick Access

### Getting Started
- **[README.md](../README.md)** - Main extension documentation and installation guide

### Performance & Optimization
- **[NUCLEI_OPTIMIZATION.md](NUCLEI_OPTIMIZATION.md)** - Nuclei performance optimization guide
- **[NUCLEI_OPTIMIZATION_SUMMARY.md](NUCLEI_OPTIMIZATION_SUMMARY.md)** - Technical optimization summary
- **[DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)** - v1.2.1 deployment checklist

### Reference
- **[loggerpp_tags.md](loggerpp_tags.md)** - Logger++ tags reference
- **[Architecture.md](Architecture.md)** - One-page architecture for State Matrix, Golden Ticket, and AI evidence graph

## Documentation Structure

```
BurpAPISecuritySuite/
├── README.md                          # Main extension documentation
├── CHANGELOG.md                       # Version history
└── docs/
    ├── DOCUMENTATION-INDEX.md         # This file
    ├── Architecture.md                # Core architecture overview
    ├── NUCLEI_OPTIMIZATION.md         # Nuclei performance guide
    ├── NUCLEI_OPTIMIZATION_SUMMARY.md # Technical optimization summary
    ├── DEPLOYMENT_CHECKLIST.md        # v1.2.1 deployment checklist
    └── loggerpp_tags.md               # Logger++ tags reference
```

## By Use Case

### First-Time Setup
1. [README.md](../README.md) - Install BurpAPISecuritySuite
2. Configure Jython in Burp Suite
3. Load extension and start capturing traffic

### Performance Optimization
1. [NUCLEI_OPTIMIZATION.md](NUCLEI_OPTIMIZATION.md) - Understand Nuclei optimizations
2. [NUCLEI_OPTIMIZATION_SUMMARY.md](NUCLEI_OPTIMIZATION_SUMMARY.md) - Technical details
3. [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) - Deployment guide

### Troubleshooting
1. [README.md](../README.md) - FAQ section
2. [NUCLEI_OPTIMIZATION.md](NUCLEI_OPTIMIZATION.md) - Nuclei-specific issues

## Key Features by Document

### README.md
- Extension overview
- Installation instructions
- Feature list (15 attack types, 108+ vectors)
- Tab overview (Recon, Logger, Diff, Version Scanner, Param Miner, Fuzzer, Auth Replay, Passive Discovery, Sensitive Data, ApiHunter, Vulners, Nuclei, HTTPX, Katana, FFUF, Wayback, SQLMap Verify, Dalfox Verify, API Assets, OpenAPI Drift, GraphQL)
- Export formats (JSON, Intruder, Turbo, Nuclei, cURL, AI Bundle)
- Use cases (API pentesting, bug bounty, security research)
- FAQ and troubleshooting

### NUCLEI_OPTIMIZATION.md
- Performance optimization guide
- Tag optimization rationale (10 → 4 tags)
- Parameter tuning explanation (timeout, retries, rate limit)
- Testing results on allocine.fr
- When to use custom commands
- Monitoring and troubleshooting

### NUCLEI_OPTIMIZATION_SUMMARY.md
- Technical change summary
- Before/after comparison (15+ min → 2-5 min)
- Performance impact metrics (5-10x faster)
- Code change details (lines modified)
- Testing verification results
- Trade-offs analysis

### DEPLOYMENT_CHECKLIST.md
- v1.2.1 deployment guide
- Verification checklist
- Performance improvements summary
- User impact analysis
- Rollback plan
- Success metrics

### loggerpp_tags.md
- Logger++ integration tags
- Custom tag definitions
- Usage examples

### Architecture.md
- High-level capture-to-analysis pipeline
- State Transition Matrix model
- Golden Ticket model
- AI evidence graph model
- Code ownership map for deep-logic components

## Quick Links

### External Resources
- [Burp Suite](https://portswigger.net/burp)
- [Jython](https://www.jython.org/download)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [HTTPX](https://github.com/projectdiscovery/httpx)
- [Katana](https://github.com/projectdiscovery/katana)
- [FFUF](https://github.com/ffuf/ffuf)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

### Related Projects
- [BurpCopyIssues](https://github.com/Teycir/BurpCopyIssues)
- [BurpWpsScan](https://github.com/Teycir/BurpWpsScan)
- [TimeSeal](https://github.com/Teycir/Timeseal)

## Cheat Sheet

### Quick Commands

#### In Burp → BurpAPISecuritySuite
1. **Recon Tab** → Enable Auto-Capture → Browse target
2. **Fuzzer Tab** → "All" → "Generate" → Review attacks
3. **Export Options:**
   - "Export AI Bundle" → Complete AI-ready context
   - "Export All" → api_analysis.json
   - "Send to Intruder" → BOLA testing
   - "Turbo Intruder" → Race conditions
4. **Passive Discovery Tab** → "Run Invariants" → Deep-logic analysis
5. **Sensitive Data Tab** → "Run Scan" → Regex-based secret/PII extraction
6. **Auth Replay Tab** → Multi-profile authorization testing
7. **ApiHunter Tab** → "Run ApiHunter" → Gap-fill endpoint discovery
8. **Vulners Tab** → "Run Enrichment" → CVE advisory lookup
9. **Nuclei Tab** → "Run Nuclei" → Automated scanning
10. **HTTPX Tab** → "Probe Endpoints" → Technology detection
11. **Katana Tab** → "Crawl Endpoints" → Deep discovery
12. **FFUF Tab** → "Fuzz Directories" → Directory fuzzing
13. **Wayback Tab** → "Discover" → Historical endpoints
14. **SQLMap Verify Tab** → "Run Verify" → SQLi confirmation
15. **Dalfox Verify Tab** → "Run Verify" → XSS confirmation
16. **API Assets Tab** → "Run Discovery" → Asset enumeration
17. **OpenAPI Drift Tab** → "Run Drift" → Spec comparison
18. **GraphQL Tab** → "Run Analysis" → GraphQL testing

### Output Locations
```
~/burp_APIRecon/
├── FullExport_TIMESTAMP/
│   ├── api_analysis.json
│   └── excalibur_bridge_bundle.json
├── HostExport_HOSTNAME_TIMESTAMP/
│   ├── api_analysis.json
│   └── excalibur_bridge_bundle.json
├── AI_Context_TIMESTAMP/
│   ├── ai_bundle.json
│   ├── ai_all_tabs_context.json
│   ├── ai_openai_request.json
│   ├── ai_anthropic_request.json
│   ├── ai_ollama_request.json
│   ├── ai_sequence_invariant_findings.json
│   ├── ai_sequence_evidence_ledger.json
│   ├── ai_golden_ticket_findings.json
│   ├── ai_token_lineage_findings.json
│   └── ai_parity_drift_findings.json
├── SequenceInvariant_Export_TIMESTAMP/
│   ├── counterfactual_differential_findings.json
│   ├── sequence_invariant_findings.json
│   ├── golden_ticket_findings.json
│   ├── state_transition_findings.json
│   ├── token_lineage_findings.json
│   └── parity_drift_findings.json
├── Payloads_TIMESTAMP/payloads.json
├── TurboIntruder_TIMESTAMP/*.py
├── NucleiTargets_TIMESTAMP/targets.txt
├── VersionScan_Export_TIMESTAMP/version_scan.txt
└── ParamMiner_Export_TIMESTAMP/param_mining.txt
```

### Common Workflows

#### 1. API Reconnaissance
```
1. Enable Auto-Capture in Recon tab
2. Browse/scan target application
3. Review captured endpoints
4. Export to JSON for analysis
```

#### 2. Vulnerability Testing
```
1. Generate fuzzing attacks (Fuzzer tab)
2. Send to Burp Intruder for automated testing
3. Export to Turbo Intruder for race conditions
4. Run Nuclei for validation
```

#### 3. AI-Powered Testing
```
1. (Optional) Run Passive Discovery → "Run Invariants"
2. (Optional) In Recon, click "Refresh Invariants"
3. In Recon tab, click "Export AI Bundle"
4. Use APIPentesting to scan from that export:
   ./scripts/scan-nuclei-prioritize.sh /path/to/ai_bundle.json burp-ai-scan
5. Feed Reports/.../priority.json + results.jsonl to AI with
   scripts/AI_TRIAGE_PROMPT.md for sensitive-data-first triage
```

#### 4. External Tool Integration
```
1. Nuclei: Automated vulnerability scanning
2. HTTPX: Fast HTTP probing
3. Katana: Deep web crawling
4. FFUF: Directory/file fuzzing
5. Wayback: Historical endpoint discovery
```

## Document Updates

### v1.4.8 (2026-04-10)
- Updated DOCUMENTATION-INDEX.md with all current tabs
- Updated README.md with v1.4.8 changelog
- Added Wayback rate limiting and UI responsiveness improvements
- Updated roadmap with completed features

### v1.4.6 (2026-04-08)
- Added Vulners tab documentation
- Updated tab overview with ApiHunter and Vulners
- Added incremental report appending workflow

### v1.2.1 (2026-04-05)
- Added NUCLEI_OPTIMIZATION.md
- Added NUCLEI_OPTIMIZATION_SUMMARY.md
- Added DEPLOYMENT_CHECKLIST.md
- Updated DOCUMENTATION-INDEX.md
- Nuclei performance optimization (5-10x faster)
- Removed mobile-specific documentation

### v1.2.0 (2026-04-02)
- Added Auth Replay tab documentation
- Added header extraction workflow
- Updated README with new features

### v1.1.0 (2026-04-02)
- Added custom command override documentation
- Added external tool UX improvements
- Updated troubleshooting guides

### v1.0.0 (Initial Release)
- Initial documentation suite
- Complete feature documentation
- FAQ and troubleshooting

## Contributing

Found an issue or have a suggestion? Please update the relevant documentation:
- Extension features → README.md
- Performance optimization → NUCLEI_OPTIMIZATION.md
- Technical details → NUCLEI_OPTIMIZATION_SUMMARY.md
- Deployment → DEPLOYMENT_CHECKLIST.md

## License

MIT License - Free to use for authorized security testing and research purposes.

## Author

Developed by [Teycir Ben Soltane](https://teycirbensoltane.tn)
