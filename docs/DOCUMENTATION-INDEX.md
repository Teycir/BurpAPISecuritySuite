# Documentation Index

**BurpAPISecuritySuite + RedTeamToolkitForAndroid Integration**

## Quick Access

### Getting Started
- **[MOBILE-QUICKSTART.md](MOBILE-QUICKSTART.md)** - 5-minute setup, 30-minute assessment
- **[README.md](README.md)** - Main extension documentation

### Complete Guides
- **[MOBILE-API-INTEGRATION.md](MOBILE-API-INTEGRATION.md)** - Complete integration guide (prerequisites, workflows, attack scenarios)
- **[WORKFLOW-DIAGRAM.md](WORKFLOW-DIAGRAM.md)** - Visual workflow diagrams and data flow

### Cross-References
- **[RedTeamToolkitForAndroid/docs/BURP-API-INTEGRATION.md](../RedTeamToolkitForAndroid/docs/BURP-API-INTEGRATION.md)** - Integration from mobile toolkit perspective

## Documentation Structure

```
BurpAPISecuritySuite/
├── README.md                          # Main extension documentation
├── MOBILE-QUICKSTART.md               # Quick start guide (5 min)
├── MOBILE-API-INTEGRATION.md          # Complete integration guide
├── WORKFLOW-DIAGRAM.md                # Visual workflows
└── DOCUMENTATION-INDEX.md             # This file

RedTeamToolkitForAndroid/
└── docs/
    └── BURP-API-INTEGRATION.md        # Mobile toolkit integration
```

## By Use Case

### First-Time Setup
1. [README.md](README.md) - Install BurpAPISecuritySuite
2. [RedTeamToolkitForAndroid README](../RedTeamToolkitForAndroid/README.md) - Setup mobile environment
3. [MOBILE-QUICKSTART.md](MOBILE-QUICKSTART.md) - Quick start guide

### Learning the Workflow
1. [WORKFLOW-DIAGRAM.md](WORKFLOW-DIAGRAM.md) - Visual overview
2. [MOBILE-API-INTEGRATION.md](MOBILE-API-INTEGRATION.md) - Detailed workflows
3. [MOBILE-QUICKSTART.md](MOBILE-QUICKSTART.md) - Quick reference

### Specific Attack Types
1. [MOBILE-API-INTEGRATION.md](MOBILE-API-INTEGRATION.md) - Complete attack scenarios
   - BOLA Testing
   - Race Conditions
   - JWT Exploitation
   - GraphQL Abuse

### AI Integration
1. [MOBILE-API-INTEGRATION.md](MOBILE-API-INTEGRATION.md) - AI Orchestration section
2. [README.md](README.md) - AI Payload Generation

### Troubleshooting
1. [MOBILE-QUICKSTART.md](MOBILE-QUICKSTART.md) - Quick troubleshooting
2. [MOBILE-API-INTEGRATION.md](MOBILE-API-INTEGRATION.md) - Detailed troubleshooting

## Key Features by Document

### README.md
- Extension overview
- Installation instructions
- Feature list (14 attack types, 108+ vectors)
- Export formats
- Use cases

### MOBILE-QUICKSTART.md
- 5-minute setup
- 30-minute complete assessment
- Quick commands
- Common attack patterns
- AI prompt templates
- Troubleshooting

### MOBILE-API-INTEGRATION.md
- Prerequisites and setup
- Core integration points
- Complete workflow (5 phases)
- Specific attack scenarios:
  - BOLA on user endpoints
  - Race conditions on payment
  - JWT privilege escalation
  - GraphQL batching abuse
- AI orchestration
- Output structure
- Best practices
- Performance tips

### WORKFLOW-DIAGRAM.md
- Visual workflow diagrams
- Attack type breakdowns
- Data flow diagrams
- Tool integration matrix
- Time breakdown
- Success metrics

### BURP-API-INTEGRATION.md (RedTeamToolkit)
- Integration from mobile perspective
- MCP server integration
- Complete attack scenarios
- Output integration
- Quick commands

## Quick Links

### External Resources
- [Frida Waydroid Launcher](https://github.com/Teycir/frida-waydroid-launcher)
- [Burp Waydroid Connector](https://github.com/Teycir/burp-waydroid-connector)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

### Related Projects
- [RedTeamToolkitForAndroid](../RedTeamToolkitForAndroid)
- [MobileAppComplianceToolkit](../MobileAppComplianceToolkit)
- [BurpCopyIssues](https://github.com/teycir/BurpCopyIssues)

## Cheat Sheet

### Quick Commands
```bash
# Start environment
cd ~/Repos/frida-waydroid-launcher && ./start-frida-env.sh

# Launch with SSL bypass
frida -U -f com.target.app -l scripts/frida-ssl-bypass.js

# Generate report
cd ~/Repos/RedTeamToolkitForAndroid
python3 scripts/generate-dashboard.py
```

### In Burp → BurpAPISecuritySuite
1. Fuzzer Tab → "All" → "Generate"
2. "Export for LLM" → api_analysis.json
3. "Send to Intruder" → BOLA testing
4. "Turbo Intruder" → Race conditions
5. "Run Nuclei" → Validation

### Output Locations
```
~/burp_APISecurity/
├── FullExport_TIMESTAMP/api_analysis.json
├── AI_Context_TIMESTAMP/ai_context.json
├── Payloads_TIMESTAMP/payloads.json
├── TurboIntruder_TIMESTAMP/*.py
└── NucleiTargets_TIMESTAMP/nuclei-output.jsonl

~/Repos/RedTeamToolkitForAndroid/Reports/com.target.app/
├── 1-attack-surface.md
├── 2-vulnerabilities.md
├── 3-poc/
└── 4-conclusion.md
```

## Document Updates

### v1.0 (Current)
- Initial documentation suite
- Complete integration guide
- Visual workflow diagrams
- Quick start guide
- Cross-references

### Planned
- Video tutorials
- Example reports
- Advanced techniques guide
- CI/CD integration guide

## Contributing

Found an issue or have a suggestion? Please update the relevant documentation:
- Extension features → README.md
- Quick reference → MOBILE-QUICKSTART.md
- Detailed workflows → MOBILE-API-INTEGRATION.md
- Visual diagrams → WORKFLOW-DIAGRAM.md

## License

MIT License - Free to use for authorized security testing and research purposes.

## Author

Developed by [Teycir Ben Soltane](https://teycirbensoltane.tn)
