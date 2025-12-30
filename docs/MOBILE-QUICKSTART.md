# Mobile API Testing - Quick Start

**5-Minute Setup → 30-Minute Complete Assessment**

## Prerequisites Check
```bash
# ✓ Waydroid running at 192.168.240.15
# ✓ Frida + ADB configured
# ✓ Burp proxy at 192.168.240.1:8080
# ✓ BurpAPISecuritySuite extension loaded
```

## Quick Workflow

### 1. Start Environment (1 min)
```bash
cd ~/Repos/frida-waydroid-launcher && ./start-frida-env.sh
```

### 2. Launch App with SSL Bypass (1 min)
```bash
frida -U -f com.target.app -l ~/Repos/RedTeamToolkitForAndroid/scripts/frida-ssl-bypass.js
```

### 3. Capture Traffic (5 min)
- Login as different users (user, admin, guest)
- Browse all app features
- Trigger all API calls
- Check Burp → BurpAPISecuritySuite → API Recon tab

### 4. Generate Attacks (2 min)
- Fuzzer Tab → Attack Type: "All" → Click "Generate"
- Review: 108+ attacks generated
- Check: Critical/High/Medium counts

### 5. Export for AI (1 min)
- Click "Export for LLM" → `api_analysis.json`
- Click "AI Payloads" → `ai_context.json`

### 6. Execute Attacks (15 min)

**BOLA Testing**:
```bash
# Extract tokens with Frida
frida -U com.target.app -l extract-tokens.js

# Send to Intruder
# Click "Send to Intruder" → Load tokens → Run
```

**Race Conditions**:
```bash
# Generate script
# Click "Turbo Intruder" → race_condition.py

# Execute in Burp
# Right-click request → Turbo Intruder → Load script → Send
```

**JWT Exploitation**:
```bash
# Hook JWT generation
frida -U com.target.app -l hook-jwt.js

# Test in Fuzzer
# Review JWT payloads → Send to Repeater → Test
```

### 7. Validate (5 min)
```bash
# Click "Run Nuclei"
# Auto-validates findings
# Check results in Nuclei tab
```

### 8. Report (5 min)
```bash
cd ~/Repos/RedTeamToolkitForAndroid
python3 scripts/generate-dashboard.py

# Review: Reports/com.target.app/
```

## Common Attack Patterns

### BOLA (Broken Object Level Authorization)
```
Target: GET /api/users/{id}
Attack: Test with different user tokens
Payload: user1_token accessing user2's data
Result: Horizontal privilege escalation
```

### Race Condition
```
Target: POST /api/vouchers/redeem
Attack: 50 parallel requests
Payload: Same voucher code
Result: Multiple redemptions
```

### JWT Privilege Escalation
```
Target: JWT with role claim
Attack: Algorithm confusion + claim manipulation
Payload: {"alg":"none","role":"admin"}
Result: Admin access without valid signature
```

### GraphQL Batching
```
Target: /graphql endpoint
Attack: 100 queries in single request
Payload: query{u1:user(id:1){name}u2:user(id:2){name}...}
Result: Rate limit bypass
```

## AI Prompt Template
```
Analyze com.target.app mobile API:

Input: api_analysis.json from BurpAPISecuritySuite
Context: Android app with JWT auth, REST + GraphQL APIs

Generate:
1. BOLA exploits for /api/users/{id}, /api/orders/{id}
2. Race condition scripts for /api/vouchers/redeem
3. JWT manipulation for privilege escalation
4. GraphQL batching for rate limit bypass
5. Business logic exploits for payment endpoints

Use RedTeamToolkit MCP servers for execution.
Output: Working PoC scripts in Reports/3-poc/
```

## Output Locations
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
│   ├── exploit-*.py
│   └── screenshots/
└── 4-conclusion.md
```

## Troubleshooting

**SSL bypass not working?**
```bash
adb shell "su -c 'killall frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
frida -U -f com.target.app -l ssl-bypass.js
```

**Burp not capturing?**
```bash
adb shell settings get global http_proxy
cd ~/Repos/burp-waydroid-connector && ./install-burp-cert.sh cacert.der
```

**Extension not capturing?**
- Check: Burp → Extender → Extensions → BurpAPISecuritySuite loaded
- Check: API Recon tab → Auto-Capture: ON

## Key Features

✅ **Auto-Capture**: All API traffic automatically captured and normalized  
✅ **Smart Detection**: BOLA, IDOR, JWT, GraphQL patterns auto-detected  
✅ **108+ Attacks**: Comprehensive payload library with bypass techniques  
✅ **AI Export**: Structured JSON for ChatGPT/Claude payload generation  
✅ **Turbo Intruder**: Race condition scripts auto-generated  
✅ **Nuclei Integration**: Automated vulnerability validation  
✅ **MCP Orchestration**: 22+ tools via AI automation  

## Next Steps

- [Complete Integration Guide](MOBILE-API-INTEGRATION.md)
- [BurpAPISecuritySuite README](README.md)
- [RedTeamToolkitForAndroid](../RedTeamToolkitForAndroid/README.md)

## License

MIT - Authorized testing only
