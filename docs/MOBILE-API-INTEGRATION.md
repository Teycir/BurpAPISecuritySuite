# Mobile API Testing Integration

**BurpAPISecuritySuite + RedTeamToolkitForAndroid**

Complete workflow for AI-orchestrated mobile API penetration testing.

## Overview

This integration combines:
- **BurpAPISecuritySuite**: API traffic capture, fuzzing, AI export (108+ attack vectors)
- **RedTeamToolkitForAndroid**: SSL bypass, runtime hooks, 22+ MCP servers, binary analysis

Result: Fully automated mobile API security assessment with AI orchestration.

## Prerequisites

### Required Setup
```bash
# 1. Waydroid with Magisk Delta root
# IP: 192.168.240.15

# 2. Frida + ADB environment
cd ~/Repos/frida-waydroid-launcher
./start-frida-env.sh

# 3. Burp proxy configured
# Host: 192.168.240.1:8080
cd ~/Repos/burp-waydroid-connector
./install-burp-cert.sh cacert.der

# 4. BurpAPISecuritySuite extension loaded
# Burp → Extender → Add → BurpAPISecuritySuite.py
```

### Verify Installation
```bash
# Check ADB
adb devices
# Expected: 192.168.240.15:5555

# Check Frida
frida-ps -U

# Check Burp proxy
adb shell settings get global http_proxy
# Expected: 192.168.240.1:8080
```

## Core Integration Points

### 1. API Traffic Capture
**Flow**: Mobile App → SSL Bypass → Burp Proxy → Extension Analysis

```bash
# Launch app with SSL bypass
frida -U -f com.target.app -l ~/Repos/RedTeamToolkitForAndroid/scripts/frida-ssl-bypass.js

# BurpAPISecuritySuite auto-captures traffic
# Check "API Recon" tab for captured endpoints
```

**What Gets Captured**:
- Normalized endpoints (`/api/users/123` → `/api/users/{id}`)
- All parameters (URL, body, JSON, cookies)
- Auth methods (Bearer, API Key, Session)
- Request/response bodies
- API patterns (REST, GraphQL, JWT)

### 2. Intelligent Fuzzing
**Generate mobile-specific attacks**

```bash
# In Burp → BurpAPISecuritySuite → Fuzzer Tab
# 1. Select "All" attack type
# 2. Click "Generate"
# 3. Review 108+ generated attacks
```

**Attack Types for Mobile APIs**:
- **BOLA**: Test all authenticated endpoints with different user tokens
- **IDOR**: Enumerate user IDs, order IDs, resource IDs
- **JWT**: Algorithm confusion, claim manipulation, kid injection
- **GraphQL**: Introspection, batching, depth attacks, alias abuse
- **Race Conditions**: Payment APIs, voucher redemption, OTP validation
- **Business Logic**: Price manipulation, quantity bypass, workflow skip

### 3. AI-Powered Testing
**Export structured data for AI payload generation**

```bash
# In Burp → BurpAPISecuritySuite
# Click "Export for LLM"
# Output: ~/burp_APISecurity/FullExport_TIMESTAMP/api_analysis.json
```

**AI Prompt Template**:
```
Analyze this mobile API structure and generate custom exploits:

Context:
- Android app: com.target.app
- API endpoints: [from api_analysis.json]
- Auth: Bearer tokens extracted via Frida
- Detected patterns: REST, JWT, GraphQL

Generate:
1. BOLA payloads for horizontal privilege escalation
2. Race condition scripts for payment endpoints
3. JWT manipulation for admin access
4. GraphQL batching to bypass rate limits
5. Business logic exploits for voucher abuse

Use RedTeamToolkit MCP servers for execution.
```

### 4. Runtime Context Extraction
**Use Frida to extract tokens, keys, and runtime data**

```bash
# Extract JWT tokens
frida -U com.target.app -l extract-tokens.js

# Hook authentication methods
frida -U com.target.app -l hook-auth.js

# Monitor crypto operations
frida -U com.target.app -l monitor-crypto.js
```

**Integration with BurpAPISecuritySuite**:
- Extract tokens → Use in BOLA fuzzing
- Hook API calls → Identify hidden endpoints
- Monitor encryption → Detect weak crypto (Base64, MD5)

### 5. Advanced Attack Execution

#### Burp Intruder (Auto-Configured)
```bash
# In BurpAPISecuritySuite → Fuzzer Tab
# Click "Send to Intruder"
# Result: Burp Intruder opens with §markers§ pre-configured

# Load payloads from:
~/burp_APISecurity/Payloads_TIMESTAMP/payloads.json
```

#### Turbo Intruder (Race Conditions)
```bash
# Click "Turbo Intruder" button
# Output: ~/burp_APISecurity/TurboIntruder_TIMESTAMP/

# Scripts generated:
# - race_condition.py (50 parallel requests)
# - bola_enum.py (user enumeration)
# - jwt_brute.py (token manipulation)

# Execute in Burp:
# Right-click request → Extensions → Turbo Intruder
# Load generated script → Send
```

#### Nuclei Validation
```bash
# Click "Run Nuclei" button
# Auto-scans for:
# - Exposed API endpoints
# - GraphQL introspection
# - JWT misconfigurations
# - Debug endpoints
# - Swagger/OpenAPI docs

# Output: ~/burp_APISecurity/NucleiTargets_TIMESTAMP/
```

## Complete Workflow

### Phase 1: Setup & Capture (5 min)
```bash
# 1. Start environment
cd ~/Repos/frida-waydroid-launcher && ./start-frida-env.sh

# 2. Launch app with SSL bypass
frida -U -f com.target.app -l ~/Repos/RedTeamToolkitForAndroid/scripts/frida-ssl-bypass.js

# 3. Exercise app features
# - Login as different users (user, admin, guest)
# - Browse all screens
# - Trigger all API calls

# 4. Check BurpAPISecuritySuite → API Recon tab
# Verify endpoints captured
```

### Phase 2: Analysis & Fuzzing (10 min)
```bash
# 5. Generate fuzzing campaign
# Fuzzer Tab → Attack Type: "All" → Generate
# Review: Critical/High/Medium counts

# 6. Export for AI
# Click "Export for LLM"
# Output: ~/burp_APISecurity/FullExport_TIMESTAMP/api_analysis.json

# 7. Export AI context
# Click "AI Payloads"
# Output: ~/burp_APISecurity/AI_Context_TIMESTAMP/ai_context.json
```

### Phase 3: Advanced Attacks (15 min)
```bash
# 8. BOLA Testing
# - Extract tokens for user1, user2, admin (Frida)
# - Send to Intruder with different tokens
# - Test all endpoints for horizontal/vertical privilege escalation

# 9. Race Conditions
# - Identify payment/voucher endpoints
# - Click "Turbo Intruder"
# - Execute race_condition.py with 50 parallel requests

# 10. JWT Exploitation
# - Hook JWT generation (Frida)
# - Generate alg:none, kid injection payloads
# - Test claim manipulation for privilege escalation

# 11. GraphQL Abuse
# - Detect GraphQL endpoint
# - Generate introspection, batching, depth attacks
# - Test alias abuse for rate limit bypass
```

### Phase 4: Validation & Reporting (10 min)
```bash
# 12. Nuclei validation
# Click "Run Nuclei"
# Validates findings automatically

# 13. Generate report
cd ~/Repos/RedTeamToolkitForAndroid
python3 scripts/generate-dashboard.py

# 14. Organize findings
Reports/com.target.app/
├── 1-attack-surface.md          # Static + dynamic analysis
├── 2-vulnerabilities.md          # Confirmed vulnerabilities
├── 3-poc/
│   ├── api_analysis.json        # BurpAPISecuritySuite export
│   ├── burp-intruder-bola.txt   # BOLA attack results
│   ├── race_condition.py        # Turbo Intruder script
│   ├── exploit-jwt.py           # JWT exploitation PoC
│   └── screenshots/
└── 4-conclusion.md
```

## Specific Attack Scenarios

### Scenario 1: BOLA on User Endpoints
**Target**: `GET /api/users/{id}`, `GET /api/orders/{id}`

```bash
# 1. Extract tokens (Frida)
frida -U com.target.app -l extract-tokens.js
# Output: user1_token, user2_token, admin_token

# 2. BurpAPISecuritySuite detects BOLA endpoints
# Fuzzer Tab → Shows "Potential BOLA" with Critical severity

# 3. Send to Intruder
# Click "Send to Intruder"
# Positions: §id§ parameter
# Payloads: 1-1000 (numeric enumeration)

# 4. Test with different tokens
# Replace Authorization header with user1_token
# Run attack → Identify accessible resources

# 5. Validate horizontal privilege escalation
# user1 can access user2's data → BOLA confirmed
```

### Scenario 2: Race Condition on Payment
**Target**: `POST /api/vouchers/redeem`

```bash
# 1. Capture voucher redemption request
# BurpAPISecuritySuite auto-captures

# 2. Generate Turbo Intruder script
# Click "Turbo Intruder"
# Output: race_condition.py

# 3. Customize script
# Edit: Set voucher_code, user_token
# Set: 50 parallel requests

# 4. Execute
# Burp → Right-click request → Turbo Intruder
# Load race_condition.py → Send

# 5. Validate
# Check if voucher redeemed multiple times
# Confirm balance increased multiple times
```

### Scenario 3: JWT Privilege Escalation
**Target**: JWT with `role` claim

```bash
# 1. Hook JWT generation (Frida)
frida -U com.target.app -l hook-jwt.js
# Output: JWT structure, signing key (if weak)

# 2. BurpAPISecuritySuite detects JWT
# Fuzzer Tab → Shows JWT exploitation payloads

# 3. Test algorithm confusion
# Payload: {"alg":"none"} + original claims
# Remove signature
# Send request → Check if accepted

# 4. Test claim manipulation
# Original: {"role":"user"}
# Modified: {"role":"admin"}
# Re-sign with extracted key (if found)
# Send request → Check for admin access

# 5. Test kid injection
# Payload: {"alg":"HS256","kid":"../../dev/null"}
# Sign with empty key
# Send request → Check if accepted
```

### Scenario 4: GraphQL Batching Abuse
**Target**: GraphQL endpoint with rate limiting

```bash
# 1. Identify GraphQL endpoint
# BurpAPISecuritySuite detects pattern

# 2. Generate GraphQL attacks
# Fuzzer Tab → Shows introspection, batching, depth attacks

# 3. Test introspection
# Query: {__schema{types{name,fields{name}}}}
# Discover all available queries/mutations

# 4. Test batching
# Send 100 queries in single request using aliases
# query { user1:user(id:1){name} user2:user(id:2){name} ... }
# Bypass rate limit (1 request = 100 queries)

# 5. Test depth attack
# Nested query: user{posts{comments{author{posts{comments{...}}}}}}
# Cause DoS or extract excessive data
```

## AI Orchestration

### MCP Server Integration
**RedTeamToolkit provides 15+ MCP servers for AI automation**

```bash
# Available MCP servers:
~/Mcp/
├── frida-mcp          # Runtime hooks
├── adb-mcp            # Device control
├── burp-mcp-server    # Burp API
├── apktool-mcp        # APK decompilation
├── jadx-mcp           # Java decompilation
├── ghidra-mcp         # Binary analysis
├── mobsf-mcp          # Static analysis
├── nuclei-mcp         # Vulnerability scanning
└── ...
```

### AI Workflow Example
```
User: "Test com.target.app for BOLA vulnerabilities"

AI executes:
1. frida-mcp: Launch app with SSL bypass
2. burp-mcp: Capture API traffic
3. BurpAPISecuritySuite: Export api_analysis.json
4. AI analyzes: Identifies 5 BOLA endpoints
5. BurpAPISecuritySuite: Generate BOLA payloads
6. frida-mcp: Extract tokens for user1, user2, admin
7. burp-mcp: Send Intruder attacks with different tokens
8. AI validates: user1 accessed user2's data → BOLA confirmed
9. AI generates: exploit-bola.py PoC
10. AI reports: Vulnerability documented in Reports/
```

### Custom AI Prompts

**Comprehensive Mobile API Assessment**:
```
Analyze com.target.app using BurpAPISecuritySuite + RedTeamToolkit:

1. Static Analysis:
   - Decompile APK (jadx-mcp)
   - Extract secrets (deep-secrets-hunter)
   - Analyze native libs (angr, r2pipe)

2. Dynamic Analysis:
   - Launch with SSL bypass (frida-mcp)
   - Capture API traffic (burp-mcp)
   - Export endpoints (BurpAPISecuritySuite)

3. Fuzzing:
   - Generate 108+ attacks (BurpAPISecuritySuite)
   - Focus on: BOLA, IDOR, JWT, GraphQL, Race Conditions
   - Execute with Intruder + Turbo Intruder

4. Validation:
   - Run Nuclei (nuclei-mcp)
   - Verify exploits
   - Generate PoCs

5. Reporting:
   - Document findings
   - Create exploit scripts
   - Generate dashboard
```

**Targeted Attack Generation**:
```
Given api_analysis.json from BurpAPISecuritySuite:

Generate custom exploits for:
1. BOLA: Endpoints with {id} parameters
2. Race Conditions: Payment/voucher endpoints
3. JWT: Detected Bearer token authentication
4. GraphQL: Identified GraphQL endpoint at /graphql
5. Business Logic: Price/quantity parameters

Use:
- Frida hooks for token extraction
- Turbo Intruder for race conditions
- Burp Intruder for enumeration
- Nuclei for validation

Output: Working PoC scripts in Reports/3-poc/
```

## Output Structure

### BurpAPISecuritySuite Exports
```
~/burp_APISecurity/
├── FullExport_TIMESTAMP/
│   └── api_analysis.json           # Complete API structure
├── Payloads_TIMESTAMP/
│   └── payloads.json               # 108+ attack payloads
├── AI_Context_TIMESTAMP/
│   └── ai_context.json             # Structured data for AI
├── TurboIntruder_TIMESTAMP/
│   ├── race_condition.py           # 50 parallel requests
│   ├── bola_enum.py                # User enumeration
│   └── jwt_brute.py                # Token manipulation
└── NucleiTargets_TIMESTAMP/
    ├── targets.txt                 # Target list
    ├── nuclei-output.txt           # Scan results
    └── nuclei-output.jsonl         # JSON findings
```

### RedTeamToolkit Reports
```
~/Repos/RedTeamToolkitForAndroid/Reports/com.target.app/
├── 1-attack-surface.md
│   ├── APK info (package, version, permissions)
│   ├── Components (activities, services, receivers)
│   ├── API endpoints (from BurpAPISecuritySuite)
│   ├── Authentication methods
│   └── Attack surface summary
│
├── 2-vulnerabilities.md
│   ├── BOLA (with PoC)
│   ├── Race Conditions (with PoC)
│   ├── JWT Exploitation (with PoC)
│   ├── GraphQL Abuse (with PoC)
│   ├── Hardcoded Secrets (from static analysis)
│   └── Weak Crypto (from traffic analysis)
│
├── 3-poc/
│   ├── api_analysis.json           # BurpAPISecuritySuite export
│   ├── ai_context.json             # AI payload context
│   ├── payloads.json               # All attack payloads
│   ├── burp-intruder-bola.txt      # Intruder results
│   ├── race_condition.py           # Turbo Intruder script
│   ├── exploit-bola.py             # BOLA exploitation
│   ├── exploit-jwt.py              # JWT manipulation
│   ├── exploit-graphql.py          # GraphQL abuse
│   ├── frida-hooks/
│   │   ├── extract-tokens.js
│   │   ├── hook-auth.js
│   │   └── monitor-crypto.js
│   ├── screenshots/
│   │   ├── bola-proof.png
│   │   ├── race-condition-proof.png
│   │   └── jwt-admin-access.png
│   └── nuclei-findings.jsonl
│
└── 4-conclusion.md
    ├── Executive summary
    ├── Risk assessment
    ├── Remediation priorities
    └── Technical recommendations
```

## Best Practices

### Reconnaissance Phase
1. **Capture Authenticated Traffic**: Login as multiple users (user, admin, guest)
2. **Exercise All Features**: Click through entire app for complete API coverage
3. **Multiple Sessions**: Capture traffic for different user roles
4. **Review Statistics**: Check Critical/High/Medium counts in BurpAPISecuritySuite

### Fuzzing Phase
1. **Start with "All"**: Generate comprehensive attack campaign first
2. **Focus on High-Risk**: Filter by severity for critical endpoints
3. **Verify Detections**: Review generated attacks before execution
4. **Batch Testing**: Use Turbo Intruder for race conditions and high-speed enumeration

### AI Integration
1. **Export Context Early**: Generate AI context after initial capture
2. **Iterate Payloads**: Use AI-generated payloads, test, refine prompt
3. **Combine Techniques**: Merge AI payloads with built-in payload library
4. **Validate with Nuclei**: Automated vulnerability validation

### Automation
1. **MCP Orchestration**: Use AI to chain multiple tools automatically
2. **CI/CD Integration**: Automate exports for regression testing
3. **Custom Scripts**: Generate reusable exploit scripts for future tests

## Troubleshooting

### SSL Bypass Not Working
```bash
# Check Frida server
frida-ps -U

# Restart Frida server
adb shell "su -c 'killall frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# Try alternative bypass
frida -U -f com.target.app -l ~/Repos/RedTeamToolkitForAndroid/tools/frida-scripts/ssl-bypass-cmodule.js
```

### Burp Not Capturing Traffic
```bash
# Check proxy setting
adb shell settings get global http_proxy

# Reinstall certificate
cd ~/Repos/burp-waydroid-connector
./install-burp-cert.sh cacert.der

# Verify certificate installed
adb shell "su -c 'ls /system/etc/security/cacerts/ | grep burp'"
```

### BurpAPISecuritySuite Not Capturing
```bash
# Check extension loaded
# Burp → Extender → Extensions → BurpAPISecuritySuite

# Check auto-capture enabled
# API Recon tab → Verify "Auto-Capture: ON"

# Manual capture
# Right-click request → Send to BurpAPISecuritySuite
```

### Nuclei Scan Fails
```bash
# Check nuclei installed
nuclei -version

# Check targets file
cat ~/burp_APISecurity/NucleiTargets_TIMESTAMP/targets.txt

# Run manually
nuclei -list targets.txt -tags api,jwt,graphql -o output.txt
```

## Performance Tips

1. **Limit Capture Scope**: Focus on API endpoints only (exclude static resources)
2. **Use Turbo Intruder**: For high-speed attacks (race conditions, enumeration)
3. **Batch Nuclei Scans**: Run once after capturing all endpoints
4. **Filter by Severity**: Focus on Critical/High findings first
5. **Parallel Testing**: Use multiple Burp Intruder tabs for different attack types

## Security Considerations

1. **Authorized Testing Only**: Ensure proper authorization before testing
2. **Rate Limiting**: Be mindful of rate limits (use delays in Intruder)
3. **Data Sensitivity**: Avoid capturing PII in reports (redact sensitive data)
4. **Cleanup**: Remove test data after assessment (vouchers, orders, users)
5. **Responsible Disclosure**: Follow responsible disclosure practices for findings

## Related Resources

- [BurpAPISecuritySuite README](README.md)
- [RedTeamToolkitForAndroid README](../RedTeamToolkitForAndroid/README.md)
- [Frida Waydroid Launcher](https://github.com/Teycir/frida-waydroid-launcher)
- [Burp Waydroid Connector](https://github.com/Teycir/burp-waydroid-connector)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

## License

MIT License - Free to use for authorized security testing and research purposes.

## Author

Developed by [Teycir Ben Soltane](https://teycirbensoltane.tn)
