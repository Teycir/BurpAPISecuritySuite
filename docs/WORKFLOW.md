# Complete API Security Testing Workflow
## Using BurpAPISecuritySuite + 21 Extensions

---

## 🎯 Phase 1: Initial Reconnaissance (Passive)

### Step 1.1: Configure Auto-Capture Extensions
**Extensions Running**: Logger++, BurpAPISecuritySuite, JS Miner, JS Link Finder, Retire.js, Sensitive Discoverer, CSP Auditor

**Actions**:
1. **Logger++**: Apply all 10 tags from `loggerpp_tags.md`
2. **BurpAPISecuritySuite**: Enable auto-capture (default)
3. **PwnFox**: Enable browser extension for enhanced context
4. **Retire.js**: Auto-scans for vulnerable JS libraries

**Browse Target**: Login and exercise all application features (5-10 minutes)

**What's Happening**:
- Logger++ tags traffic by risk (IDOR, auth, sensitive data)
- BurpAPISecuritySuite normalizes endpoints
- JS Miner extracts API endpoints from JavaScript
- JS Link Finder discovers hidden paths
- Retire.js flags vulnerable libraries (jQuery, Angular, etc.)
- Sensitive Discoverer finds API keys, tokens in responses
- CSP Auditor checks Content-Security-Policy headers

---

## 🔍 Phase 2: Deep Discovery (Active)

### Step 2.1: Parameter Discovery
**Extension**: Param Miner

**Actions**:
1. Logger++ → Filter `api_endpoint` tag → Select all
2. Right-click → Extensions → Param Miner → Guess params
3. Wait 5-15 minutes (checks headers, cookies, body params)

**Finds**: Hidden parameters, cache poisoning vectors, header injection points

### Step 2.2: GraphQL Enumeration
**Extensions**: GraphQL Raider, InQL

**Actions** (if GraphQL detected):
1. Logger++ → Filter `/graphql` → Right-click request
2. Send to **GraphQL Raider** → Run introspection
3. Send to **InQL** → Generate queries/mutations
4. Export schema to BurpAPISecuritySuite

**Finds**: Full GraphQL schema, hidden queries, depth limits

### Step 2.3: JavaScript Analysis
**Extensions**: JS Miner, JS Link Finder

**Actions**:
1. **JS Miner** → Review discovered endpoints tab
2. **JS Link Finder** → Check for:
   - API keys in source
   - Hardcoded endpoints
   - Debug/staging URLs
3. Add findings to BurpAPISecuritySuite manually

---

## 🛡️ Phase 3: WAF/Protection Analysis

### Step 3.1: Identify Protections
**Extensions**: Bypass Bot Detection, Bypass WAF

**Actions**:
1. Logger++ → Filter `write_ops` tag
2. Select POST/PUT/DELETE → Send to Repeater
3. **Bypass Bot Detection** → Test for Cloudflare, Akamai, DataDome
4. **Bypass WAF** → Auto-test bypass techniques

**Finds**: WAF type, bypass methods, rate limits

### Step 3.2: Test 403 Bypasses
**Extension**: 403 Bypasser

**Actions**:
1. Logger++ → Filter `admin_debug` tag
2. Select 403 responses → Right-click → 403 Bypasser
3. Tests: Header manipulation, path traversal, HTTP method override

**Finds**: Authorization bypass vectors

---

## 🔐 Phase 4: Authentication Testing

### Step 4.1: JWT Analysis
**Extension**: JWT Editor

**Actions**:
1. Logger++ → Filter `jwt` tag → Select request
2. Send to Repeater → JWT Editor tab appears
3. Test:
   - Algorithm confusion (alg: none)
   - Signature stripping
   - Claim manipulation (role, user_id)
   - Key confusion (RS256 → HS256)

### Step 4.2: Authorization Testing
**Extension**: Autorize

**Actions**:
1. Configure two users: **Admin** (high-priv) + **User** (low-priv)
2. Browse as Admin → Autorize captures requests
3. Auto-replays with User token → Flags BOLA/IDOR

**Finds**: Horizontal/vertical privilege escalation

### Step 4.3: CSRF Testing
**Extension**: CSRF Scanner

**Actions**:
1. Logger++ → Filter `write_ops` AND `csrf_risk` tags
2. Right-click → CSRF Scanner → Test all
3. Checks: Token validation, SameSite cookies, CORS

---

## ⚡ Phase 5: Vulnerability Scanning

### Step 5.1: Active Scanning
**Extension**: Active Scan++

**Actions**:
1. Logger++ → Filter `api_endpoint` tag → Select all
2. Right-click → Actively scan selected items
3. Active Scan++ adds:
   - Host header injection
   - Edge Side Includes (ESI)
   - CRLF injection
   - CORS misconfigurations

### Step 5.2: XSS Testing
**Extension**: XSS Validator

**Actions**:
1. Logger++ → Filter `reflected` tag
2. BurpAPISecuritySuite → Generate XSS fuzzing
3. Send to Intruder → Enable XSS Validator
4. Launch attack → XSS Validator confirms exploits via Collaborator

### Step 5.3: Request Smuggling
**Extension**: HTTP Request Smuggler

**Actions**:
1. Select API gateway/load balancer requests
2. Right-click → HTTP Request Smuggler → Smuggle probe
3. Tests: CL.TE, TE.CL, TE.TE desync

---

## 🚀 Phase 6: Advanced Exploitation

### Step 6.1: Generate Comprehensive Fuzzing
**Extension**: BurpAPISecuritySuite

**Actions**:
1. **Fuzzer Tab** → Attack Type: **All**
2. Click **Generate** → Reviews 108+ payloads
3. Review generated attacks (BOLA, SQLi, XSS, NoSQLi, SSTI, etc.)

### Step 6.2: Export to Intruder
**Actions**:
1. Click **Send to Intruder** → Auto-configures §markers§
2. Intruder → Payloads tab → Load from:
   - BurpAPISecuritySuite payloads.json
   - Param Miner discoveries
   - Custom wordlists
3. Launch attack

### Step 6.3: High-Speed Attacks
**Extension**: Turbo Intruder

**Actions**:
1. BurpAPISecuritySuite → Click **Turbo Intruder** button
2. Generates scripts:
   - `race_condition.py` (50 parallel requests)
   - `bola_enum.py` (ID enumeration)
   - `jwt_brute.py` (token brute-force)
3. Right-click target → Send to Turbo Intruder → Load script

**Use Cases**:
- Race conditions (discount codes, vouchers)
- BOLA enumeration (user IDs 1-10000)
- Rate limit bypass

---

## 🎯 Phase 7: Out-of-Band Testing

### Step 7.1: Collaborator Injection
**Extension**: Collaborator Everywhere

**Actions**:
1. Enable extension (auto-injects Collaborator payloads)
2. Browse application normally
3. Checks for:
   - SSRF (Server-Side Request Forgery)
   - Blind XSS
   - XXE (XML External Entity)
   - DNS exfiltration

**Monitors**: Burp Collaborator tab for interactions

---

## 📊 Phase 8: Analysis & Reporting

### Step 8.1: Review Findings

**Logger++ Analysis**:
```
Filter by tags:
- idor_risk (Red) → Autorize results
- jwt (Cyan) → JWT Editor findings
- sensitive (Orange) → Sensitive Discoverer alerts
- reflected (Pink) → XSS Validator confirmations
- no_auth (Gray) → Unauthenticated endpoints
```

**BurpAPISecuritySuite Statistics**:
- Critical: BOLA, SQLi, Deserialization
- High: IDOR, SSTI, XXE, SSRF
- Medium: XSS, NoSQLi, JWT issues
- Low: Information disclosure

### Step 8.2: Export Data

**BurpAPISecuritySuite Exports**:
1. **Export for LLM** → `api_analysis.json` (full recon data)
2. **Export Payloads** → `payloads.json` (all attack vectors)
3. **AI Payloads** → `ai_context.json` (for ChatGPT/Claude)
4. **Export Targets** → `targets.txt` (for external tools)

**Logger++ Export**:
1. Apply filter → Select rows → Export to CSV
2. Use for: Custom scripts, reporting, timeline analysis

---

## 🔄 Phase 9: AI-Powered Custom Testing

### Step 9.1: Generate Custom Payloads

**Actions**:
1. BurpAPISecuritySuite → Click **AI Payloads**
2. Feed `ai_context.json` to ChatGPT/Claude:

```
Prompt:
"Analyze these API endpoints and generate 50 custom payloads for:
1. SQLi based on parameter names (user_id, search, filter)
2. IDOR matching observed ID patterns (numeric, UUID, ObjectID)
3. XSS for detected reflection points
4. NoSQLi for MongoDB operators
5. Business logic (price=-100, quantity=999999)

Focus on context-aware attacks for this specific API."
```

3. Import AI-generated payloads → Intruder/Turbo Intruder

### Step 9.2: Iterate & Refine

**Actions**:
1. Test AI payloads → Review results
2. Refine prompt with successful patterns
3. Generate next iteration
4. Combine with Param Miner discoveries

---

## 🎯 Phase 10: Validation & Exploitation

### Step 10.1: Confirm Vulnerabilities

**Manual Verification**:
- **BOLA**: Autorize + manual token swap
- **SQLi**: Time-based confirmation (sleep payloads)
- **XSS**: XSS Validator + manual browser test
- **SSRF**: Collaborator Everywhere interactions
- **CSRF**: CSRF Scanner + PoC generation

### Step 10.2: Exploit Development

**High-Impact Findings**:
1. **Race Conditions**: Turbo Intruder scripts
2. **Request Smuggling**: HTTP Request Smuggler PoCs
3. **JWT Bypass**: JWT Editor attack chains
4. **GraphQL Abuse**: InQL + GraphQL Raider exploitation

---

## 📋 Quick Reference: Extension Roles

| Extension | Phase | Purpose |
|-----------|-------|---------|
| **Logger++** | 1-10 | Central hub, traffic tagging |
| **BurpAPISecuritySuite** | 1,6,8,9 | Recon, fuzzing, export |
| **JS Miner** | 1,2 | Extract API endpoints from JS |
| **JS Link Finder** | 1,2 | Find hidden paths in JS |
| **Retire.js** | 1 | Vulnerable library detection |
| **Sensitive Discoverer** | 1,8 | API keys, tokens, secrets |
| **CSP Auditor** | 1,5 | CSP policy analysis |
| **PwnFox** | 1 | Enhanced browser context |
| **Param Miner** | 2 | Hidden parameter discovery |
| **GraphQL Raider** | 2,10 | GraphQL introspection |
| **InQL** | 2,10 | GraphQL scanner |
| **Bypass Bot Detection** | 3 | WAF/bot detection bypass |
| **Bypass WAF** | 3 | WAF evasion techniques |
| **403 Bypasser** | 3 | Authorization bypass |
| **JWT Editor** | 4,10 | JWT manipulation |
| **Autorize** | 4,10 | BOLA/IDOR detection |
| **CSRF Scanner** | 4,10 | CSRF testing |
| **Active Scan++** | 5 | Enhanced active scanning |
| **XSS Validator** | 5,10 | XSS confirmation |
| **HTTP Request Smuggler** | 5,10 | Desync attacks |
| **Turbo Intruder** | 6,10 | High-speed attacks |
| **Collaborator Everywhere** | 7,10 | Out-of-band detection |

---

## ⚡ Speed Run (30 Minutes)

**For quick assessments**:

1. **0-5 min**: Browse app → Logger++ + BurpAPISecuritySuite capture
2. **5-10 min**: Param Miner on top 10 endpoints
3. **10-15 min**: Autorize with 2 users (admin + user)
4. **15-20 min**: BurpAPISecuritySuite → Generate All → Send to Intruder
5. **20-25 min**: Turbo Intruder race condition tests
6. **25-30 min**: Review Collaborator Everywhere + export findings

---

## 🎓 Pro Tips

1. **Logger++ is your command center** → All analysis starts here
2. **Tag before testing** → Apply all 10 tags immediately
3. **Autorize runs passively** → Configure once, forget it
4. **Param Miner is slow** → Run overnight for full coverage
5. **Turbo Intruder for scale** → Use when Intruder is too slow
6. **Collaborator Everywhere is noisy** → Disable for stealth testing
7. **BurpAPISecuritySuite exports** → Use AI context for custom payloads
8. **XSS Validator eliminates false positives** → Always enable for XSS testing
9. **JWT Editor + Autorize combo** → Deadly for auth bypass
10. **Active Scan++ adds edge cases** → Run after manual testing

---

## 🚨 Common Pitfalls

- **Logger++ freezing**: Clear history before applying complex filters
- **Param Miner timeout**: Reduce thread count in settings
- **Autorize false positives**: Verify token extraction is correct
- **Turbo Intruder rate limits**: Add delays between requests
- **Collaborator Everywhere noise**: Filter by endpoint in Collaborator tab
- **BurpAPISecuritySuite memory**: Export/clear after 500+ endpoints

---

## 📁 Output Structure

```
~/burp_APISecurity/
├── FullExport_TIMESTAMP/
│   └── api_analysis.json (BurpAPISecuritySuite)
├── Payloads_TIMESTAMP/
│   └── payloads.json (108+ attack vectors)
├── AI_Context_TIMESTAMP/
│   └── ai_context.json (for ChatGPT/Claude)
├── TurboIntruder_TIMESTAMP/
│   ├── race_condition.py
│   ├── bola_enum.py
│   └── jwt_brute.py
├── NucleiTargets_TIMESTAMP/
│   └── targets.txt
└── logger_plus_export.csv (Logger++ filtered data)
```

---

## 🎯 Success Metrics

**Good Coverage**:
- 50+ unique endpoints captured
- 10+ IDOR candidates (Logger++ red tags)
- 5+ JWT tokens analyzed
- 20+ parameters discovered (Param Miner)
- 100+ Intruder requests sent
- 3+ Collaborator interactions

**Excellent Coverage**:
- 200+ endpoints
- Autorize tested 50+ requests
- GraphQL schema extracted
- Turbo Intruder race conditions tested
- Request smuggling probed
- AI-generated custom payloads tested

---

**Author**: Teycir Ben Soltane  
**Last Updated**: 2024  
**License**: MIT
