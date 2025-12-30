# Mobile API Testing Workflow

**BurpAPISecuritySuite + RedTeamToolkitForAndroid**

## Complete Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 1: SETUP & CAPTURE                         │
└─────────────────────────────────────────────────────────────────────┘

[Waydroid Android]                [Frida Server]              [Burp Suite]
192.168.240.15                     Port 27042                  192.168.240.1:8080
       │                                 │                            │
       │  1. Start Environment           │                            │
       │  ./start-frida-env.sh           │                            │
       │◄────────────────────────────────┤                            │
       │                                 │                            │
       │  2. Launch App + SSL Bypass     │                            │
       │  frida -U -f com.target.app     │                            │
       │◄────────────────────────────────┤                            │
       │                                 │                            │
       │  3. API Traffic (HTTPS)         │                            │
       ├─────────────────────────────────┼───────────────────────────►│
       │                                 │                            │
       │                                 │    [BurpAPISecuritySuite]  │
       │                                 │    ┌──────────────────┐    │
       │                                 │    │ Auto-Capture ON  │    │
       │                                 │    │ Normalize URLs   │    │
       │                                 │    │ Detect Patterns  │    │
       │                                 │    └──────────────────┘    │
       │                                 │            │                │
       │                                 │            ▼                │
       │                                 │    ┌──────────────────┐    │
       │                                 │    │ API Recon Tab    │    │
       │                                 │    │ 15 endpoints     │    │
       │                                 │    │ 5 BOLA detected  │    │
       │                                 │    └──────────────────┘    │


┌─────────────────────────────────────────────────────────────────────┐
│                  PHASE 2: ANALYSIS & FUZZING                        │
└─────────────────────────────────────────────────────────────────────┘

[BurpAPISecuritySuite]                    [AI Assistant]
       │                                         │
       │  4. Generate Attacks                    │
       │  Fuzzer Tab → "All" → Generate          │
       ├────────────────────────────────────────►│
       │                                         │
       │  ┌──────────────────────────────────┐  │
       │  │ 108+ Attack Vectors Generated:   │  │
       │  │ • BOLA: 15 endpoints (Critical)  │  │
       │  │ • IDOR: 8 endpoints (High)       │  │
       │  │ • JWT: 3 endpoints (High)        │  │
       │  │ • GraphQL: 1 endpoint (Medium)   │  │
       │  │ • Race Conditions: 2 (Critical)  │  │
       │  └──────────────────────────────────┘  │
       │                                         │
       │  5. Export for AI                       │
       │  "Export for LLM" → api_analysis.json   │
       ├────────────────────────────────────────►│
       │                                         │
       │  6. Export AI Context                   │
       │  "AI Payloads" → ai_context.json        │
       ├────────────────────────────────────────►│
       │                                         │
       │                                         │  7. AI Analyzes
       │                                         │  • Identifies patterns
       │                                         │  • Generates custom payloads
       │                                         │  • Plans attack strategy


┌─────────────────────────────────────────────────────────────────────┐
│                  PHASE 3: EXPLOITATION                              │
└─────────────────────────────────────────────────────────────────────┘

[Frida Hooks]          [BurpAPISecuritySuite]         [Burp Intruder]
       │                        │                            │
       │  8. Extract Tokens     │                            │
       │  extract-tokens.js     │                            │
       │  • user1_token         │                            │
       │  • user2_token         │                            │
       │  • admin_token         │                            │
       ├───────────────────────►│                            │
       │                        │                            │
       │                        │  9. Send to Intruder       │
       │                        │  Pre-configured §markers§  │
       │                        ├───────────────────────────►│
       │                        │                            │
       │                        │                            │  10. BOLA Attack
       │                        │                            │  Test all endpoints
       │                        │                            │  with different tokens
       │                        │                            │
       │                        │  11. Results               │
       │                        │◄───────────────────────────┤
       │                        │  user1 → user2 data ✓      │
       │                        │  BOLA confirmed!           │


[Turbo Intruder]       [BurpAPISecuritySuite]         [Target API]
       │                        │                            │
       │                        │  12. Generate Script       │
       │                        │  "Turbo Intruder"          │
       │◄───────────────────────┤  race_condition.py         │
       │                        │                            │
       │  13. Execute           │                            │
       │  50 parallel requests  │                            │
       ├────────────────────────┼───────────────────────────►│
       │                        │                            │
       │                        │  14. Race Condition ✓      │
       │◄───────────────────────┼────────────────────────────┤
       │  Voucher redeemed 5x   │                            │


┌─────────────────────────────────────────────────────────────────────┐
│                  PHASE 4: VALIDATION                                │
└─────────────────────────────────────────────────────────────────────┘

[BurpAPISecuritySuite]         [Nuclei Scanner]          [Results]
       │                              │                       │
       │  15. Run Nuclei              │                       │
       │  "Run Nuclei" button         │                       │
       ├─────────────────────────────►│                       │
       │                              │                       │
       │                              │  16. Scan             │
       │                              │  • API endpoints      │
       │                              │  • GraphQL intro      │
       │                              │  • JWT misconfig      │
       │                              │  • Debug endpoints    │
       │                              │                       │
       │  17. Findings                │                       │
       │◄─────────────────────────────┤                       │
       │  • 3 Critical                │                       │
       │  • 5 High                    │                       │
       │  • 8 Medium                  │                       │
       │                              │                       │
       │  18. Export Results          │                       │
       ├──────────────────────────────┼──────────────────────►│
       │  nuclei-output.jsonl         │                       │


┌─────────────────────────────────────────────────────────────────────┐
│                  PHASE 5: REPORTING                                 │
└─────────────────────────────────────────────────────────────────────┘

[All Findings]                 [AI Assistant]            [Final Report]
       │                              │                       │
       │  19. Aggregate Data          │                       │
       │  • api_analysis.json         │                       │
       │  • Intruder results          │                       │
       │  • Turbo Intruder results    │                       │
       │  • Nuclei findings           │                       │
       ├─────────────────────────────►│                       │
       │                              │                       │
       │                              │  20. Generate Report  │
       │                              │  • PoC exploits       │
       │                              │  • Screenshots        │
       │                              │  • Recommendations    │
       │                              │                       │
       │                              ├──────────────────────►│
       │                              │                       │
       │                              │  Reports/com.target.app/
       │                              │  ├── 1-attack-surface.md
       │                              │  ├── 2-vulnerabilities.md
       │                              │  ├── 3-poc/
       │                              │  │   ├── exploit-bola.py
       │                              │  │   ├── race_condition.py
       │                              │  │   └── screenshots/
       │                              │  └── 4-conclusion.md
```

## Attack Type Breakdown

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BOLA ATTACK WORKFLOW                             │
└─────────────────────────────────────────────────────────────────────┘

1. Detection (BurpAPISecuritySuite)
   GET /api/users/{id}
   GET /api/orders/{id}
   GET /api/documents/{id}
   ↓
2. Token Extraction (Frida)
   user1_token: eyJhbGc...
   user2_token: eyJhbGc...
   admin_token: eyJhbGc...
   ↓
3. Payload Generation (BurpAPISecuritySuite)
   Test all endpoints with all tokens
   ↓
4. Execution (Burp Intruder)
   user1_token → /api/users/2 (user2's data)
   user1_token → /api/orders/456 (user2's order)
   ↓
5. Validation
   ✓ Horizontal privilege escalation confirmed
   ✓ user1 accessed user2's resources


┌─────────────────────────────────────────────────────────────────────┐
│                 RACE CONDITION WORKFLOW                             │
└─────────────────────────────────────────────────────────────────────┘

1. Endpoint Identification (BurpAPISecuritySuite)
   POST /api/vouchers/redeem
   POST /api/payments/process
   ↓
2. Script Generation (BurpAPISecuritySuite)
   race_condition.py
   • 50 parallel requests
   • Same voucher code
   • Same user token
   ↓
3. Execution (Turbo Intruder)
   Send 50 requests simultaneously
   ↓
4. Validation
   ✓ Voucher redeemed 5 times
   ✓ Balance increased 5x
   ✓ Race condition confirmed


┌─────────────────────────────────────────────────────────────────────┐
│                   JWT EXPLOITATION WORKFLOW                         │
└─────────────────────────────────────────────────────────────────────┘

1. JWT Detection (BurpAPISecuritySuite)
   Authorization: Bearer eyJhbGc...
   ↓
2. Hook JWT Generation (Frida)
   hook-jwt.js
   • Algorithm: HS256
   • Claims: {role: "user", id: 123}
   ↓
3. Payload Generation (BurpAPISecuritySuite)
   • Algorithm confusion: {"alg":"none"}
   • Claim manipulation: {"role":"admin"}
   • kid injection: {"kid":"../../dev/null"}
   ↓
4. Testing (Burp Repeater)
   Test each payload
   ↓
5. Validation
   ✓ alg:none accepted
   ✓ Admin access granted
   ✓ JWT vulnerability confirmed


┌─────────────────────────────────────────────────────────────────────┐
│                  GRAPHQL ABUSE WORKFLOW                             │
└─────────────────────────────────────────────────────────────────────┘

1. GraphQL Detection (BurpAPISecuritySuite)
   POST /graphql
   Content-Type: application/json
   ↓
2. Introspection (BurpAPISecuritySuite)
   {__schema{types{name,fields{name}}}}
   ↓
3. Payload Generation (BurpAPISecuritySuite)
   • Batching: 100 queries with aliases
   • Depth attack: Nested queries
   • Mutation injection
   ↓
4. Execution (Burp Repeater)
   query {
     u1:user(id:1){name}
     u2:user(id:2){name}
     ...
     u100:user(id:100){name}
   }
   ↓
5. Validation
   ✓ Rate limit bypassed
   ✓ 100 queries in 1 request
   ✓ GraphQL abuse confirmed
```

## Data Flow

```
┌──────────────────┐
│  Android App     │
│  com.target.app  │
└────────┬─────────┘
         │ HTTPS Traffic
         │ (SSL Bypassed)
         ▼
┌──────────────────┐
│  Burp Proxy      │
│  192.168.240.1   │
└────────┬─────────┘
         │ HTTP Messages
         ▼
┌──────────────────────────────┐
│  BurpAPISecuritySuite        │
│  ┌────────────────────────┐  │
│  │ 1. Capture             │  │
│  │ 2. Normalize           │  │
│  │ 3. Detect Patterns     │  │
│  │ 4. Generate Attacks    │  │
│  └────────────────────────┘  │
└────────┬─────────────────────┘
         │
         ├─────────────────────────────┐
         │                             │
         ▼                             ▼
┌──────────────────┐         ┌──────────────────┐
│  Burp Intruder   │         │  Turbo Intruder  │
│  • BOLA          │         │  • Race Cond.    │
│  • IDOR          │         │  • High-speed    │
│  • JWT           │         │  • Parallel      │
└────────┬─────────┘         └────────┬─────────┘
         │                            │
         └──────────┬─────────────────┘
                    ▼
         ┌──────────────────┐
         │  Nuclei Scanner  │
         │  • Validation    │
         │  • Discovery     │
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  AI Assistant    │
         │  • Analysis      │
         │  • PoC Gen       │
         │  • Reporting     │
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  Final Report    │
         │  Reports/app/    │
         └──────────────────┘
```

## Tool Integration Matrix

```
┌─────────────────┬──────────┬──────────┬──────────┬──────────┐
│                 │  Frida   │   Burp   │  Nuclei  │    AI    │
├─────────────────┼──────────┼──────────┼──────────┼──────────┤
│ SSL Bypass      │    ✓     │          │          │          │
│ Token Extract   │    ✓     │          │          │          │
│ Traffic Capture │          │    ✓     │          │          │
│ Normalization   │          │    ✓     │          │          │
│ Pattern Detect  │          │    ✓     │          │          │
│ Attack Gen      │          │    ✓     │          │          │
│ BOLA Testing    │    ✓     │    ✓     │          │          │
│ Race Condition  │          │    ✓     │          │          │
│ Validation      │          │          │    ✓     │          │
│ PoC Generation  │          │          │          │    ✓     │
│ Reporting       │          │          │          │    ✓     │
└─────────────────┴──────────┴──────────┴──────────┴──────────┘
```

## Time Breakdown

```
Total Assessment Time: ~40 minutes

Phase 1: Setup & Capture          5 min  ████░░░░░░░░░░░░░░░░
Phase 2: Analysis & Fuzzing       10 min ████████░░░░░░░░░░░░
Phase 3: Exploitation             15 min ████████████░░░░░░░░
Phase 4: Validation               5 min  ████░░░░░░░░░░░░░░░░
Phase 5: Reporting                5 min  ████░░░░░░░░░░░░░░░░
```

## Success Metrics

```
┌─────────────────────────────────────────────────────────────┐
│  Typical Findings per Mobile App                            │
├─────────────────────────────────────────────────────────────┤
│  BOLA Vulnerabilities:        3-8 endpoints                 │
│  IDOR Issues:                 2-5 endpoints                 │
│  JWT Misconfigurations:       1-3 issues                    │
│  Race Conditions:             1-2 endpoints                 │
│  GraphQL Abuse:               0-1 endpoints                 │
│  Business Logic Flaws:        1-3 issues                    │
│  ────────────────────────────────────────────────────────   │
│  Total Critical/High:         8-15 findings                 │
└─────────────────────────────────────────────────────────────┘
```

## Quick Reference

**Start Testing**:
```bash
cd ~/Repos/frida-waydroid-launcher && ./start-frida-env.sh
frida -U -f com.target.app -l scripts/frida-ssl-bypass.js
```

**In Burp → BurpAPISecuritySuite**:
1. Fuzzer Tab → "All" → "Generate"
2. "Export for LLM" → api_analysis.json
3. "Send to Intruder" → Execute BOLA tests
4. "Turbo Intruder" → Race conditions
5. "Run Nuclei" → Validate findings

**Generate Report**:
```bash
cd ~/Repos/RedTeamToolkitForAndroid
python3 scripts/generate-dashboard.py
```

## Documentation

- [Complete Integration Guide](MOBILE-API-INTEGRATION.md)
- [Quick Start Guide](MOBILE-QUICKSTART.md)
- [Main README](README.md)
