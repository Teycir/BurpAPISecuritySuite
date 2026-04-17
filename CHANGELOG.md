# Changelog

All notable changes to this project are documented in this file.

## [1.4.14] - 2026-04-17

### Added
- Better filter management:
  - Improved filter organization and UI controls for better usability,
  - Enhanced filter state tracking and persistence,
  - Streamlined filter application workflows across modules.

## [1.4.13] - 2026-04-12

### Added
- ApiHunter `Auth Mode` control in the tab UI:
  - `Unauth Only`
  - `Auth Only`
  - `Auth + Unauth` (default dual-pass mode)
- Nuclei `Auth Mode` control in the tab UI:
  - `Unauth Only`
  - `Auth Only`
  - `Auth + Unauth` (default dual-pass mode)
- Auth-context derivation for ApiHunter authenticated runs from Recon-filtered traffic:
  - captures best available request `Authorization` header candidate,
  - captures top auth-like headers (`X-API-Key`, `Api-Key`, `ApiKey`, `X-Auth-Token`, `X-Access-Token`),
  - derives cookie pairs from request `Cookie` headers for `--cookies` pass-through.
- Auth-context derivation for Nuclei authenticated runs from Recon-filtered traffic:
  - captures best available request `Authorization` header candidate,
  - captures top auth-like headers (`X-API-Key`, `Api-Key`, `ApiKey`, `X-Auth-Token`, `X-Access-Token`),
  - derives cookie pairs from request `Cookie` headers and injects them as `Cookie: ...` request headers.

### Changed
- ApiHunter runner now supports multi-pass execution per run:
  - dual-pass (unauth + auth) when `Auth + Unauth` is selected,
  - per-pass command/output/status rendering in tab output,
  - per-pass findings summary labels (`APIHUNTER SCAN RESULTS [Unauth/Auth]`).
- Nuclei runner now supports multi-pass execution per run:
  - dual-pass (unauth + auth) when `Auth + Unauth` is selected,
  - per-pass command/output/status rendering in tab output,
  - per-pass findings summary labels (`NUCLEI SCAN RESULTS [Unauth/Auth]`) and aggregate `NUCLEI MULTI-PASS SUMMARY`.
- ApiHunter findings storage now aggregates across all passes in the same run instead of replacing with only the last pass.
- Custom-command behavior updated for auth-mode compatibility:
  - `Auth + Unauth` is blocked while `Enable Custom` is checked (requires preset/default execution for controlled dual-pass).
  - `Auth Only` in custom mode appends derived auth headers/cookies to the custom command.
  - Nuclei `Auth + Unauth` is also blocked while `Enable Custom` is checked; `Auth Only` appends derived auth headers/cookies to the custom command.
- ApiHunter `Auth + Unauth` run planning now splits deduplicated base targets into two lists:
  - auth-associated targets (based on request auth headers and non-header auth signals from request metadata),
  - unauth-associated targets (remaining deduplicated base URLs).
  - each pass now runs only on its corresponding list.
- ApiHunter auth-discovery console diagnostics now print the auth/unauth split counts and explicit notes when reusable header/cookie auth context is unavailable.
- Refactored auth-target split extraction into one shared helper engine used by both Nuclei and ApiHunter runners to keep auth/unauth classification behavior consistent.
- Nuclei `Auth + Unauth` execution now mirrors ApiHunter split behavior:
  - unauth pass runs only on deduplicated `unauth_targets`,
  - auth pass runs only on deduplicated `auth_targets`,
  - console output now includes auth/unauth split counts and header-vs-signal auth detail metrics.

### Tests
- Updated feature-contract expectations for ApiHunter and Nuclei auth-mode wiring plus labeled result summaries.

## [1.4.12] - 2026-04-10

### Added
- Fuzzer host-base relaxation fallback for narrow single-base scopes:
  - When filtered targets yield ≤1 endpoint but raw capture has ≥80 endpoints, Fuzzer now attempts a relaxed pass without host-base restrictions.
  - Relaxed pass only activates when scope override and force-host filters are disabled and allowed_bases was previously constraining results.
  - Summary output now reports `Host-base relax fallback: +N endpoints (single-base scope was too narrow)` when relaxation adds targets.

### Changed
- Refactored `_collect_fuzzer_targets` to use an internal `_run_target_filter_pass` helper for cleaner dual-pass logic (strict + relaxed fallback).
- Fuzzer metadata now includes `host_base_relaxed` (bool) and `host_base_relax_added` (int) for operator visibility into fallback behavior.

### Tests
- Updated `tests/test_feature_contracts.py` to assert relaxation logic tokens and summary output format.

## [1.4.11] - 2026-04-10

### Fixed
- Improved Recon -> Logger detail navigation visibility:
  - the destination Logger row now gets an explicit attention marker when opened from Recon detail flow,
  - attention style now uses red text plus italic font (instead of relying only on subtle background contrast),
  - attention highlight is endpoint-scoped and time-bounded to reduce persistent UI noise.
- Updated feature-contract coverage for the Recon->Logger highlight behavior to prevent regression.

## [1.4.10] - 2026-04-10

### Removed
- GraphQL `Generate Raider` action button from the GraphQL tab.
- GraphQL `Analyze Schema` workflow and related schema UI controls:
  - removed `Schema File` input field,
  - removed `Browse` button,
  - removed `Analyze Schema` button.
- Local schema-analysis/inql-like helper pipeline from GraphQL tooling:
  - schema file selection and parsing helpers,
  - schema-derived operation generation helpers,
  - points-of-interest and circular-reference analysis helpers.
- GraphQL Raider `Include Schema Ops` toggle and schema-coupled profile handling.

### Changed
- GraphQL operation delivery and batch export now rely on Raider-family payload generation only (no schema-generated operation pool).
- GraphQL empty-operation guidance now directs operators to enable Raider families instead of running schema analysis.
- Feature-contract coverage updated to match the removed GraphQL buttons/workflows and new operator guidance text.

## [1.4.9] - 2026-04-10

### Added
- New `Sensitive Data` tab for regex-driven API-sensitive data extraction:
  - Scans captured Recon samples from both live Proxy traffic and imported HAR/replay data.
  - Supports scope targeting (`Selected Endpoint`, `Filtered View`, `All Endpoints`).
  - Supports source filtering (`All Captured+Imported`, `Proxy/Live Capture`, `Imported HAR/Replay`).
  - Includes API-focused pattern packs (`All API Sensitive`, `Secrets & Tokens`, `PII & Financial`, `Credentials & Session`, `Infra/Internal Exposure`).
  - Emits richer evidence output per finding: severity, category, pattern, endpoint, source tool, section, match, and contextual snippet.
- Sensitive findings export flow:
  - Added JSON + TXT export artifacts under `SensitiveData_Export`.
  - Added tab-level `Append Report` + `To AI` wiring parity for Sensitive Data output.

### Changed
- Updated tab documentation/index to include the new `Sensitive Data` workflow in operator quick references.

## [1.4.8] - 2026-04-10

### Added
- Enhanced Wayback Machine rate limiting and reliability:
  - Added intelligent retry logic with exponential backoff for rate-limited requests.
  - Implemented request throttling to respect API rate limits.
  - Added better error handling for timeout and connection issues.
  - Improved progress reporting during long-running Wayback queries.

### Fixed
- Fixed Recon/Logger UI freeze issues during high-volume traffic capture:
  - Moved table view updates to background worker threads.
  - Implemented debounced UI refresh to prevent EDT blocking.
  - Reduced UI update frequency during bulk capture operations.
- Fixed Auth Replay UI responsiveness during heavy replay runs:
  - Buffered replay results off-EDT for chunked rendering.
  - Batched progress output to reduce Swing update pressure.

## [1.4.7] - 2026-04-10

### Changed
- Auth Replay execution now isolates UI updates from the hot replay loop:
  - replay result rows are buffered off-EDT and rendered in chunked Swing updates,
  - progress output appends are batched to reduce `invokeLater(...)` pressure during long runs.
- Recon/Logger capture pipeline now applies the same anti-freeze traffic policy:
  - internal `Extender` traffic is skipped by default from auto-capture (`capture_extender_traffic = false` runtime default),
  - listener and deep capture paths both short-circuit extension-generated traffic for layered safety.

### Fixed
- Fixed UI freeze/stall behavior during heavy Auth Replay runs caused by capture/UI churn.
- Fixed equivalent responsiveness degradation in Recon and Logger when extension-generated traffic was re-captured during active extension workflows.

## [1.4.6] - 2026-04-08

### Added
- Native Vulners enrichment workflow:
  - Added a dedicated `Vulners` tab (positioned between `ApiHunter` and `Nuclei`) with run/stop/export wiring.
  - Added software/version fingerprint collection from filtered Recon traffic plus optional custom-target fingerprint collection.
  - Added advisory enrichment output with ranked top findings, CVE context, and source-reference links when available.
- Incremental report appending workflow:
  - Added per-tab `Append Report` actions to append output into the active `FullExport` directory.
  - Added report session tracking (`session_id`, sequence counter, export directory, timestamp) for deterministic append sequencing.
  - Added active-export guardrails that disable append actions when no active export folder is available and emit explicit operator-facing status.

### Changed
- AI prompt/export contract now aligns with the APIPentesting triage schema across bundle and request-oriented surfaces.
- AI analysis prompts now explicitly require non-destructive PoCs, evidence-backed claims, and duplicate-resistant novelty fields for severe triage.
- README documentation now reflects the APIPentesting companion-repo workflow and refined AI handoff artifact guidance.


## [1.4.5] - 2026-04-07

### Added
- Auth Replay UX guidance improvements:
  - Added a top-row `?` action that opens an `Auth Replay Workflow` popup with step-by-step usage guidance.
  - Added a live `Scope Hint` row under controls to explain `Selected Endpoint` / `Filtered View` / `All Endpoints` behavior in-context.
  - Added run-time context output for `Selected Endpoint` mode, including the resolved Recon endpoint key when available.

### Changed
- Auth Replay role-header extraction now prioritizes distinct tokens:
  - Added auth-header signature normalization helpers for semantic duplicate detection across Guest/User/Admin fields.
  - `Extract` candidate ordering now prefers distinct signatures first and tags duplicate candidates as `[DUP TOKEN]`.
  - Auto-prefill (`_auto_detect_auth_profile_headers`) now attempts distinct token assignment for empty role fields before duplicate fallback.
- AI export prompt strategy now prioritizes bundle-aware reasoning over generic code generation:
  - `_generate_llm_prompt()` now explicitly references `invariant_hints`, `sequence_candidates`, `evidence_graph`, `truncation`, `confidence_score`, and `non_destructive`.
  - Added truncation-aware follow-up guidance (`truncation.total_truncated`) and multi-hop graph reasoning instructions for higher ROI prioritization.
- AI handoff prompts are now optimized for sensitive-data exploit discovery and duplicate resistance across all export surfaces:
  - Updated all tab-level `To AI` exports (`_export_text_output_to_ai`) to require novelty-aware ranking (`duplicate_risk`, `why_novel`), sensitive-data targets, and exploit-proof response deltas.
  - Updated request-level AI packs (`_build_ai_request_analysis_prompt`) to prioritize cross-account data exposure, privilege pivots, state-machine abuse, and explicit missing-data requests when evidence is thin.
  - Updated bundle-level enhanced prompt (`_generate_enhanced_ai_prompt`) used by OpenAI/Anthropic/Ollama export files to prioritize high-bounty non-obvious chains over generic findings.
- Duplicate-header handling remains execution-safe while improving operator visibility:
  - Duplicate role headers are still collapsed for replay/evaluation noise control.
  - Duplicate role table columns now mirror canonical role results to avoid misleading empty (`-`) Guest/User/Admin cells.

### Fixed
- Fixed Auth Replay startup crash on severity-sort wiring in Jython:
  - `TableRowSorter.setComparator(...)` now receives a concrete `java.util.Comparator` implementation (`_AuthReplaySeverityComparator(Comparator)`), resolving Jython coercion failure.
- Clarified `Selected Endpoint` failure/empty-target path with explicit Recon-selection dependency messaging in output.

## [1.4.4] - 2026-04-07

### Added
- Native ApiHunter integration tab:
  - New tab: `ApiHunter` (placed before `Nuclei` in main workflow order).
  - New runner wiring: `_run_apihunter` via `src/heavy_runners.py`.
  - New target export action: `Export Targets` for ApiHunter-scoped input lists.
- ApiHunter custom target workflow:
  - Added `Use Custom Targets` checkbox to force ApiHunter input from popup-defined URLs.
  - Added `Custom Targets...` multiline popup editor for explicit target control.
  - Added strict parser/sanitizer that canonicalizes to base URLs (`scheme://host[:port]/`), de-duplicates entries, and enforces a hard max of `20`.
- ApiHunter deep-calibration profiles tuned for complementary value:
  - `Deep Search (WAF Evasive Recommended)` (default)
  - `Deep (Fast)`
  - `Gap-Fill (Balanced)`
  - `Passive Drift`
- WAF-evasive deep defaults:
  - Adds `--waf-evasion`, custom `--user-agents`, lower concurrency, higher delay, adaptive/per-host controls, and active deep-response checks.

### Changed
- ApiHunter calibration profiles were realigned to ApiHunter Desktop defaults:
  - `Quick (Desktop Preset)`
  - `Balanced (Desktop Preset)` (default)
  - `Deep (Desktop Preset)`
- ApiHunter target feed now emits filtered/deduped host-base targets (`scheme://host[:port]/`) from filtered Recon scope.
- ApiHunter default command assembly now mirrors desktop preset flags (including `--filter-timeout`, endpoint caps, and per-profile active/dry-run/WAF settings) without Burp-side runtime tuning logic.
- ApiHunter target source now always uses Recon filtered view (whether filters are actively narrowed or at default state).
- ApiHunter targets are now canonically de-duplicated before execution (including normalization for equivalent URL variants).
- ApiHunter path defaults now use strict PATH discovery: find `apihunter` in `PATH` and prefill the discovered absolute binary path (no fallback candidates).
- ApiHunter strict PATH discovery now probes process `PATH` plus shell modes (`bash -lc` and `bash -ic` with `command -v apihunter`) to handle GUI-launched Burp environment gaps.
- Tool-health coverage now includes ApiHunter binary signature checks.
- External stop/emergency-kill coverage now includes ApiHunter (`Stop`, tracked process stop, and pkill/taskkill sweeps).
- ApiHunter report formatter now produces higher-signal summaries:
  - `TOP FINDINGS` defaults to `>= MEDIUM` display (suppresses low/info noise in high-volume runs).
  - entries include richer context when available: `confidence`, `scanner`, `evidence`, and `remediation`.
  - runtime meta context now includes HTTP request/retry stats and scanner finding distribution.
- ApiHunter `Top Findings Min` is now operator-configurable (`Critical` / `High` / `Medium`) and persisted across extension restarts.
- ApiHunter default preset commands now mirror Desktop flags without Burp-injected `--min-severity` / `--no-auto-report` additions.
- ApiHunter default overlap-trim set now disables only `CORS` and `OpenAPI` checks (no longer disables CSP/GraphQL/API versioning by default).
- ApiHunter run header now uses one non-redundant severity line: `Top Findings Min` (Burp display filter).
- ApiHunter default calibrations now allow overlap scanners by default while relying on ApiHunter-native runtime behavior.
- Added explicit `Deep (Fast)` calibration profile for speed-first deep scans.
- ApiHunter launch now auto-resolves `apihunter` from PATH at run-time (process PATH + shell `command -v` probe) and auto-fills the field with the resolved absolute binary.
- ApiHunter runner was simplified to an ApiHunter-native execution model:
  - Burp now launches the selected ApiHunter command and renders results, without Burp-side runtime guardrails/tuning heuristics.
  - Deep/Gap-Fill presets now use concise ApiHunter-native flags (no Burp-injected watchdog/max-endpoints runtime controls).
- Capture defaults now retain more context:
  - Recon request/response max body size is now operator-configurable from a dropdown (`5000`, `7500`, `10000`, `15000`) and persisted across restarts.
  - the same max-body setting now applies to Logger capture/sync/preview paths so Recon and Logger truncate bodies consistently.
  - Added a `?` help popup next to `Max Body` that explains integer safety vs operational memory/UI tradeoffs and gives sizing guidance.
  - Added a `?` help popup next to Recon `Per page` that explains pagination scope/performance tradeoffs and how it differs from `Max Body`.
  - Recon and Logger filter labels are now aligned as `String Filter` and `Regex Filter` for clearer operator intent.
  - Recon and Logger now place the `Saved` filter dropdown before the `Save Filter` button for quicker saved-profile workflows.
  - Recon saved-filter controls now mirror Logger with exactly three colored actions: `Save Filter` (purple), `Clear Saved` (red), and `Clear Filter` (gray).
  - Recon and Logger now support saved filter profiles (string + regex criteria) via `Save Filter`, saved selector apply, and `Remove Filter`.
  - Added explicit `Clear Filter` actions to clear active filter inputs without deleting saved filter profiles.
  - Added explicit `Clear Saved` actions beside saved-filter selectors to remove selected saved entries from memory and persisted settings.
  - Logger row-1 toolbar no longer shows `Clear Data`; shared data clearing remains available from Recon.
  - `Max Rows` is now configured from Recon top controls and acts as a shared cap for Logger runtime retention/pruning behavior.
  - Recon now includes a dedicated `?` help button next to `Max Rows` that explains `Show Last` vs `Max Rows` behavior and tuning guidance.
  - `Auto Prune` is now configured from Recon top controls and applies to Logger retention behavior.
  - `Filter Noise` now uses Recon as the single UI source and applies to both Recon and Logger filtering.
  - `Import on Open` is now configured from Recon top controls as a shared startup backfill control.
  - Logger auto-pruning is now endpoint-aware: oldest duplicate rows are pruned first so one anchor row per endpoint is preserved whenever possible.
  - default Recon/Logger request/response body capture truncation is now `15KB`.
  - Logger max rows default increased from `5,000` to `20,000` (UI + runtime fallback defaults).
- ApiHunter runtime target source reporting now explicitly shows whether the run is using Recon filtered scope or `Custom Targets` popup input.
- GraphQL analysis Wayback stage now avoids shell pipelines:
  - removed inline `bash -lc "echo ... | waybackurls | head"` execution path,
  - now runs Wayback binary directly with `shell=False` and stdin-fed domain input.
- Custom external-tool command override mode now enforces stricter safety validation:
  - blocks shell chaining/redirection/subshell operators (for example: `&&`, `||`, `;`, `<`, `>`, backticks, `$()`),
  - allows only tokenized command syntax with simple pipeline support,
  - logs explicit trusted-operator warning when override mode is active.
- AI prep export caps are now centralized and explicit:
  - `hints=300`, `sequence_candidates=220`, `graph_nodes=900`, `graph_edges=2400`,
  - export payload now carries truncation metadata (`truncated_*`, `max_*`, `total_truncated`).
- Passive/Fuzzer/Wayback `To AI` action ordering was standardized for operator consistency:
  - `To AI` now appears as the final action button and is placed directly to the right of `Clear`.

### Fixed
- Removed unfiltered fallback behavior for ApiHunter target collection; scans now stay strictly scoped to filtered Recon data.
- Strengthened ApiHunter output clarity with explicit source/de-dup metadata and surfaced parse/runtime errors.
- Hardened external binary validation: if all expected flags appear missing, the help probe now force-refreshes cache and retries once before reporting incompatibility.
- Fixed ApiHunter no-op launch path: target-filter config now reads from filtered Recon snapshot format (no list/dict mismatch crash).
- Fixed silent ApiHunter failures: launcher and target collection errors are now always surfaced in-tab and in Burp error logs.
- Fixed ApiHunter preset UX: preset dropdown now has stable display width and preloads the default deep-search template text for immediate visibility.
- Standardized AI export popups to reusable `Copy`/`Exit` two-button dialogs across tab `To AI` actions and Logger AI request export.
- Split ApiHunter toolbar into an additional command/preset row so `Preset` controls are not truncated on common screen widths.
- Fixed ApiHunter timeout parse gap: when `results.ndjson` exists but is empty/partial, Burp now also parses streamed stdout NDJSON and merges/deduplicates findings/errors.
- Fixed result-loss edge case by parsing both `results.ndjson` and stdout JSON output sources, then deduplicating merged findings/error records before summary rendering.
- Added startup collision guard for split-module method injection:
  - duplicate `__all__` exports across modules now raise a clear `RuntimeError` instead of silently shadowing methods.
- Tightened `process_traffic` synchronization:
  - memory-rotation and sample-cap checks now share one pre-extraction lock window,
  - append path now re-checks sample cap to avoid over-cap races during concurrent capture.
- Removed SSTI probe markers (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`) from XSS payload list while keeping them in SSTI payloads.
- Replaced remaining bare `except Exception:` in ApiHunter timeout-kill flow with explicit logged exception handling.
- Fixed ApiHunter custom-target validation gaps:
  - when `Use Custom Targets` is enabled, empty/invalid/overflow popup content now blocks execution with explicit operator-facing error messaging.
- Fixed silent AI-prep clipping ambiguity by surfacing cap/truncation notices in Fuzzer output/logs when prep artifacts are trimmed.

## [1.4.3] - 2026-04-07

### Added
- Token Lineage deep-logic analysis (passive, non-destructive):
  - Added dedicated module: `src/token_lineage_analysis.py`.
  - Added Token Lineage package wrappers in `src/behavior_analysis.py`.
  - Detects high-ROI lifecycle drift patterns from captured traffic:
    - logout/revoke success with continued protected access,
    - refresh rotation overlap across multiple tokens,
    - subject-level parallel token sprawl on overlapping resources.
- Deep-logic export + AI context artifacts for Token Lineage:
  - `token_lineage_findings.json`
  - `token_lineage_ledger.json`
  - `ai_token_lineage_findings.json`
  - `ai_token_lineage_ledger.json`
- Cross-Interface Parity and Drift analysis suite (passive, non-destructive):
  - Added dedicated module: `src/parity_drift_analysis.py`.
  - Added standalone Passive actions:
    - `Run Token Lineage`
    - `Run Parity Drift`
  - Added new detection families for high-ROI logic flaws:
    - cross-interface parity checks (REST vs GraphQL vs internal),
    - cache/auth drift detection,
    - time-window auth drift detection,
    - workflow state-machine breaking heuristics,
    - cross-tenant identifier collision probes,
    - content-type policy drift checks,
    - error-oracle intelligence extraction,
    - replay-after-delete/deactivate checks.
- Deep-logic export + AI context artifacts for parity/drift:
  - `parity_drift_findings.json`
  - `parity_drift_ledger.json`
  - `ai_parity_drift_findings.json`
  - `ai_parity_drift_ledger.json`
- Excalibur bridge interoperability:
  - Added shared export artifact `excalibur_bridge_bundle.json` with schema `excalibur-burp-bridge/v1`.
  - Added import support for Excalibur session exports:
    - `.har`
    - `-replay-studio.json`
    - `-cookies.json`
    - `-insights.json`
    - bridge bundles (`schema: excalibur-burp-bridge/v1`)

### Changed
- `Run Invariants` and Recon `Refresh Invariants` now include Token Lineage generation/storage alongside Differential + Sequence + Golden + State flows.
- Recon invariant footer status now includes `Lineage=` cached count.
- AI bundle/schema/all-tabs context now include `token_lineage` block and `token_lineage_count` metadata.
- `Run Invariants` and Recon `Refresh Invariants` now also include Parity Drift generation/storage.
- Recon invariant footer status now includes `Parity=` cached count.
- AI bundle/schema/all-tabs context now include `parity_drift` block and `parity_drift_count` metadata.
- Captured endpoint samples now include additive timing metadata (`captured_at`, `captured_at_epoch_ms`) for time-window drift analysis.
- Recon `Import` now auto-discovers Excalibur sidecars by session prefix and auto-runs deep-logic invariant refresh after Excalibur imports.

## [1.4.2] - 2026-04-07

### Changed
- Burp startup profile configuration updates:
  - Removed Logger++ from auto-load extensions list
  - Removed Param Miner from auto-load extensions list
  - Removed Autorize from auto-load extensions list
  - Changed default theme from Dark to Light
- Recon/Logger refill flow performance hardening:
  - Moved dual-tab refill orchestration into dedicated module `src/burp_recon_logger_sync_methods.py`.
  - Coordinated Recon+Logger refill through one pipeline to avoid concurrent heavy backfill scans.
  - Backfill history seeding now uses bounded tail-window snapshots instead of full-history list copies.
- Deep-logic run and status flows now include scoreless Differential artifacts:
  - `Run Invariants` now runs Differential + Sequence + Golden + State + Advanced engines.
  - Recon `Refresh Invariants` now refreshes Differential cache alongside Sequence/Golden/State.
  - Recon invariant footer now surfaces `Diff=` count in cached status text.
- Differential parsing/error behavior hardening:
  - Removed silent JSON parse swallowing in differential extraction path.
  - JSON parse failures are now explicitly surfaced via Burp `printError` logging.

### Added
- Advanced deep-logic analysis suite in Passive Discovery:
  - `Run All Advanced`: one-click execution of all advanced deep-logic engines.
  - `Abuse Chains`: graph-to-replay shortest chain builder (`auth -> object access -> state change`).
  - `Proof Mode`: auto-generates minimal reproducible packet sets with expected vulnerable vs safe response signals.
  - `Spec Guardrails`: derives auth/param/method guardrails from observed traffic and flags baseline violations.
  - `Role Delta`: ranks suspicious parity across role behaviors (guest/user/admin-like signals) for BOLA/BFLA triage.
- Advanced artifact export coverage from `Export Ledger`:
  - `abuse_chain_findings.json`, `abuse_chain_ledger.json`
  - `proof_mode_packet_sets.json`
  - `spec_guardrails_rules.json`, `spec_guardrails_violations.json`
  - `role_delta_findings.json`, `role_delta_ledger.json`
- Counterfactual differential pipeline (passive-only, non-destructive, scoreless):
  - New helper module: `src/burp_counterfactual_methods.py`.
  - New Passive Discovery action: `Run Differential`.
  - Detects high-ROI drift classes often missed by signature scanners:
    - representation/auth invariance breaks,
    - identifier source-precedence conflicts,
    - weak-context sensitive-field exposure monotonicity drift.
- Differential artifact export coverage:
  - `counterfactual_differential_findings.json`
  - `counterfactual_differential_summary.json`
- AI export bundle/context/schema coverage for differential artifacts:
  - `counterfactual_differentials` block in `ai_bundle.json` + schema validation/defaulting path.
  - `ai_counterfactual_differential_findings.json`
  - `ai_counterfactual_differential_summary.json`

## [1.4.1] - 2026-04-06

### Added
- Logger toolbar operator-visibility update:
  - Added a dedicated red `Clear Data` action in Logger row-1 controls.
  - `Clear Data` now performs shared data reset semantics (same behavior as Recon `Clear Data`).

### Changed
- Logger toolbar layout is now explicitly two-line to prevent control clipping on narrower Burp windows:
  - row-1 keeps primary filters/toggles and high-frequency actions visible,
  - row-2 hosts secondary actions/search/export controls.
- Logger clear actions simplified:
  - removed duplicate Logger-only clear buttons (`Clear`, `Clear Logs`) from the toolbar,
  - kept one canonical Logger clear entrypoint (`Clear Data`) for Recon+Logger shared clearing.

### Fixed
- Fixed remaining Tags-column rendering leakage where HTML-like tag markup could appear literally in some Burp/Jython Swing render paths.
  - Tags cells now use stable plain-token rendering fallback while retaining row/tag color semantics and tag tooltips.
- Fixed shared clear-data parity so Recon `Clear Data` and Logger `Clear Data` consistently clear both Recon and Logger in-memory state.

### Tests
- Added/updated source-contract coverage in `tests/test_feature_contracts.py`:
  - shared clear-data wiring (`clear_data` + `_clear_logger_logs(emit_log=False)` + Logger `Clear Data` button token).
- Validation:
  - `python3 -m py_compile burp_core_ui_and_fuzz_methods.py burp_capture_export_and_tooling_methods.py tests/test_feature_contracts.py` passed.
  - `python3 tests/run_all_tests.py` passed (`Passed: 4/4`, `Failed: 0/4`).

## [1.4.0] - 2026-04-06

### Added
- Shared Recon/Logger noise filtering workflow:
  - Added `Filter Noise` toggle to Recon filters.
  - Added `Filter Noise` toggle to Logger controls.
  - Reused shared noise heuristics to suppress ad-tech/static/tracker-heavy rows while preserving high-signal API traffic.
- Logger table UX upgrades:
  - Enabled column sorting via header click.
  - Added concurrent multi-column sorting (`Shift+click` adds secondary sort key).
  - Added header tooltip guidance for sorting behavior.
- Logger signal metrics upgrades:
  - `ReqM`/`RespM` now show useful default marker counts when regex is not active.
  - Existing regex-driven `ReqM`/`RespM` behavior remains when regex filter is active.
- Logger/Recon parity hardening:
  - Added lightweight logger-to-recon sync helper for endpoint materialization.
  - `Show Endpoint Detail` now includes recovery path when selected Logger row has no existing Recon entry.

### Changed
- Logger capture controls simplified:
  - Removed redundant `Capture` checkbox from Logger toolbar.
  - `Logging Off` is now the single authoritative Logger capture toggle.
  - Logger status wording changed from `Capture: on/off` to `Logging: on/off`.
- Tooltip coverage improved:
  - Added fallback tooltip generation for checkboxes and buttons that do not define explicit tooltip text.
  - Tooltips standardized to short, plain-language action descriptions.
- Logger sorting/runtime behavior adjusted for stability:
  - Disabled `sortsOnUpdates` to avoid UI stalls during bulk table refresh/backfill while keeping manual header sorting.

### Fixed
- Fixed Logger toggle deadlock where `Logging Off` could become stuck checked and prevent recovery.
- Fixed intermittent `Show Endpoint Detail` failures caused by Logger/Recon endpoint cache drift.
- Fixed `ReqM`/`RespM` appearing as `0` in non-regex workflows by adding default marker metrics.
- Fixed sorted-table selection mapping issues by converting Logger table view indices to model indices for row actions.
- Mitigated Burp reload freeze regressions by:
  - removing expensive recon-rotation work from logger hot path under endpoint-cap pressure,
  - avoiding heavy recon sync during bulk Logger history backfill.

### Tests
- Expanded source-contract checks in `tests/test_feature_contracts.py` for:
  - Recon/Logger shared noise filter wiring.
  - Logger sorting setup (`TableRowSorter`) and header guidance.
  - Logger/Recon parity sync + detail recovery paths.
  - Default `ReqM`/`RespM` marker helper wiring and sorted-row index conversions.
- Validation:
  - `python3 -m py_compile burp_core_ui_and_fuzz_methods.py burp_capture_export_and_tooling_methods.py tests/test_feature_contracts.py tests/run_all_tests.py` passed.
  - `python3 tests/run_all_tests.py` passed (`Passed: 4/4`).

## [1.3.9] - 2026-04-06

### Added
- Recon Param Miner-style hidden parameter workflow:
  - New Recon button: `Hidden Params`.
  - Generates ranked hidden-parameter candidates from scoped Recon data (`All`, `Filtered`, `Host`, or selected endpoint).
  - Candidate pool now combines built-in seeds with harvested words from observed parameters, paths, and JSON request bodies.
  - Added endpoint right-click shortcut: `Hidden Params (Selected Endpoint)`.
- Recon GAP-style global parameter intelligence workflow:
  - New Recon button: `Param Intel`.
  - Aggregates parameter names across `url`, `body`, `json`, and `cookie` sources.
  - Reports frequency, endpoint/host spread, source overlap, sample values, and lightweight risk hints.
  - New export action: `Export Param Intel` with artifacts:
    - `param_intel.json`
    - `param_intel_report.txt`
- Dedicated `Logger++` tab for long-running capture sessions:
  - high-signal request timeline table (`tool`, `method`, `host/path`, `status`, `len`, `type`, `tags`),
  - side-by-side request/response preview inspectors for selected entries,
  - quick actions: `Show Selected`, `To Repeater`, `Export View`, `Clear Logs`.
  - one-tab parity controls inspired by Burp Logger/Logger++:
    - `Backfill History` + `Import on Open` proxy-history seeding,
    - Grep-style regex search with `Req`/`Resp`/`In Scope` toggles,
    - lightweight named filter library (`Save/Apply/Remove Filter`),
    - custom `Tag Rules` popup (`tag|scope|regex`) for operator-defined labels (for example admin-risk tagging),
    - explicit popup launchers for advanced workflows:
      - `Grep Values...` popup with regex + request/response/in-scope toggles and live match preview,
      - `Tag Rules...` popup with quick add fields (`Tag`, `Scope`, `Regex`) and admin preset shortcut,
      - `Tag Rules...` now supports style metadata per rule (`fg`, `bg`, `enabled`) for colorized tag chips,
      - `Tag Rules...` now includes real color picker actions (`Pick FG`, `Pick BG`) plus an innovative `Rule Lab`:
        - live preview of regex matches on cached Logger events,
        - sample matched endpoints (method/host/path/status/len),
        - one-click `Auto Style` color suggestions based on tag intent,
    - bulk operator actions from Logger table context menu:
      - `Select All Rows`
      - `Copy Selected Rows`
      - `Send Selected To Repeater`
      - `Tag Rules (Regex)...`,
    - multi-format export selector (`JSONL`, `JSON`, `CSV`).
- GraphQL Raider-inspired upgrades in `GraphQL` tab:
  - attack-family toggles (`Introspection`, `Batching`, `Aliases`, `Depth`, `Mutations`, `Field Guess`, `Directives`, `Fragments`),
  - one-click `Generate Raider` operation pack,
  - request mode selector (`POST JSON` or `GET Query`) for Repeater/Intruder sends,
  - custom header injection field for GraphQL operation dispatch.
  - saved profile selector for quick mode switching:
    - `Balanced`
    - `Safe Recon`
    - `Aggressive Raider`
    with one-click apply to synchronize attack-family toggles + request mode + max-ops.

### Changed
- Recon help dialog and button tooltips now include `Hidden Params`, `Param Intel`, and `Export Param Intel`.
- Recon clear-data flow now resets hidden-param and parameter-intel in-memory snapshots.
- Extracted Recon Param/GAP logic into a dedicated helper module `recon_param_intel.py` and kept thin delegating wrappers in `BurpAPISecuritySuite.py` to reduce Jython compile pressure (`Module or method too large` risk).
- Refactored Burp startup wiring so `registerExtenderCallbacks` is now a thin orchestrator with smaller helper methods for state init, Recon UI build, tab creation, output-dir init, and callback registration to further reduce Jython method-size risk.
- Added `jython_size_helpers.py` and delegated additional large methods from `BurpAPISecuritySuite.py`:
  - `_create_auth_replay_tab`
  - `show_endpoint_details`
  - `_run_auth_replay`
  - `_process_traffic`
  - `_collect_nuclei_targets`
  - `_collect_ffuf_targets`
  - `_collect_wayback_queries`
  This further reduces compile pressure on the primary Burp entry module.
- Reworked `BurpExtender` method layout for Jython compatibility:
  - Methods are now defined at module scope and rebound to `BurpExtender` at import time.
  - `BurpExtender` class body now mainly contains constants, significantly reducing class compile-size pressure.
- Split extracted BurpExtender methods into dedicated helper modules:
  - `burp_core_ui_and_fuzz_methods.py` (startup wiring, Recon/UI build, fuzz generation helpers)
  - `burp_fuzz_detection_and_capture_methods.py` (fuzz detection/evidence and capture ingestion helpers)
  - `burp_capture_export_and_tooling_methods.py` (capture normalization, export flows, and tool-control helpers)
  - `burp_auth_passive_and_scanner_methods.py` (auth replay, passive analysis, scanner target orchestration)
  - `burp_wayback_import_and_logging_methods.py` (Wayback import + shared UI logging helpers)
  with runtime rebinding in `BurpAPISecuritySuite.py`, reducing main-module Jython compile pressure further.
- Fixed split-module startup symbol resolution by expanding Swing/Java imports in helper modules (for example `BorderFactory`) so tabs render correctly after extension load.
- Auth Replay now performs best-effort automatic header prefill for empty `Guest/User/Admin Header` fields from captured traffic before replay starts (selected endpoint preferred, then Recon history), closer to Autorize-style automatic detection UX.
- Auth Replay tab UI now follows a more Autorize-like operator layout:
  - table-first replay results view (`ID`, method/URL, per-role status/length, result summary),
  - right-side configuration groups for headers, filters, and unauth detector settings,
  - `Clear Table` now resets both table rows and replay output.
- Logger capture path now includes long-session protections:
  - bounded in-memory retention (`Max Rows`) with incremental prune batches,
  - UI refresh debounce to avoid event-table repaint thrash during heavy traffic,
  - capture pause toggle (`Capture`) and auto-prune toggle (`Auto-prune`),
  - `Show Last` limit to keep render volume under operator control.
- Logger view now reports grep match counts per row (`ReqM`, `RespM`) and live status summary includes grep/scope/capture state.
- Logger table title now aligns with tab naming (`Logger Events`).
- Logger toolbar now includes first-class operations controls:
  - `Logging Off` capture toggle,
  - quick `Clear` button,
  - `?` help popup,
  - response length filters (`Len >=`, `Len <=`).
- Logger regex control now behaves as an active live filter (debounced):
  - right-side `Regex` field is consumed directly in every logger refresh cycle,
  - invalid inline regex is surfaced in status text without noisy repeated log spam.
- Logger tag-rule defaults are now auto-seeded with colored baseline presets:
  - `api_endpoint`, `auth`, `sensitive`, `idor_risk`, `write_ops`, `jwt`,
  - presets merge with operator custom rules (missing built-ins appended, existing custom rules preserved).
- Fuzzer sparse-session enrichment:
  - added bounded heuristic candidate scoring/fallback when API-like target set is too small,
  - retains scope/noise filtering while increasing campaign depth on low-signal captures,
  - summary now reports fallback contribution (`+N heuristic endpoints from M candidates`).

### Tests
- Extended `tests/test_feature_contracts.py` with wiring checks for Recon Param Miner/GAP integrations.
- Added source-contract coverage for Logger++ tab wiring and long-session control hooks.

## [1.3.8] - 2026-04-06

### Added
- Autorize-inspired Auth Replay upgrades:
  - Added interception-style filters: `Include Regex`, `Exclude Regex`, and `Methods`.
  - Added configurable enforcement detectors:
    - `Enforced Status` (comma-separated HTTP status list)
    - `Enforced Regex` (response preview regex)
  - Added per-profile detector overrides (`guest`, `user`, `unauth`) for status and regex matching.
  - Added `Check Unauth` toggle to explicitly replay unauthenticated requests.
  - Auth Replay findings now suppress bypass alerts when low-privileged responses clearly match enforcement detectors.
- InQL-inspired GraphQL upgrades:
  - Added local schema picker (`Schema File` + `Browse`) for introspection JSON analysis.
  - Added `Analyze Schema` action to generate operations and summarize:
    - generated queries/mutations/subscriptions
    - points of interest categories
    - circular type references
  - Added `Batch Queries` export action for GraphQL batching/rate-limit testing payload packs.
  - Added direct operation handoff actions:
    - `To Repeater` sends generated schema operations as runnable GraphQL requests.
    - `To Intruder` sends generated schema operations for Intruder workflows.
  - Added GraphQL batch export artifacts:
    - `graphql_batch_payload.json`
    - `graphql_queries.txt`
    - `README.txt`

### Changed
- GraphQL tab now tracks generated operation templates in memory (`graphql_generated_operations`) for downstream export/testing.
- Auth Replay UI guidance now explicitly documents Autorize-style detector/filter mode.

### Tests
- Extended `tests/test_feature_contracts.py` with wiring checks for:
  - Auth Replay detector/filter controls and enforcement logic helpers.
  - GraphQL schema analysis and batch export actions/helpers.

## [1.3.7] - 2026-04-06

### Added
- Recon Logger++-style triage controls:
  - `Tag` filter sourced from auto-tagged endpoint metadata.
  - `Tool` filter sourced from captured request origin (`Proxy`, `Repeater`, `Intruder`, `Manual`, etc.).
  - `Regex` + scope filter (`Any`, `Request`, `Response`, `Req+Resp`) for advanced content matching.
- Recon `Grep` action for capture-wide regex search and extraction of match groups from request/response data.
- Extended automatic Recon tagging with Logger++-inspired categories:
  - `api_endpoint`, `auth`, `idor_risk`, `sensitive`, `write_ops`, `jwt`, `admin_debug`, `no_auth`.
- Recon `Turbo Pack` export:
  - Exports Turbo Intruder-ready request templates with `%s` insertion points.
  - Exports starter Turbo scripts (`basic.py`, `race_gate.py`), payload seed list, and manifest.
  - Added right-click shortcut on selected Recon endpoint: `Export Turbo Pack (Selected Endpoint)`.

### Changed
- Recon capture entries now track `source_tool` so operators can filter/log by origin tool.
- Endpoint tags now merge over time as additional samples are captured for the same endpoint key.
- Recon button help text now includes `Grep` and `Turbo Pack` guidance.

### Tests
- Expanded `tests/test_feature_contracts.py` with wiring checks for:
  - Recon Logger++-style filters and grep action.
  - Recon Turbo Pack export and selected-endpoint popup action.
  - Source tool tracking and new tag/filter update helpers.

## [1.3.6] - 2026-04-06

### Added
- Non-destructive **Golden Ticket** analysis from captured traffic (no active probing):
  - Finds tokens reused across unrelated resources
  - Flags likely over-privileged token patterns
  - Checks JWT expiry/scope/audience signals when claims are available
- Extracted Golden Ticket logic to a dedicated module: `golden_ticket_analysis.py`.
- Kept compatibility wrappers in `behavior_analysis.py`:
  - `build_golden_ticket_findings(...)`
  - `build_golden_ticket_package(...)`
- New AI export artifacts:
  - `ai_golden_ticket_findings.json`
  - `ai_golden_ticket_ledger.json`
- Extended `Export Ledger` artifact set:
  - `golden_ticket_findings.json`
  - `golden_ticket_ledger.json`
- Non-destructive **State Transition Matrix** analysis from captured traffic:
  - Finds workflow/state drift across methods and auth contexts
  - Flags write/read overlap and inconsistent transition outcomes
- Extracted State Transition logic to a dedicated module: `state_transition_analysis.py`.
- Kept compatibility wrappers in `behavior_analysis.py`:
  - `build_state_transition_findings(...)`
  - `build_state_transition_package(...)`
- New AI export artifacts:
  - `ai_state_transition_findings.json`
  - `ai_state_transition_ledger.json`
- Extended `Export Ledger` artifact set:
  - `state_transition_findings.json`
  - `state_transition_ledger.json`

### Changed
- `Run Invariants` and Recon `Refresh Invariants` now compute/store Sequence + Golden + State Matrix findings.
- Recon status line now shows Sequence, Golden, and State counts.
- AI export bundle/all-tabs context now include `state_transitions` alongside `sequence_invariants` and `golden_tickets`.
- AI prompt guidance now also asks for token-overreach and state-transition hypotheses.

### Documentation
- Added a plain-language "recent additions" summary in `README.md` covering shipped updates across v1.3.2 -> v1.3.5 in one place.
- Clarified invariant workflow order in docs as:
  - `Run Invariants` (Passive Discovery) -> `Refresh Invariants` (Recon) -> `Export AI Bundle`.
- Documented shipped Sequence/Golden/State artifacts and optional AI prep artifacts in simpler language.
- Updated README to show Golden Ticket as shipped and where related files are exported.

### Tests
- Expanded source-contract assertions to cover Golden Ticket wiring and artifact filenames.
- Added golden replay test coverage for Golden Ticket detection/ledger output.
- Expanded source-contract assertions to cover State Transition wiring and artifact filenames.
- Added golden replay test coverage for State Transition detection/ledger output.

## [1.3.5] - 2026-04-05

### Changed
- Moved AI export action from the Fuzzer tab to the Recon tab to reflect its real scope:
  - New Recon button: `Export AI Bundle`
  - Removed misleading Fuzzer-only `AI Payloads` action placement.
- Added explicit Recon button explanations:
  - Per-button tooltips for Recon actions.
  - New `Button Help` dialog describing each Recon control and expected output.
- Generalized tooltip wiring with reusable helpers (`_set_component_tooltip`, `_apply_component_tooltips`) to reduce repetitive per-button tooltip code.
- Unified tooltip rendering to a single deterministic path and enabled a global Swing tooltip policy (`ToolTipManager`) to avoid missing Recon tooltips.
- Added centralized auto-tooltips for all action buttons created via `_create_action_button`, so non-Recon tabs now get consistent hover guidance too.
- Upgraded auto-generated button tooltips from generic verb text to operator-focused guidance (scope, action outcome, and export/reuse intent).
- Simplified invariant-specific tooltip wording to plain action language:
  - `Run Invariants`: "Check captured endpoint flows for hidden logic issues"
  - `Refresh Invariants`: "Recompute invariant checks from Recon/captured data"
  - `Export Ledger`: "Save invariant findings and confidence report"
- Added passive-tab deep logic actions:
  - `Run Invariants` for sequence/state invariant analysis on scoped captured traffic.
  - `Export Ledger` for confidence-weighted evidence artifacts.
- Improved Passive Discovery layout visibility by splitting controls into dedicated rows (`Passive Checks` + `Deep Logic`) so new actions are not hidden on narrower windows.
- Added Recon-side deep-logic visibility and control:
  - New `Refresh Invariants` button near `Export AI Bundle`.
  - New live invariant status line (findings/confidence/source/updated timestamp) so operators can see freshness before AI export.
- Extended AI export bundle with non-destructive deep-logic artifacts:
  - `ai_sequence_invariant_findings.json`
  - `ai_sequence_evidence_ledger.json`
- Started maintainability extraction by moving deep logic invariant/ledger generation into `behavior_analysis.py` with thin wrappers in `BurpAPISecuritySuite.py`.

### Tests
- Updated `tests/test_feature_contracts.py` to assert:
  - Recon AI export + help button wiring.
  - Recon help dialog content and tooltip guidance.
  - Removal of legacy `AI Payloads` button label from source.
- Added `tests/test_golden_replay.py` + fixture corpus (`tests/fixtures/golden_replay_sequence.json`) for behavior-level replay coverage of sequence invariants and evidence ledger output.

### Documentation
- Updated README invariant workflow guidance to clarify recommended order:
  - `Run Invariants` (Passive Discovery) -> `Refresh Invariants` (Recon) -> `Export AI Bundle`.
- Updated README tab descriptions and FAQ language for invariant actions to match current UI wording and exported artifacts.

## [1.3.4] - 2026-04-05

### Added
- Non-destructive AI prep export layer for deeper post-collection triage:
  - `ai_prep_invariant_hints.json`
  - `ai_prep_sequence_candidates.json`
  - `ai_prep_evidence_graph.json`
- New additive AI prep builders in `BurpAPISecuritySuite.py`:
  - Invariant hints for state consistency, auth boundaries, lifecycle integrity, and financial-integrity checks.
  - Sequence candidate generation for multi-step abuse paths (create/read, read/modify/read, delete/re-read, race probes, cross-context replay).
  - Evidence graph linking endpoints, parameters, auth contexts, and attack candidates.
- Feature flag support via `AI_PREP_LAYER` environment variable for controlled rollout.

### Changed
- `Export for LLM` now conditionally writes AI prep artifacts when `AI_PREP_LAYER` is enabled, while preserving all existing export files and schemas unchanged.
- Refactored heavy AI prep builder logic into `ai_prep_layer.py` and kept lightweight wrappers in `BurpAPISecuritySuite.py` to reduce single-module compile pressure in Jython/Burp environments.
- Extracted large external scanner runner methods into `heavy_runners.py` and delegated from `BurpAPISecuritySuite.py` wrappers (`GraphQL`, `Nuclei`, `HTTPX`, `Katana`, `FFUF`, `Wayback`) to further reduce Jython compile-size risk (`Module or method too large`).

### Tests
- Expanded `tests/test_feature_contracts.py` with additive export-contract checks for:
  - AI prep feature-flag wiring.
  - AI prep helper method presence.
  - AI prep artifact filenames and non-destructive intent messaging.

## [1.3.3] - 2026-04-05

### Added
- Enhanced AI context export bundle for security analysis workflows:
  - New multi-file outputs including `ai_bundle.json`, `ai_vulnerability_context.json`, `ai_all_tabs_context.json`, and per-platform request payloads for OpenAI/Anthropic/Ollama.
  - Cross-tab context aggregation (Recon, Fuzzer, Passive Discovery, Auth Replay, Nuclei/HTTPX/Katana/FFUF/Wayback, SQLMap, Dalfox, API Assets, OpenAPI Drift, GraphQL).
  - Payload sanitization/redaction helpers for sensitive fields before exporting to external LLMs.
- New `Lenient JSON GET` mode controls in `Fuzzer`, `Param Miner`, and `Version Scanner` tabs for structured-content API targeting beyond strict `/api/` path heuristics.
- Stricter path/parameter keyword markers for targeted fuzzing decisions:
  - Added dedicated strict noise marker sets for Fuzzer/Param Miner/Version Scanner.
  - Added SQLi/SSRF/SSTI parameter keyword sets to prioritize likely injection points.
- Capture UI refresh debouncing for Recon updates to reduce refresh churn during high-volume traffic capture.
- Runtime heartbeat messages for long-running staged command execution (e.g., Subfinder stage output progress).

### Changed
- Fuzzer candidate selection and attack generation now apply stronger API-signal and object-target checks to reduce false positives in BOLA/Auth Bypass/SQLi/SSRF/SSTI paths.
- Param Miner and Version Scanner collection flow now supports strict-vs-lenient routing behavior with clearer endpoint filtering summaries.
- External command streaming hardened across tools by consolidating stderr into stdout and decoding streamed bytes consistently.
- Nuclei runtime output handling now uses capture-file based ingestion (`nuclei_runtime.log`) for safer parse and diagnostics flow.
- SQLMap and Dalfox verification output capture now uses temporary log files with cleanup to improve evidence extraction reliability.
- Asset discovery domain selection now applies host-filter/scope-aware prioritization with source metadata (`manual`, `selected`, `history`) and dropped-item telemetry.

### Fixed
- GraphQL analysis error logging now preserves exception text safely when emitting asynchronous UI log callbacks.
- Security observation analysis now works against normalized snapshots directly instead of mutating shared capture state.

### Tests
- Expanded `tests/test_feature_contracts.py` to cover:
  - Enhanced AI export bundle and LLM payload format builders.
  - Strict/lenient endpoint filtering behavior in Fuzzer/Param Miner/Version Scanner.
  - Runtime output capture-path contracts for Nuclei and staged command execution.
  - Target-base scope and host-filter enforcement paths.
- Updated `tests/test_fuzzer_logic.py` normalization assertions for `host` and `protocol` handling.

## [1.3.2] - 2026-04-05

### Added
- New `GraphQL` tab wired into the external workflow with run/export/send-to-Recon actions.
- OpenAPI Drift spec auto-detection from proxy history:
  - Automatic best-candidate preselection.
  - Manual `Detect` action to refresh candidate selection.
- Subfinder command presets and optional custom command override in the asset discovery tab.
- Copy-ready output blocks for discovered asset domains and generated asset URLs.

### Changed
- Inlined tool profile and command builder helpers into `BurpAPISecuritySuite.py` to simplify runtime dependencies.
- Version Scanner path generation now preserves or replaces existing version segments more safely via `_build_version_test_path`.
- API asset discovery flow now runs a Subfinder-first workflow with stronger fallback behavior when command output is limited.
- External tab labels and ordering updated in UI wiring:
  - `sqlmap`, `Dalfox`, `Subfinder`, `OpenAPI Drift`, `GraphQL`.

### Removed
- Removed legacy standalone `tool_profiles.py` helper module.
- Removed `tests/test_tool_profiles.py` and consolidated coverage through feature contract tests.

### Tests
- Updated `tests/test_feature_contracts.py` to assert:
  - OpenAPI spec auto-detection flow and detect action wiring.
  - Subfinder copy-ready output and fallback behavior.
  - GraphQL tab and action wiring.
  - In-file profile helper wiring after `tool_profiles` module removal.
- Updated `tests/run_all_tests.py` to stop invoking the removed `test_tool_profiles` suite.

## [1.3.1] - 2026-04-05

### Changed
- Reordered tab layout to keep internal workflow tabs first:
  - `Recon`, `Diff`, `Version Scanner`, `Param Miner`, `Fuzzer`, `Auth Replay`, `Passive Discovery`
- Moved external scanner/tool tabs to the end in operational order:
  - `Nuclei`, `HTTPX`, `Katana`, `FFUF`, `Wayback`, `SQLMap Verify`, `Dalfox Verify`, `API Assets`, `OpenAPI Drift`

### Documentation
- Updated README Tab Overview ordering and numbering to match the in-app UI.
- Added explicit `Passive Discovery` tab documentation in Tab Overview.
- Updated README release/version references for semver consistency after `1.3.0`.

## [1.2.2] - 2026-04-05

### Added
- **Enhanced GraphQL Fuzzing**: Expanded GraphQL attack payloads from 5 to 40+ vectors
  - Advanced introspection queries (queryType, mutationType, __type)
  - Field suggestion attacks for schema discovery when introspection is disabled
  - Directive overloading (@skip, @include, @deprecated abuse)
  - Circular fragment DoS attacks
  - Array-based batching attacks
  - Improved depth attacks with deeper nesting
  - Additional mutation injection payloads
- GraphQL FAQ entry with three-pronged testing approach (Fuzzer + Nuclei + Manual)
- Nuclei GraphQL template documentation (29+ templates available)

### Changed
- GraphQL attack detection now includes 7 attack categories (was 4)
- Updated GraphQL risk description to include schema disclosure and field suggestion
- Improved GraphQL payload organization by attack type

### Documentation
- Updated README with detailed GraphQL attack capabilities
- Added GraphQL testing guidance in FAQ section
- Documented Nuclei GraphQL template integration

## [1.2.1] - 2026-04-05

### Changed
- **Nuclei Performance Optimization**: Dramatically improved scan speed and reliability
  - Reduced tag set from 10 to 4 tags (exposure, api, swagger, openapi) for focused API discovery
  - Faster timeout: 12s → 8s per request (33% faster)
  - Fewer retries: 2 → 1 (50% reduction in wasted time)
  - Higher throughput: rate limit 50 → 100 req/s, concurrency 10 → 20 (2x faster)
  - Added exclusions: fuzzing, brute-force tags
  - Expected scan time: 2-5 minutes (vs 15+ minute timeouts)
  - Trade-off: Less comprehensive coverage, but much faster and more reliable for endpoint discovery
- Updated "Recon Fast" preset with optimized parameters
- Updated UI messages to reflect "optimized for speed" configuration

### Fixed
- Nuclei timeout issues on large target sets (e.g., allocine.fr)
- Excessive template loading causing 15+ minute hangs

### Documentation
- Added `NUCLEI_OPTIMIZATION.md` explaining the performance improvements and when to use custom commands for comprehensive scans

## [1.2.0] - 2026-04-02

### Added
- New `Auth Replay` tab to compare authorization behavior across Guest/User/Admin profiles.
- Replay scope selector (`Selected Endpoint`, `Filtered View`, `All Endpoints`) and run limiter (`Max`).
- Profile header `Extract` actions for Guest/User/Admin with candidate discovery from captured Recon traffic.
- Searchable extraction popup with live filtering to pick header candidates safely and explicitly.
- Replay stop control integrated with cross-platform cancellation flow.

### Changed
- Auth Replay helper text and logging now explain extraction/selection workflow clearly.
- Header extraction now prioritizes profile-aware candidates while preserving explicit user choice.

### Fixed
- Eliminated ambiguous single-candidate auto-fill for replay profile headers by requiring explicit popup selection.

## [1.1.0] - 2026-04-02

### Added
- Custom command override controls (`Use Custom Cmd`) for Nuclei, HTTPX, Katana, and Wayback tabs.
- Command preset dropdowns and richer `?` help popups with usage flow, placeholders, and override rules.
- Cross-platform stop controls for external tool runs (`Stop` button per tab).
- External tool process tracking and cancellation state for long-running scans.
- Dedicated local binary compatibility checks for Nuclei, HTTPX, Katana, and FFUF.
- Wayback custom-command tool checks for `waybackurls` and `gau`.

### Changed
- Nuclei default/preset commands now avoid unsupported flags and focus on broad compatibility.
- External tool UX now clearly separates default mode vs override mode.
- README updated with current external-tool workflow and troubleshooting notes.

### Fixed
- Prevented misleading success summaries when custom command scope differs from generated target scope.
- Improved non-zero exit handling and actionable error hints for external tools.
- Added specific guidance for HTTPX binary mismatch (ProjectDiscovery vs Python CLI).
- Removed hidden error suppression patterns in updated external-tool execution paths.

## [1.0.0] - Initial Release

- Initial public release of BurpAPISecuritySuite.
- Recon, Diff, Version Scanner, Param Miner, Fuzzer, Nuclei, HTTPX, Katana, FFUF, and Wayback tabs.
- 15 attack types with payload generation, Burp Intruder export, Turbo Intruder scripts, and AI context export.
