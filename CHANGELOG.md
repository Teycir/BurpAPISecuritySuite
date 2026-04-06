# Changelog

All notable changes to this project are documented in this file.

## [1.3.10] - 2026-04-06

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
