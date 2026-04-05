# Changelog

All notable changes to this project are documented in this file.

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
