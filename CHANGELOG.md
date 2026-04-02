# Changelog

All notable changes to this project are documented in this file.

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
