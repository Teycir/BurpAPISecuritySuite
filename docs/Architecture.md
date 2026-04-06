# BurpAPISecuritySuite Architecture

This page explains the core analysis pipeline behind three advanced features:
- State Transition Matrix
- Golden Ticket analysis
- AI Evidence Graph

## High-Level Flow

1. Capture traffic in Recon/Logger (`processHttpMessage` / `processProxyMessage`).
2. Normalize requests into endpoint keys (`METHOD:/normalized/path`) with bounded samples.
3. Build deep-logic artifacts from the captured snapshot:
   - Sequence invariants
   - Golden Ticket findings
   - State Transition Matrix findings
4. Build AI context exports:
   - Vulnerability + behavioral context
   - Cross-tab context
   - AI prep layer (invariant hints, sequence candidates, evidence graph)
5. Export structured JSON bundles for operator review and LLM-assisted triage.

## Analysis Matrix

The suite uses a layered matrix view of captured behavior:

- **Endpoint Matrix**: method/path/auth/params/status/content-type by endpoint key.
- **State Transition Matrix**: inferred resource transitions and write/read drift risks.
- **Auth Context Matrix**: where auth modes differ for similar resources/paths.

This matrix is passive and non-destructive: it uses observed traffic, not active mutation.

## Golden Ticket Model

Golden Ticket analysis looks for token overreach patterns using captured sessions only:

- one token touching many unrelated resources
- privilege/context mismatch signals across endpoints
- cross-role access patterns that look like master-key behavior

The output is a findings list plus a confidence ledger to keep the signal explainable.

## AI Evidence Graph

The AI prep layer builds a graph to keep reasoning grounded:

- **Nodes**: endpoints, parameters, auth contexts, attack candidates
- **Edges**: `has_param`, `uses_auth`, `flagged_as`
- **Purpose**: provide structured context so AI workflows reason over relationships, not only raw text blocks

This graph is additive: it does not suppress runtime detection paths.

## Design Principles

- **Capture-first**: broad collection before narrowing.
- **Additive analysis**: no hard gating from AI prep artifacts.
- **Explainability**: findings are paired with evidence and confidence metadata.
- **Operator control**: all deep logic can be refreshed/exported from UI workflows.

## Where It Lives in Code

- `src/burp_fuzz_detection_and_capture_methods.py`
  - AI bundle export, cross-tab context, payload sanitization
- `src/burp_auth_passive_and_scanner_methods.py`
  - sequence/golden/state package orchestration and formatting
- `src/behavior_analysis.py`
  - wrappers delegating to extracted deep-logic modules
- `src/golden_ticket_analysis.py`
  - token overreach/master-key pattern logic
- `src/state_transition_analysis.py`
  - workflow/state drift and transition matrix logic
- `src/ai_prep_layer.py`
  - invariant hints, sequence candidates, evidence graph
