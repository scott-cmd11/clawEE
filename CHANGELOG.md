# Changelog

## Unreleased

- Added Initiative Engine and Initiative Store for proactive task orchestration with retry/backoff, interruption controls, and hash-chained initiative events.
- Added initiative control endpoints for create/list/state transitions and task/event inspection (`/_clawee/control/initiatives*`).
- Added initiative telemetry to control status/metrics and conformance context.
- Added initiative smoke test and wired it into `smoke:security`.
- Added periodic immutable export jobs for audit attestation and security conformance with chain sealing and retention controls.
- Added initiative RBAC boundary coverage in gate integration smoke tests (`initiative.read` vs `initiative.write`).
- Added keyring coverage tests for audit attestation and security conformance signatures.
- Added repo-check workflow assertions to enforce strict replay smoke in CI/release workflows.
- Added key-rotation runbook for signed catalogs and attestation/conformance signing surfaces.
- Added security-hardened initiative intake adapters for Jira/Linear/PagerDuty webhook ingestion with token/HMAC auth and replay protection.
- Added typed provider intake template compiler (`notify+triage`) so Jira/Linear/PagerDuty events produce deterministic `channel.send` task plans with template metadata.
- Added production validation harness (`scripts/production-validation.mjs`) with quick/staging/soak profiles and JSON evidence reports.
- Added production validation runbook and npm commands (`validate:production*`) for release gating.
- Added startup audit hash-chain verification with configurable fail mode (`AUDIT_STARTUP_VERIFY_MODE`).
- Added `GET /_clawee/control/audit/verify` for runtime audit-integrity checks.
- Added `verify-audit-chain` command in `scripts/security-tools.mjs` for offline/CI validation.
- Added strict modality-ingest schema validation (`text|vision|audio|action`) with configurable payload size limits.
- Added inbound channel text-size enforcement (`CHANNEL_INGRESS_MAX_TEXT_CHARS`) and explicit `413` responses for oversize payloads.
- Added signed audit attestation payload/snapshot export + chain verification control endpoints.
- Added audit-attestation signing key reload endpoint with static key and keyring support.
- Added runtime security invariant registry and fail-closed invariant enforcement mode.
- Added signed security conformance export/verify endpoints with sealed chain evidence.
- Added static anti-bypass checker (`scripts/security-invariants-check.mjs`) integrated into `repo:check`.
- Added Postgres replay-store backend (`REPLAY_STORE_MODE=postgres`) with schema/table bootstrap and TTL cleanup.
- Added cluster identity metadata (`CLAWEE_NODE_ID`, `CLAWEE_CLUSTER_ID`) to status/metrics/conformance artifacts.
- Added config-fingerprint telemetry to detect cross-node policy/config drift in multi-node deployments.
- Added Postgres replay smoke test and wired it into `smoke:security`.
- Added strict replay smoke mode (`REPLAY_SMOKE_STRICT=true`) that fails on missing replay backends.
- Added `smoke:security:strict` script and moved smoke scripts to cross-platform `npm run build` invocation.
- Upgraded GitHub `security-smoke` and `release` workflows to run Redis/Postgres service-backed strict replay smoke checks.

## 0.1.0

- Air-gapped sidecar proxy with runtime egress enforcement.
- Signed policy/model/capability catalogs with keyring rotation support.
- High-risk approval workflow with quorum + role requirements.
- Approval attestation export with hash-chained sealed snapshots.
- Economic circuit breaker (hourly/daily spend caps).
- Channel ingress HMAC + replay protections (nonce and event-id dedupe).
- Outbound channel controls (destination policy, connector signing, size caps).
- Fail-closed risk evaluator mode and per-request token ceilings.
- Security smoke test suite and GitHub CI workflow.
