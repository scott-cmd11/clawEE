# Changelog

## Unreleased

- Added startup audit hash-chain verification with configurable fail mode (`AUDIT_STARTUP_VERIFY_MODE`).
- Added `GET /_clawee/control/audit/verify` for runtime audit-integrity checks.
- Added `verify-audit-chain` command in `scripts/security-tools.mjs` for offline/CI validation.
- Added strict modality-ingest schema validation (`text|vision|audio|action`) with configurable payload size limits.
- Added inbound channel text-size enforcement (`CHANNEL_INGRESS_MAX_TEXT_CHARS`) and explicit `413` responses for oversize payloads.
- Added signed audit attestation payload/snapshot export + chain verification control endpoints.
- Added audit-attestation signing key reload endpoint with static key and keyring support.

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
