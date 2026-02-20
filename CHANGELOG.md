# Changelog

## Unreleased

- Added startup audit hash-chain verification with configurable fail mode (`AUDIT_STARTUP_VERIFY_MODE`).
- Added `GET /_clawee/control/audit/verify` for runtime audit-integrity checks.
- Added `verify-audit-chain` command in `scripts/security-tools.mjs` for offline/CI validation.

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
