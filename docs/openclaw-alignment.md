# OpenClaw Alignment (Claw-EE)

This note maps Claw-EE controls to the OpenClaw runtime surface so the sidecar stays compatible with upstream OpenClaw behavior.

Reference architecture source:
- OpenClaw repository README: https://github.com/openclaw/openclaw

## OpenClaw Surface -> Claw-EE Control

- `openclaw daemon` / background operation
  - Claw-EE maps this to `HeartbeatService` plus runtime egress enforcement and budget circuit breaking.
- Proactive task execution / "initiative" behavior
  - Claw-EE maps this to `InitiativeEngine` + `InitiativeStore` with task retries, interrupt handling, and hash-chained initiative events.
- External work-queue intake (Jira/Linear/PagerDuty style)
  - Claw-EE maps this to signed/tokenized initiative intake webhooks that normalize provider events into initiatives with replay protection.
- OpenClaw runtime work-item events
  - Claw-EE maps this to dedicated adapter intake endpoints (`/_clawee/intake/openclaw/work-item`, `/_clawee/intake/openclaw/heartbeat`) with token/HMAC auth, replay protection, and initiative normalization.
- Built-in skills and direct host actions (`run shell`, file writes, browser automation)
  - Claw-EE maps this to policy engine block/approval gates, uncertainty scoring, and model registry checks before forwarding.
- Workspace memory (`SOUL.md`, agent session logs under `.openclaw`)
  - Claw-EE maps this to `AffectiveMemoryService`, audit logging, and interaction persistence.
- Communication channels (Slack/Teams/Discord/Email style usage pattern)
  - Claw-EE maps this to authenticated channel ingress, strict ingress payload validation, signed channel delivery, and delivery lifecycle state tracking.
- Model/provider configuration (`OPENCLAW_MODEL`, API base URLs, enterprise providers)
  - Claw-EE maps this to air-gap attestation, runtime DNS/IP revalidation, TLS/mTLS hardening, and signed model registry policy.
- Modality ingestion (`text`, `vision`, `audio`, `action`)
  - Claw-EE maps this to strict schema validation, payload bounds, and audit-backed ingestion endpoints for multimodal event streams.

## Security-first delta beyond OpenClaw base runtime

- Hash-chained audit ledger (tamper-evident provenance trail).
- Startup/runtime audit-chain integrity verification (`AUDIT_STARTUP_VERIFY_MODE`, `/_clawee/control/audit/verify`).
- Audit attestation export/verification with sealed append-only snapshot chain.
- Runtime security invariants registry and conformance artifact export/verification.
- Strict modality envelope/payload schema checks with modality-specific size caps.
- Economic circuit breaker (hourly/daily hard caps with suspension).
- Fail-closed risk gate mode (`RISK_EVALUATOR_FAIL_MODE=block`) for evaluator outages.
- Approval workflow for high-risk actions and high-risk outbound messages.
- Quorum approvals (two-person rule via configurable `APPROVAL_REQUIRED_COUNT`).
- Signed approval-policy catalog for stricter per-risk/per-tool/per-channel approval roles/quorum.
- Single-use approval token consumption (`APPROVAL_MAX_USES`) to reduce approval replay abuse.
- Signed policy catalog and signed model registry.
- Channel ingress HMAC verification (timestamp-bound) and outbound connector signature support.
- Channel ingress replay defense (nonce + stable event-id tracking) and scoped RBAC for control-plane endpoints.
  - `REPLAY_STORE_MODE=redis|postgres` supports cluster-shared replay dedupe.
- Signed channel connector catalogs to prevent webhook target tampering.
- Endpoint abuse controls via fixed-window rate limiting on control and channel ingress routes.
- Optional signed control-token catalog for RBAC integrity and hot reload.
- Signed capability policy catalog for fine-grained action segmentation (per channel and per tool).
- Signed per-channel destination policy with queue-time and delivery-time enforcement.
- Approval attestation export (hash chain + optional signature) for governance evidence.
- Periodic approval attestation snapshot job with append-only seal chain.
- Periodic audit-attestation and security-conformance export jobs with append-only seal chains.
- Verification tooling/API for snapshot and chain integrity checks.
- Signing key rotation via keyrings (`kid`/multi-key trust) for control tokens and attestation signatures.
- Hot-reload endpoint for attestation signing keyring rotation without process restart.

## Remaining roadmap (not fully solved in current MVP)

- Full VDI computer-use runtime (persistent desktop/session sandbox with vision-to-action loop).
- Live synchronous meeting presence (calendar join, real-time STT diarization, low-latency TTS response loop).
- Enterprise IAM/SSO bridge for dedicated synthetic worker identities and revocation lifecycle.
- Expanded initiative template library beyond current `notify+triage` plans (for example, provider-native ticket transitions, owner reassignment, and escalation fanout).
- Formal machine-checked proofs for every critical action path (current implementation is runtime/static enforcement, not theorem-proved).
- Deep causal failure diagnosis loop for long-running autonomous plans.
