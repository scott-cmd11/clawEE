# Claw-EE

Claw-EE is an air-gapped enterprise sidecar for OpenClaw that adds:

- tamper-evident audit logging (hash-chained SQLite records)
- uncertainty gating for tool-intent requests
- economic circuit breaker with hard hourly/daily USD caps
- control plane endpoints for suspend/resume status
- dynamic affective overrides to `SOUL.md`

OpenClaw integration map: `docs/openclaw-alignment.md`

## 1. Configure environment

```powershell
cd C:\Users\scott\clawguard
Copy-Item .env.example .env
```

Required values:

- `UPSTREAM_BASE_URL` (where proxied requests are forwarded)
- `INTERNAL_INFERENCE_BASE_URL` (internal risk-evaluator endpoint)
- `INTERNAL_INFERENCE_API_KEY`
- `CONTROL_API_TOKEN`
- `MODEL_REGISTRY_SIGNING_KEY`
- `POLICY_CATALOG_SIGNING_KEY`
- `CAPABILITY_CATALOG_SIGNING_KEY`

Optional:

- `CHANNEL_INGEST_TOKEN` (defaults to `CONTROL_API_TOKEN` if unset)
- `CHANNEL_INGRESS_HMAC_SECRET` (enables HMAC validation for channel ingress)
- `CHANNEL_INGRESS_MAX_SKEW_SECONDS` (max allowed timestamp skew for signed ingress requests)
- `CHANNEL_INGRESS_EVENT_TTL_SECONDS` (event-id dedupe TTL for `x-channel-event-id` / body `event_id`)
- `CHANNEL_INGRESS_MAX_TEXT_CHARS` (hard cap for inbound channel `text` length)
- `CONTROL_RATE_LIMIT_WINDOW_SECONDS` / `CONTROL_RATE_LIMIT_MAX_REQUESTS`
- `CHANNEL_INGRESS_RATE_LIMIT_WINDOW_SECONDS` / `CHANNEL_INGRESS_RATE_LIMIT_MAX_REQUESTS`
- `REPLAY_STORE_MODE` (`sqlite` default, `redis` for cluster-shared replay defense)
- `REPLAY_REDIS_URL` / `REPLAY_REDIS_PREFIX` (required when `REPLAY_STORE_MODE=redis`)
- `AUDIT_STARTUP_VERIFY_MODE` (`block` default; `warn` or `off` for relaxed startup integrity handling)
- `MODALITY_TEXT_MAX_PAYLOAD_BYTES` / `MODALITY_VISION_MAX_PAYLOAD_BYTES`
- `MODALITY_AUDIO_MAX_PAYLOAD_BYTES` / `MODALITY_ACTION_MAX_PAYLOAD_BYTES`
- `MODALITY_TEXT_MAX_CHARS` (schema cap for text modality payloads)
- `MAX_REQUEST_INPUT_TOKENS` / `MAX_REQUEST_OUTPUT_TOKENS` (hard per-request token ceilings)
- `RISK_EVALUATOR_FAIL_MODE` (`block` recommended for fail-closed behavior)
- `CONTROL_TOKENS_PATH` (optional RBAC token catalog; legacy `CONTROL_API_TOKEN` remains superadmin)
- `CONTROL_TOKENS_SIGNING_KEY` (optional; enforces signed RBAC token catalog integrity)
- `CONTROL_TOKENS_SIGNING_KEYRING_PATH` (optional keyring for signing-key rotation, supports `signature_v2`)
- `CAPABILITY_CATALOG_PATH` / `CAPABILITY_CATALOG_SIGNING_KEY`
- `CAPABILITY_CATALOG_SIGNING_KEYRING_PATH` (optional keyring for capability-catalog signing rotation)
- `CHANNEL_CONNECTOR_SIGNING_KEY` (optional HMAC key to require signed connector catalogs)
- `CHANNEL_DESTINATION_POLICY_PATH` / `CHANNEL_DESTINATION_POLICY_SIGNING_KEY`
- `CHANNEL_MAX_OUTBOUND_CHARS` (hard cap for outbound channel message size)
- `APPROVAL_ATTESTATION_DEFAULT_PATH` / `APPROVAL_ATTESTATION_SIGNING_KEY`
- `APPROVAL_ATTESTATION_SIGNING_KEYRING_PATH` (optional keyring for attestation signing rotation)
- `AUDIT_ATTESTATION_DEFAULT_PATH` / `AUDIT_ATTESTATION_SIGNING_KEY`
- `AUDIT_ATTESTATION_SIGNING_KEYRING_PATH` (optional keyring for audit-attestation signing rotation)
- `APPROVAL_ATTESTATION_PERIODIC_ENABLED`
- `APPROVAL_ATTESTATION_PERIODIC_INTERVAL_SECONDS`
- `APPROVAL_ATTESTATION_SNAPSHOT_DIRECTORY` / `APPROVAL_ATTESTATION_CHAIN_PATH`
- `APPROVAL_ATTESTATION_MAX_RECORDS_PER_EXPORT` / `APPROVAL_ATTESTATION_INCREMENTAL`
- `APPROVAL_ATTESTATION_RETENTION_MAX_FILES`
- `APPROVAL_REQUIRED_COUNT` (default `2`; number of distinct approvers required for high-risk actions)
- `APPROVAL_MAX_USES` (default `1`; replay-resistant approval token use limit)
- `APPROVAL_POLICY_CATALOG_PATH` / `APPROVAL_POLICY_CATALOG_SIGNING_KEY`
- `APPROVAL_POLICY_CATALOG_SIGNING_KEYRING_PATH` (optional keyring for approval-policy signing rotation)

## 2. Install and run

```powershell
npm install
npm run build
npm run start
```

If PowerShell blocks `npm.ps1`, use:

```powershell
npm.cmd install
npm.cmd run build
npm.cmd run start
```

Security smoke checks:

```powershell
npm.cmd run smoke:security
npm.cmd run repo:check
npm.cmd run release:notes -- v0.1.0
```

Containerized run:

```powershell
docker compose up --build -d
docker compose logs -f claw-ee
```

If using Redis replay mode:

```powershell
npm.cmd install redis
```

Security tooling:

```powershell
node scripts/security-tools.mjs hash-token "my-secret-token"
node scripts/security-tools.mjs sign-control-catalog .\config\control-tokens.v1.example.json "signing-key"
node scripts/security-tools.mjs sign-control-catalog-keyring .\config\control-tokens.v1.example.json .\config\control-tokens-signing-keyring.v1.example.json
node scripts/security-tools.mjs sign-connector-catalog .\config\channel-connectors.v1.json "signing-key"
node scripts/security-tools.mjs sign-destination-policy .\config\channel-destination-policy.v1.json "signing-key"
node scripts/security-tools.mjs sign-capability-catalog .\config\capability-catalog.v1.json "signing-key"
node scripts/security-tools.mjs sign-capability-catalog-keyring .\config\capability-catalog.v1.json .\config\capability-catalog-signing-keyring.v1.example.json
node scripts/security-tools.mjs sign-approval-policy-catalog .\config\approval-policy-catalog.v1.json "signing-key"
node scripts/security-tools.mjs sign-approval-policy-catalog-keyring .\config\approval-policy-catalog.v1.json .\config\approval-policy-catalog-signing-keyring.v1.example.json
node scripts/security-tools.mjs verify-attestation-snapshot .\approval_attestation.json "signing-key"
node scripts/security-tools.mjs verify-attestation-chain .\approval_attestation_chain.jsonl "signing-key"
node scripts/security-tools.mjs verify-attestation-snapshot-keyring .\approval_attestation.json .\config\approval-attestation-signing-keyring.v1.example.json
node scripts/security-tools.mjs verify-attestation-chain-keyring .\approval_attestation_chain.jsonl .\config\approval-attestation-signing-keyring.v1.example.json
node scripts/security-tools.mjs verify-audit-chain "$env:USERPROFILE\\.openclaw\\enterprise_audit.db"
```

A GitHub Actions workflow (`.github/workflows/security-smoke.yml`) runs the same checks on push/PR.

## 3. Wire OpenClaw

Point OpenClaw base URL to:

```text
http://localhost:8080
```

OpenAPI spec:

- `openapi/claw-ee.openapi.yaml`

## 4. Control API

Control endpoints are protected by bearer token (`Authorization: Bearer <token>`) or `x-control-token`.
By default, `CONTROL_API_TOKEN` has full access. If `CONTROL_TOKENS_PATH` is configured, scoped tokens are also accepted.

- `GET /_clawee/control/status`
- `POST /_clawee/control/suspend`
- `POST /_clawee/control/resume`
- `GET /_clawee/control/approvals/pending`
- `POST /_clawee/control/approvals/:id/approve`
- `POST /_clawee/control/approvals/:id/deny`
- `GET /_clawee/control/audit/recent?limit=100`
- `GET /_clawee/control/audit/verify`
- `GET /_clawee/control/audit/attestation?limit=1000&since=<iso8601>`
- `POST /_clawee/control/audit/attestation/export`
- `POST /_clawee/control/audit/attestation/verify`
- `POST /_clawee/control/modality/ingest`
- `GET /_clawee/control/modality/recent?limit=100`
- `GET /_clawee/control/channel/inbound?limit=100`
- `GET /_clawee/control/channel/outbound?limit=100`
- `GET /_clawee/control/channel/delivery?limit=100`
- `POST /_clawee/control/channel/send`
- `POST /_clawee/control/channel/delivery/:id/retry`
- `POST /_clawee/control/channel/reload-connectors`
- `GET /_clawee/control/metrics`
- `POST /_clawee/control/reload/policies`
- `POST /_clawee/control/reload/approval-policy`
- `POST /_clawee/control/reload/capability-policy`
- `POST /_clawee/control/reload/model-registry`
- `POST /_clawee/control/reload/control-tokens`
- `POST /_clawee/control/reload/channel-destination-policy`
- `GET /_clawee/control/approvals/attestation?limit=1000&since=<iso8601>`
- `POST /_clawee/control/approvals/attestation/export`
- `POST /_clawee/control/approvals/attestation/verify`
- `POST /_clawee/control/reload/approval-attestation-signing`
- `POST /_clawee/control/reload/audit-attestation-signing`

Channel ingress endpoint (for corporate connectors):

- `POST /_clawee/channel/:channel/inbound` (`:channel` = `slack|teams|discord|email|webhook`)
- If `CHANNEL_INGRESS_HMAC_SECRET` is set, include:
  - `x-channel-timestamp: <unix-seconds-or-ms>` (required)
  - `x-channel-signature: sha256=<hmac(secret, timestamp + "." + raw_body)>`

## Behavior Notes

- `ENFORCEMENT_MODE=block` blocks low-confidence risky tool actions.
- `RISK_EVALUATOR_FAIL_MODE=block` fails closed if the secondary risk evaluator is unavailable.
- `AUDIT_STARTUP_VERIFY_MODE=block` fails startup if audit hash-chain integrity is broken.
- Modality ingest enforces strict per-modality schemas (`text|vision|audio|action`).
- Modality and channel-ingress payload size limits return `413` when exceeded.
- Budget caps are enforced via `HOURLY_USD_CAP` and `DAILY_USD_CAP`.
- Per-request token ceilings are enforced before forwarding and return `413` when exceeded.
- Budget breach auto-suspends inference forwarding until manual resume.
- `OUTBOUND_INTERNET_POLICY=deny` enforces air-gap startup checks for configured outbound endpoints.
- `ALLOWED_OUTBOUND_HOSTS` can explicitly allow non-private hosts (comma-separated) when required.
- Startup writes air-gap attestation to `AIRGAP_ATTESTATION_PATH` (default: `~/.openclaw/airgap_attestation.json`).
- `RUNTIME_EGRESS_REVALIDATION_MS` controls DNS/IP re-validation cadence for upstream and internal inference endpoints during runtime.
- Channel outbound delivery webhooks are also checked against runtime egress policy before each send.
- Model execution is gated by signed entries in `MODEL_REGISTRY_PATH`.
- Requests using unapproved model/modality combinations are blocked with 403.
- High-risk actions are policy-gated and can return `428 Approval Required`.
- High-risk outbound channel messages are also policy-gated and require approval before queueing.
- Outbound channel messages over `CHANNEL_MAX_OUTBOUND_CHARS` are blocked with `413`.
- Approval quorum is configurable via `APPROVAL_REQUIRED_COUNT`; approvals require distinct actors.
- Approval tokens are single-use by default (`APPROVAL_MAX_USES=1`) and are consumed on execution.
- Approval policy can enforce stricter quorum/roles by risk class, tool, and channel action.
- `POST /_clawee/control/approvals/:id/approve` returns `202` when partially approved and `200` when quorum is reached.
- Capability policy can hard-deny specific tool executions and channel actions before policy/risk evaluation.
- Approval/deny actions bind to authenticated control principal (request body actor is ignored).
- Self-approval is blocked when requester identity is known (separation-of-duties).
- Channel ingress signatures are replay-protected; duplicate signed payloads within skew window are rejected with `409`.
- Channel ingress event IDs are replay-protected; duplicate `x-channel-event-id` / `event_id` values are rejected with `409`.
- For multi-node deployments, use `REPLAY_STORE_MODE=redis` so replay dedupe is shared across nodes.
- Redis replay mode is validated at startup (ping) and fails fast on bad config/connectivity.
- Control and channel ingress endpoints are rate-limited and return `429` with `retry-after`.
- Status/metrics include active control-authz catalog state and connector catalog fingerprint/signing state.
- Status/metrics include attestation signing mode and active key id when keyring signing is used.
- Submit `x-clawee-approval-id: <approved_id>` on retry after manual approval.
- Optional alert webhook can receive critical events (`ALERT_WEBHOOK_URL`).
- Policy rules are loaded from signed catalog (`POLICY_CATALOG_PATH`).
- Approval rules can be loaded from signed catalog (`APPROVAL_POLICY_CATALOG_PATH`).
- Capability rules are loaded from signed catalog (`CAPABILITY_CATALOG_PATH`).
- Optional transport hardening supports TLS pinning and mTLS for upstream/inference endpoints.
- Heartbeat scheduler runs continuously and logs due tasks from `HEARTBEAT_TASKS_PATH`.
- Outbound channel connector definitions are loaded from `CHANNEL_CONNECTOR_CONFIG_PATH`.
- Connector entries may include `hmac_secret` to sign outbound webhook payloads with `x-clawee-signature`.
- If `CHANNEL_CONNECTOR_SIGNING_KEY` is set, connector catalog must include valid `signature` and tampered catalogs are rejected.
- Outbound destinations are enforced by channel destination policy from `CHANNEL_DESTINATION_POLICY_PATH`.
- Destination policy can run default-allow or default-deny modes per channel with allow/deny regex patterns.
- Example RBAC token catalog: `config/control-tokens.v1.example.json`
- If `CONTROL_TOKENS_SIGNING_KEY` is set, token catalog must include valid `signature`.
- For key rotation, use `CONTROL_TOKENS_SIGNING_KEYRING_PATH` and `signature_v2 { kid, sig }`.
- Example control-token keyring: `config/control-tokens-signing-keyring.v1.example.json`
- Example capability-catalog keyring: `config/capability-catalog-signing-keyring.v1.example.json`
- Example approval-policy keyring: `config/approval-policy-catalog-signing-keyring.v1.example.json`
- Approval attestation exports produce hash-chained records and optional HMAC signature.
- Audit attestation exports produce hash-chained records and optional HMAC signature.
- Example attestation keyring: `config/approval-attestation-signing-keyring.v1.example.json`
- `POST /_clawee/control/approvals/attestation/export` writes sealed snapshot + append-only chain (`snapshot_path`/`chain_path` optional in body).
- Optional periodic attestation job can auto-export sealed snapshots on interval.
- `APPROVAL_ATTESTATION_RETENTION_MAX_FILES>0` prunes old snapshot files while preserving append-only chain.
- Audit ledger path: `~/.openclaw/enterprise_audit.db`
- Budget ledger path: `~/.openclaw/enterprise_budget.db`
- Approval DB path: `~/.openclaw/enterprise_approvals.db`
- Interaction DB path: `~/.openclaw/enterprise_interactions.db`

## Smoke Test

1. Start Claw-EE.
2. Send a model request through `http://localhost:8080`.
3. Check control status endpoint for hourly/daily budget counters.
4. Lower `HOURLY_USD_CAP` temporarily and confirm auto-suspend behavior.
