# Claw-EE

Claw-EE is a security and governance sidecar for OpenClaw.  
It sits between OpenClaw and model/tool providers to enforce enterprise controls before actions execute.

## Why Claw-EE Exists

OpenClaw can execute meaningful work. Enterprise deployment needs more:

- enforceable policy gates (not just prompt-level intent)
- replay protection and abuse controls for inbound channels
- auditable, tamper-evident decision history
- bounded compute spend and fail-closed behavior options

Claw-EE provides those controls without requiring OpenClaw core changes.

## What You Get

| Concern | Claw-EE control | Evidence surface |
| --- | --- | --- |
| Prompt injection / dangerous tool use | Policy engine + risk gate + approval workflow | `/_clawee/control/status`, audit ledger |
| Replay / connector abuse | HMAC validation + nonce/event replay store (`sqlite`, `redis`, `postgres`) | `/_clawee/control/metrics`, replay store state |
| Cost runaway / agentic drift | Economic circuit breaker (`HOURLY_USD_CAP`, `DAILY_USD_CAP`) | budget state in status/metrics |
| Proactive initiative execution | Initiative Engine (task queue, retries, interrupt/start/pause/cancel) | `/_clawee/control/initiatives*`, initiative DB + audit ledger |
| Model/provider drift | Signed model registry and policy catalogs | catalog fingerprints in status/conformance |
| Governance and accountability | Hash-chained audit + signed attestations + conformance exports | attestation/conformance endpoints |

## How It Fits OpenClaw

```text
OpenClaw -> Claw-EE gateway -> policy/risk/approval/budget checks -> upstream model/tool endpoint
```

OpenClaw runtime mapping: `docs/openclaw-alignment.md`  
API contract: `openapi/claw-ee.openapi.yaml`

## Synthetic Worker Scope

Claw-EE is designed as the enterprise control-plane around OpenClaw.  
OpenClaw is the execution brain; Claw-EE provides policy, safety, cost control, and initiative orchestration.

Current implementation status by modality stack:

- Text + code ("brain"): implemented via gateway control, policy, approvals, and channel operations.
- Action + tool use ("hands"): implemented as guarded execution path (risk gate, capability policy, approval, audit).
- Vision + screen parsing ("eyes"): partial. Structured vision ingestion exists (`/_clawee/control/modality/ingest`), full VDI computer-use loop is roadmap.
- Audio + meeting presence ("ears/voice"): partial. Structured audio ingestion exists (`/_clawee/control/modality/ingest`), live meeting bot/WebRTC/TTS is roadmap.
- Proactive work queue ("initiative"): implemented. Initiatives and tasks can be created, started, paused, interrupted, and audited.

## Quickstart (10 minutes)

1. Create env file.

```powershell
Copy-Item .env.example .env
```

2. Set minimum required values in `.env`:

- `UPSTREAM_BASE_URL`
- `INTERNAL_INFERENCE_BASE_URL`
- `INTERNAL_INFERENCE_API_KEY`
- `CONTROL_API_TOKEN`

Note: catalog signing keys are required by config and have defaults in `.env.example`. Replace defaults for real deployments.

3. Install and run.

```powershell
npm install
npm run build
npm run start
```

4. Run smoke checks.

```powershell
npm run smoke:security
npm run repo:check
```

5. Optional: enable proactive initiative execution in `.env`:

- `INITIATIVE_ENGINE_ENABLED=true`
- `INITIATIVE_POLL_SECONDS=15`

Windows fallback if `npm.ps1` is blocked:

```powershell
npm.cmd run smoke:security
```

## Strict Replay Verification

Claw-EE supports strict replay smoke mode for CI/release:

- `REPLAY_SMOKE_STRICT=true` causes replay smoke tests to fail if backend URLs are missing.
- `smoke:security:strict` enables this mode.

CI workflows (`.github/workflows/security-smoke.yml`, `.github/workflows/release.yml`) run strict smoke checks with Redis and Postgres service containers.

## Deployment Modes

1. Local evaluation
- Single-node replay store (`REPLAY_STORE_MODE=sqlite`)
- Fastest setup, not cross-node dedupe

2. Multi-node enterprise
- Shared replay store (`REPLAY_STORE_MODE=redis` or `postgres`)
- Use `CLAWEE_NODE_ID` and `CLAWEE_CLUSTER_ID` for cluster telemetry

3. Air-gapped / controlled egress
- `OUTBOUND_INTERNET_POLICY=deny`
- allowlist only required hosts via `ALLOWED_OUTBOUND_HOSTS`
- optional TLS pinning and mTLS for upstream/inference transport

## Control API Overview

Auth: `Authorization: Bearer <token>` or `x-control-token`.

Core groups:

- System: `/_clawee/control/status`, `/_clawee/control/metrics`, suspend/resume
- Policy/catalog reload: model, policy, approval-policy, capability-policy, control-tokens, destination-policy
- Approvals: pending list, approve/deny, attestation export/verify
- Audit/security: recent audit, audit verify, attestation export/verify, conformance export/verify, invariants
- Channel operations: inbound/outbound visibility, send, delivery, retry, connector reload
- Modality ingest: validated `text|vision|audio|action` payload intake
- Initiative engine: create/list/start/pause/cancel/interrupt initiatives and inspect task/event history

Full endpoint details: `openapi/claw-ee.openapi.yaml`

### Initiative API quick example

```powershell
$token = "your-control-token"
$headers = @{ Authorization = "Bearer $token" }

Invoke-RestMethod -Method Post -Uri "http://localhost:8080/_clawee/control/initiatives" -Headers $headers -ContentType "application/json" -Body '{
  "source":"jira",
  "external_ref":"PROJ-123",
  "title":"Prepare status update",
  "priority":"normal",
  "risk_class":"low",
  "tasks":[
    {
      "task_type":"channel.send",
      "payload":{
        "channel":"slack",
        "destination":"team-updates",
        "text":"Status update prepared by Claw-EE initiative engine."
      }
    }
  ]
}'
```

## Configuration Reference

Use `.env.example` as the full source of truth. High-impact groups:

### Routing and execution

- `UPSTREAM_BASE_URL`
- `INTERNAL_INFERENCE_BASE_URL`
- `INTERNAL_INFERENCE_API_KEY`
- `ENFORCEMENT_MODE`
- `RISK_EVALUATOR_FAIL_MODE`

### Replay and cluster identity

- `REPLAY_STORE_MODE` (`sqlite|redis|postgres`)
- `REPLAY_REDIS_URL`, `REPLAY_REDIS_PREFIX`
- `REPLAY_POSTGRES_URL`, `REPLAY_POSTGRES_SCHEMA`, `REPLAY_POSTGRES_TABLE_PREFIX`
- `REPLAY_POSTGRES_CONNECT_TIMEOUT_MS`, `REPLAY_POSTGRES_SSL_MODE`
- `CLAWEE_NODE_ID`, `CLAWEE_CLUSTER_ID`

### Initiative engine (proactive queue)

- `INITIATIVE_ENGINE_ENABLED`
- `INITIATIVE_POLL_SECONDS`
- `INITIATIVE_MAX_TASK_RETRIES`
- `INITIATIVE_DB_PATH`

### Budget and guardrails

- `HOURLY_USD_CAP`, `DAILY_USD_CAP`
- `MAX_REQUEST_INPUT_TOKENS`, `MAX_REQUEST_OUTPUT_TOKENS`
- `CHANNEL_MAX_OUTBOUND_CHARS`
- `CHANNEL_INGRESS_MAX_TEXT_CHARS`

### Governance and approvals

- `APPROVAL_REQUIRED_COUNT`, `APPROVAL_MAX_USES`, `APPROVAL_TTL_SECONDS`
- `APPROVAL_POLICY_CATALOG_PATH`
- `APPROVAL_ATTESTATION_*`, `AUDIT_ATTESTATION_*`
- `SECURITY_CONFORMANCE_*`

### Signed policy surfaces

- `POLICY_CATALOG_*`
- `MODEL_REGISTRY_*`
- `CAPABILITY_CATALOG_*`
- `CONTROL_TOKENS_*`
- `CHANNEL_DESTINATION_POLICY_*`
- `CHANNEL_CONNECTOR_SIGNING_KEY`

## Operational Behavior (Key Defaults)

- `ENFORCEMENT_MODE=block` blocks low-confidence risky actions.
- `RISK_EVALUATOR_FAIL_MODE=block` fails closed on evaluator outage.
- `AUDIT_STARTUP_VERIFY_MODE=block` blocks startup on broken audit chain.
- `SECURITY_INVARIANTS_ENFORCEMENT=block` blocks on invariant bypass risk.
- Oversized modality/channel payloads return `413`.
- Replay collisions return `409`.
- Approval-required actions return `428` until quorum is satisfied.
- Rate-limited routes return `429` with `retry-after`.

## Security Tooling

Useful commands:

```powershell
node scripts/security-tools.mjs hash-token "my-secret-token"
node scripts/security-tools.mjs verify-audit-chain "$env:USERPROFILE\\.openclaw\\enterprise_audit.db"
node scripts/security-tools.mjs sign-control-catalog .\config\control-tokens.v1.example.json "signing-key"
node scripts/security-tools.mjs sign-capability-catalog .\config\capability-catalog.v1.json "signing-key"
node scripts/security-tools.mjs sign-approval-policy-catalog .\config\approval-policy-catalog.v1.json "signing-key"
```

## Repository Scripts

- `npm run build`
- `npm run dev`
- `npm run start`
- `npm run smoke:security`
- `npm run smoke:security:strict`
- `npm run repo:check`
- `npm run security:invariants`
- `npm run release:notes -- <tag>`

## Who This Is For

- Platform, security, and infra teams evaluating autonomous agent deployment risk
- Teams using OpenClaw that need enforceable controls and auditable operations

## Not A Goal

- Replacing OpenClaw runtime behavior or agent UX
- Claiming formal theorem-proved end-to-end correctness

Current roadmap/non-goals: `docs/openclaw-alignment.md`
