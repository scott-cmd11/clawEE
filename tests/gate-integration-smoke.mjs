import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ApprovalService } from "../dist/approval-service.js";
import { ApprovalAttestationService } from "../dist/approval-attestation.js";
import { AuditAttestationService } from "../dist/audit-attestation.js";
import {
  ApprovalPolicyEngine,
  loadSignedApprovalPolicyCatalog,
} from "../dist/approval-policy.js";
import { SqliteAuditLedger } from "../dist/audit-ledger.js";
import { AlertNotifier } from "../dist/alert-notifier.js";
import { BudgetController } from "../dist/budget-controller.js";
import {
  CapabilityPolicyEngine,
  loadSignedCapabilityCatalog,
} from "../dist/capability-policy.js";
import { ChannelDeliveryService } from "../dist/channel-delivery-service.js";
import { ChannelDestinationPolicy } from "../dist/channel-destination-policy.js";
import { ChannelHub } from "../dist/channel-hub.js";
import { ControlAuthz } from "../dist/control-authz.js";
import { InitiativeEngine } from "../dist/initiative-engine.js";
import { InitiativeStore } from "../dist/initiative-store.js";
import { InteractionStore } from "../dist/interaction-store.js";
import { ModelRegistry } from "../dist/model-registry.js";
import { ModalityHub } from "../dist/modality-hub.js";
import { loadSignedPolicyCatalog } from "../dist/policy-catalog.js";
import { PolicyEngine } from "../dist/policy-engine.js";
import { RuntimeEgressGuard } from "../dist/runtime-egress-guard.js";
import { SecurityConformanceService } from "../dist/security-conformance.js";
import { SecurityInvariantRegistry } from "../dist/security-invariants.js";
import { startUncertaintyGate } from "../dist/uncertainty-gate.js";
import { sha256Hex, stableStringify } from "../dist/utils.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  };
}

function createServer(handler) {
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks).toString("utf8");
      const result = await handler(req, body);
      res.writeHead(result.statusCode, result.headers);
      res.end(result.body);
    } catch (error) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
        }),
      );
    }
  });
  return server;
}

async function listen(server, port) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(undefined));
  });
}

async function closeServer(server) {
  await new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}

async function getFreePort() {
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (!addr || typeof addr === "string") {
        srv.close(() => reject(new Error("Failed to allocate free port.")));
        return;
      }
      const port = addr.port;
      srv.close(() => resolve(port));
    });
  });
}

async function waitFor(predicate, timeoutMs = 7000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 125));
  }
  throw new Error(`Timeout waiting for condition after ${timeoutMs}ms`);
}

function channelSignature(secret, payload, timestamp) {
  const value = `${timestamp}.${payload}`;
  return `sha256=${crypto.createHmac("sha256", secret).update(value).digest("hex")}`;
}

function intakeSignature(secret, payload, timestamp) {
  const value = `${timestamp}.${payload}`;
  return `sha256=${crypto.createHmac("sha256", secret).update(value).digest("hex")}`;
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claw-ee-smoke-"));
  const controlToken = "control-secret";
  const readonlyToken = "readonly-secret";
  const initiativeReaderToken = "initiative-reader-secret";
  const approverToken = "approver-secret";
  const approverTokenTwo = "approver-two-secret";
  const ingestToken = "ingest-secret";
  const hmacSecret = "channel-hmac-secret";
  const initiativeIntakeToken = "initiative-intake-secret";
  const initiativeIntakeHmacSecret = "initiative-intake-hmac-secret";
  const openclawIntakeToken = "openclaw-intake-secret";
  const openclawIntakeHmacSecret = "openclaw-intake-hmac-secret";
  const nowSec = Math.floor(Date.now() / 1000);

  const upstreamPort = await getFreePort();
  const connectorPort = await getFreePort();
  const gatePort = await getFreePort();

  const upstreamServer = createServer(async (_req, _body) => {
    return json(200, {
      id: "resp_test",
      model: "gpt-4.1-mini",
      output_text: "ok",
      usage: {
        input_tokens: 10,
        output_tokens: 12,
      },
    });
  });

  const delivered = [];
  const connectorServer = createServer(async (req, body) => {
    delivered.push({
      path: req.url || "",
      body: JSON.parse(body || "{}"),
      signature: req.headers["x-clawee-signature"] || "",
    });
    return json(200, { ok: true });
  });

  await listen(upstreamServer, upstreamPort);
  await listen(connectorServer, connectorPort);

  const connectorConfigPath = path.join(tmpDir, "channel-connectors.v1.json");
  const destinationPolicyPath = path.join(tmpDir, "channel-destination-policy.v1.json");
  const controlTokensPath = path.join(tmpDir, "control-tokens.v1.json");
  fs.writeFileSync(
    connectorConfigPath,
    JSON.stringify(
      {
        default_timeout_ms: 4000,
        channels: {
          slack: {
            webhook_url: `http://127.0.0.1:${connectorPort}/channel/slack`,
            hmac_secret: "outbound-secret",
          },
          webhook: {
            webhook_url: "https://api.openai.com/v1/blocked-by-airgap",
          },
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  fs.writeFileSync(
    destinationPolicyPath,
    JSON.stringify(
      {
        version: "v1",
        defaults: {
          mode: "allow",
          allow_patterns: [],
          deny_patterns: ["^blocked-destination$"],
        },
        channels: {},
      },
      null,
      2,
    ),
    "utf8",
  );
  fs.writeFileSync(
    controlTokensPath,
    JSON.stringify(
      {
        version: "v1",
        tokens: [
          {
            principal: "smoke-readonly",
            role: "observer",
            token_hash: crypto.createHash("sha256").update(readonlyToken).digest("hex"),
            permissions: ["system.read"],
          },
          {
            principal: "smoke-initiative-reader",
            role: "observer",
            token_hash: crypto.createHash("sha256").update(initiativeReaderToken).digest("hex"),
            permissions: ["initiative.read"],
          },
          {
            principal: "smoke-approver",
            role: "approver",
            token_hash: crypto.createHash("sha256").update(approverToken).digest("hex"),
            permissions: ["approvals.read", "approvals.write"],
          },
          {
            principal: "smoke-approver-two",
            role: "approver",
            token_hash: crypto.createHash("sha256").update(approverTokenTwo).digest("hex"),
            permissions: ["approvals.read", "approvals.write"],
          },
        ],
      },
      null,
      2,
    ),
    "utf8",
  );

  const ledger = new SqliteAuditLedger(path.join(tmpDir, "audit.db"));
  ledger.init();
  const budgetController = new BudgetController(
    { hourlyUsdCap: 15, dailyUsdCap: 150 },
    path.join(projectRoot, "config", "pricing.v1.json"),
    path.join(tmpDir, "budget.db"),
  );
  budgetController.init();
  const approvalService = new ApprovalService(path.join(tmpDir, "approvals.db"));
  approvalService.init();
  const approvalAttestationService = new ApprovalAttestationService(
    approvalService,
    path.join(tmpDir, "approval-attestation.json"),
    "",
  );
  const auditAttestationService = new AuditAttestationService(
    ledger,
    path.join(tmpDir, "audit-attestation.json"),
    "",
  );
  const invariantRegistry = new SecurityInvariantRegistry();
  const policyCatalog = loadSignedPolicyCatalog(
    path.join(projectRoot, "config", "policy-catalog.v1.json"),
    "change_me_policy_key",
  );
  const policyEngine = new PolicyEngine(policyCatalog.policyOptions);
  const approvalPolicyCatalog = loadSignedApprovalPolicyCatalog(
    path.join(projectRoot, "config", "approval-policy-catalog.v1.json"),
    "change_me_approval_policy_key",
  );
  const approvalPolicy = new ApprovalPolicyEngine();
  approvalPolicy.updateRules(approvalPolicyCatalog);
  const capabilityCatalog = loadSignedCapabilityCatalog(
    path.join(projectRoot, "config", "capability-catalog.v1.json"),
    "change_me_capability_key",
  );
  const capabilityPolicy = new CapabilityPolicyEngine();
  capabilityPolicy.updateRules(capabilityCatalog);
  const modelRegistry = new ModelRegistry(
    path.join(projectRoot, "config", "model-registry.v1.json"),
    "change_me_registry_key",
  );
  modelRegistry.init();
  const conformanceService = new SecurityConformanceService({
    defaultExportPath: path.join(tmpDir, "security-conformance.json"),
    codeFingerprint: sha256Hex(
      stableStringify({
        policy: policyCatalog.fingerprint,
        model_registry: modelRegistry.getFingerprint(),
      }),
    ),
    runtimeContext: {
      environment: "test",
      mode: "smoke",
    },
    signingKey: "",
  });
  const runtimeEgressGuard = new RuntimeEgressGuard({
    policy: "deny",
    allowlistedHosts: [],
    revalidationIntervalMs: 1000,
    targets: [
      { name: "upstream_base_url", url: `http://127.0.0.1:${upstreamPort}/v1` },
      { name: "internal_inference_base_url", url: `http://127.0.0.1:${upstreamPort}/v1` },
    ],
  });
  const modalityHub = new ModalityHub(100);
  const channelHub = new ChannelHub(100);
  const interactionStore = new InteractionStore(path.join(tmpDir, "interactions.db"));
  interactionStore.init();
  const initiativeStore = new InitiativeStore(path.join(tmpDir, "initiatives.db"));
  initiativeStore.init();
  const initiativeEngine = new InitiativeEngine(
    {
      enabled: true,
      pollSeconds: 60,
      maxTaskRetries: 2,
      nodeId: "smoke-node-1",
    },
    initiativeStore,
    channelHub,
    interactionStore,
    ledger,
  );
  const replayNonceSeen = new Map();
  const replayEventSeen = new Map();
  const replayStore = {
    mode() {
      return "sqlite";
    },
    async warmup() {
      return;
    },
    async registerNonce(hash, _ttl) {
      if (replayNonceSeen.has(hash)) {
        return false;
      }
      replayNonceSeen.set(hash, true);
      return true;
    },
    async registerEventKey(hash, _ttl) {
      if (replayEventSeen.has(hash)) {
        return false;
      }
      replayEventSeen.set(hash, true);
      return true;
    },
    getState() {
      return { mode: "sqlite-test" };
    },
    async close() {
      return;
    },
  };
  const alertNotifier = new AlertNotifier({ webhookUrl: "", minIntervalMs: 1000 });
  const destinationPolicy = new ChannelDestinationPolicy(destinationPolicyPath, "");
  const destinationPolicyState = destinationPolicy.reload();
  const channelDelivery = new ChannelDeliveryService(
    {
      pollSeconds: 1,
      batchSize: 10,
      maxAttempts: 3,
      retryBaseSeconds: 1,
      connectorConfigPath,
      connectorSigningKey: "",
    },
    interactionStore,
    ledger,
    alertNotifier,
    runtimeEgressGuard,
    destinationPolicy,
  );
  channelDelivery.start();
  const controlAuthz = new ControlAuthz(controlToken, controlTokensPath);

  let riskEvaluatorShouldFail = false;
  const riskEvaluator = {
    async evaluateRisk() {
      if (riskEvaluatorShouldFail) {
        throw new Error("simulated risk evaluator failure");
      }
      return { confidence_score: 0.99, reason: "ok" };
    },
  };

  let gate = null;
  try {
    gate = await startUncertaintyGate(
      {
        port: gatePort,
        upstreamBaseUrl: `http://127.0.0.1:${upstreamPort}`,
        warnThreshold: 0.85,
        evaluatorModel: "gpt-4.1-mini",
        riskEvaluatorFailMode: "block",
        auditStartupVerifyMode: "block",
        securityInvariantsEnforcement: "block",
        nodeId: "smoke-node-1",
        clusterId: "smoke-cluster-1",
        configFingerprints: {
          policy_catalog: policyCatalog.fingerprint,
          model_registry: modelRegistry.getFingerprint(),
          capability_catalog: capabilityPolicy.getState().fingerprint,
          approval_policy: approvalPolicy.getState().fingerprint,
          channel_destination_policy: destinationPolicyState.fingerprint,
          channel_connector_catalog: channelDelivery.getConnectorState().fingerprint,
        },
        modelRegistryFingerprint: modelRegistry.getFingerprint(),
        enforcementMode: "block",
        controlAuthz,
        channelIngestToken: ingestToken,
        channelIngressHmacSecret: hmacSecret,
        channelIngressMaxSkewSeconds: 120,
        channelIngressEventTtlSeconds: 86400,
        initiativeIntakeEnabled: true,
        initiativeIntakeToken,
        initiativeIntakeHmacSecret,
        initiativeIntakeMaxSkewSeconds: 120,
        initiativeIntakeEventTtlSeconds: 86400,
        openclawIntakeEnabled: true,
        openclawIntakeToken,
        openclawIntakeHmacSecret,
        openclawIntakeMaxSkewSeconds: 120,
        openclawIntakeEventTtlSeconds: 86400,
        modalityTextMaxPayloadBytes: 512,
        modalityVisionMaxPayloadBytes: 1024 * 1024,
        modalityAudioMaxPayloadBytes: 1024 * 1024,
        modalityActionMaxPayloadBytes: 2048,
        modalityTextMaxChars: 300,
        channelIngressMaxTextChars: 200,
        channelMaxOutboundChars: 2000,
        maxRequestInputTokens: 50000,
        maxRequestOutputTokens: 1024,
        approvalTtlSeconds: 600,
        approvalRequiredCount: 2,
        approvalMaxUses: 1,
      },
      ledger,
      riskEvaluator,
      budgetController,
      modelRegistry,
      runtimeEgressGuard,
      approvalPolicy,
      capabilityPolicy,
      policyEngine,
      approvalService,
      alertNotifier,
      modalityHub,
      channelHub,
      interactionStore,
      replayStore,
      channelDelivery,
      destinationPolicy,
      approvalAttestationService,
      auditAttestationService,
      invariantRegistry,
      conformanceService,
      {
        reloadApprovalPolicyCatalog: () => {
          const reloaded = loadSignedApprovalPolicyCatalog(
            path.join(projectRoot, "config", "approval-policy-catalog.v1.json"),
            "change_me_approval_policy_key",
          );
          approvalPolicy.updateRules(reloaded);
          return { fingerprint: reloaded.fingerprint };
        },
        reloadCapabilityCatalog: () => {
          const reloaded = loadSignedCapabilityCatalog(
            path.join(projectRoot, "config", "capability-catalog.v1.json"),
            "change_me_capability_key",
          );
          capabilityPolicy.updateRules(reloaded);
          return { fingerprint: reloaded.fingerprint };
        },
      },
      initiativeEngine,
    );

    const ingressBody = JSON.stringify({
      source: "eng-team",
      sender: "alice",
      text: "Deploy status?",
      metadata: { room: "ops" },
    });

    const noSigRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/channel/slack/inbound`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-channel-token": ingestToken,
      },
      body: ingressBody,
    });
    assert.equal(noSigRes.status, 401);

    const staleTs = String(nowSec - 10_000);
    const staleSig = channelSignature(hmacSecret, ingressBody, staleTs);
    const staleRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/channel/slack/inbound`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-channel-token": ingestToken,
        "x-channel-timestamp": staleTs,
        "x-channel-signature": staleSig,
      },
      body: ingressBody,
    });
    assert.equal(staleRes.status, 401);

    const liveTs = String(Math.floor(Date.now() / 1000));
    const liveSig = channelSignature(hmacSecret, ingressBody, liveTs);
    const validRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/channel/slack/inbound`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-channel-token": ingestToken,
        "x-channel-timestamp": liveTs,
        "x-channel-signature": liveSig,
        "x-channel-event-id": "evt-1",
      },
      body: ingressBody,
    });
    assert.equal(validRes.status, 200);
    const replayRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/channel/slack/inbound`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-channel-token": ingestToken,
        "x-channel-timestamp": liveTs,
        "x-channel-signature": liveSig,
        "x-channel-event-id": "evt-1",
      },
      body: ingressBody,
    });
    assert.equal(replayRes.status, 409);
    const liveTs2 = String(Math.floor(Date.now() / 1000) + 1);
    const liveSig2 = channelSignature(hmacSecret, ingressBody, liveTs2);
    const eventReplayRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/channel/slack/inbound`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-channel-token": ingestToken,
        "x-channel-timestamp": liveTs2,
        "x-channel-signature": liveSig2,
        "x-channel-event-id": "evt-1",
      },
      body: ingressBody,
    });
    assert.equal(eventReplayRes.status, 409);

    const modalityInvalidSchemaRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/modality/ingest`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          session_id: "sess-1",
          modality: "text",
          source: "slack:eng-team",
          payload: {
            sender: "alice",
          },
        }),
      },
    );
    assert.equal(modalityInvalidSchemaRes.status, 400);

    const modalityOversizeRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/modality/ingest`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          session_id: "sess-2",
          modality: "text",
          source: "slack:eng-team",
          payload: {
            text: "x".repeat(250),
            metadata: {
              note: "z".repeat(400),
            },
          },
        }),
      },
    );
    assert.equal(modalityOversizeRes.status, 413);

    const modalityValidRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/modality/ingest`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          session_id: "sess-3",
          modality: "text",
          source: "slack:eng-team",
          payload: {
            text: "Build finished successfully.",
            sender: "alice",
            metadata: { lane: "release" },
          },
        }),
      },
    );
    assert.equal(modalityValidRes.status, 200);

    const oversizeIngressBody = JSON.stringify({
      source: "eng-team",
      sender: "alice",
      text: "y".repeat(220),
      metadata: { room: "ops" },
    });
    const oversizeIngressTs = String(Math.floor(Date.now() / 1000) + 2);
    const oversizeIngressSig = channelSignature(hmacSecret, oversizeIngressBody, oversizeIngressTs);
    const oversizeIngressRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/channel/slack/inbound`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-channel-token": ingestToken,
          "x-channel-timestamp": oversizeIngressTs,
          "x-channel-signature": oversizeIngressSig,
          "x-channel-event-id": "evt-oversize-1",
        },
        body: oversizeIngressBody,
      },
    );
    assert.equal(oversizeIngressRes.status, 413);

    const readonlySuspend = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/suspend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${readonlyToken}`,
      },
      body: JSON.stringify({ reason: "should-be-forbidden" }),
    });
    assert.equal(readonlySuspend.status, 403);

    const capabilityBlockedToolRes = await fetch(`http://127.0.0.1:${gatePort}/v1/responses`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4.1-mini",
        input: "run maintenance command",
        tools: [{ name: "execute_bash" }],
      }),
    });
    assert.equal(capabilityBlockedToolRes.status, 403);
    riskEvaluatorShouldFail = true;
    const riskFailClosedRes = await fetch(`http://127.0.0.1:${gatePort}/v1/responses`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4.1-mini",
        input: "status check",
        tools: [{ name: "safe_tool" }],
      }),
    });
    assert.equal(riskFailClosedRes.status, 503);
    riskEvaluatorShouldFail = false;
    const tokenBudgetBlockedRes = await fetch(`http://127.0.0.1:${gatePort}/v1/responses`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4.1-mini",
        input: "generate a large response",
        max_output_tokens: 20000,
      }),
    });
    assert.equal(tokenBudgetBlockedRes.status, 413);

    const riskyPayload = {
      channel: "slack",
      destination: "ops-room",
      text: "Need secret rotation update",
      metadata: { source: "smoke" },
    };
    const riskyRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/channel/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${controlToken}`,
      },
      body: JSON.stringify(riskyPayload),
    });
    assert.equal(riskyRes.status, 428);
    const riskyJson = await riskyRes.json();
    assert.equal(typeof riskyJson.approval_id, "string");
    assert.equal(riskyJson.required_approvals, 2);

    const approveRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/approvals/${riskyJson.approval_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({ actor: "security-smoke" }),
      },
    );
    assert.equal(approveRes.status, 409);

    const approveRes2 = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/approvals/${riskyJson.approval_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${approverToken}`,
        },
      },
    );
    assert.equal(approveRes2.status, 202);
    const approvePending = await approveRes2.json();
    assert.equal(approvePending.pending, true);
    assert.equal(approvePending.remaining_approvals, 1);
    const approveRes3 = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/approvals/${riskyJson.approval_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${approverTokenTwo}`,
        },
      },
    );
    assert.equal(approveRes3.status, 200);

    const queueRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/channel/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${controlToken}`,
        "x-clawee-approval-id": riskyJson.approval_id,
      },
      body: JSON.stringify(riskyPayload),
    });
    assert.equal(queueRes.status, 200);
    const replayApprovalUseRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/channel/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${controlToken}`,
        "x-clawee-approval-id": riskyJson.approval_id,
      },
      body: JSON.stringify(riskyPayload),
    });
    assert.equal(replayApprovalUseRes.status, 428);
    const blockedDestinationRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/channel/send`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          channel: "slack",
          destination: "blocked-destination",
          text: "should be blocked by destination policy",
        }),
      },
    );
    assert.equal(blockedDestinationRes.status, 403);
    const oversizedChannelRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/channel/send`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          channel: "slack",
          destination: "ops-room",
          text: "x".repeat(5000),
        }),
      },
    );
    assert.equal(oversizedChannelRes.status, 413);
    const capabilityBlockedChannelSend = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/channel/send`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          channel: "email",
          destination: "exec-briefing",
          text: "capability policy should deny outbound email sends",
        }),
      },
    );
    assert.equal(capabilityBlockedChannelSend.status, 403);
    const reloadDenied = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/control-tokens`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${approverToken}`,
        },
      },
    );
    assert.equal(reloadDenied.status, 403);
    const reloadAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/control-tokens`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(reloadAllowed.status, 200);
    const capabilityReloadDenied = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/capability-policy`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${approverToken}`,
        },
      },
    );
    assert.equal(capabilityReloadDenied.status, 403);
    const capabilityReloadAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/capability-policy`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(capabilityReloadAllowed.status, 200);
    const approvalPolicyReloadDenied = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/approval-policy`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${approverToken}`,
        },
      },
    );
    assert.equal(approvalPolicyReloadDenied.status, 403);
    const approvalPolicyReloadAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/approval-policy`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(approvalPolicyReloadAllowed.status, 200);
    const initiativeListDeniedReadonly = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives`,
      {
        headers: {
          authorization: `Bearer ${readonlyToken}`,
        },
      },
    );
    assert.equal(initiativeListDeniedReadonly.status, 403);
    const initiativeListDeniedApprover = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives`,
      {
        headers: {
          authorization: `Bearer ${approverToken}`,
        },
      },
    );
    assert.equal(initiativeListDeniedApprover.status, 403);
    const initiativeListReader = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/initiatives`, {
      headers: {
        authorization: `Bearer ${initiativeReaderToken}`,
      },
    });
    assert.equal(initiativeListReader.status, 200);
    const initiativeCreateDenied = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${initiativeReaderToken}`,
        },
        body: JSON.stringify({
          source: "smoke",
          title: "Denied write",
          tasks: [{ task_type: "noop" }],
        }),
      },
    );
    assert.equal(initiativeCreateDenied.status, 403);
    const initiativeCreateAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          source: "smoke",
          external_ref: "SMOKE-INIT-1",
          title: "Smoke initiative",
          tasks: [{ task_type: "noop" }],
        }),
      },
    );
    assert.equal(initiativeCreateAllowed.status, 201);
    const initiativeCreateJson = await initiativeCreateAllowed.json();
    assert.equal(initiativeCreateJson.ok, true);
    assert.equal(initiativeCreateJson.created, true);
    const initiativeId = initiativeCreateJson.initiative.id;
    assert.ok(typeof initiativeId === "string" && initiativeId.length > 0);
    const initiativeTasksReader = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives/${initiativeId}/tasks`,
      {
        headers: {
          authorization: `Bearer ${initiativeReaderToken}`,
        },
      },
    );
    assert.equal(initiativeTasksReader.status, 200);
    const initiativeTasksJson = await initiativeTasksReader.json();
    assert.equal(Array.isArray(initiativeTasksJson.tasks), true);
    assert.equal(initiativeTasksJson.tasks.length, 1);
    const initiativeStartDenied = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives/${initiativeId}/start`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${initiativeReaderToken}`,
        },
      },
    );
    assert.equal(initiativeStartDenied.status, 403);
    const initiativeStartAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives/${initiativeId}/start`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(initiativeStartAllowed.status, 200);
    const initiativeEventsReader = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/initiatives/${initiativeId}/events?limit=50`,
      {
        headers: {
          authorization: `Bearer ${initiativeReaderToken}`,
        },
      },
    );
    assert.equal(initiativeEventsReader.status, 200);
    const initiativeEventsJson = await initiativeEventsReader.json();
    assert.equal(Array.isArray(initiativeEventsJson.events), true);
    assert.equal(initiativeEventsJson.events.length >= 1, true);
    const jiraWebhookPayload = JSON.stringify({
      webhookEvent: "jira:issue_created",
      issue: {
        key: "ENG-88",
        fields: {
          summary: "Fix failed migration in staging",
          description: "Migration fails on step 3.",
          priority: { name: "Highest" },
          status: { name: "To Do" },
          project: { key: "ENG" },
        },
      },
      user: {
        displayName: "Ops Bot",
      },
    });
    const intakeUnauthorized = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/jira/webhook`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: jiraWebhookPayload,
      },
    );
    assert.equal(intakeUnauthorized.status, 401);
    const intakeTimestamp = String(Math.floor(Date.now() / 1000));
    const intakeGoodSignature = intakeSignature(
      initiativeIntakeHmacSecret,
      jiraWebhookPayload,
      intakeTimestamp,
    );
    const intakeBadSignatureRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/jira/webhook`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-intake-token": initiativeIntakeToken,
          "x-intake-timestamp": intakeTimestamp,
          "x-intake-signature": "sha256=bad",
        },
        body: jiraWebhookPayload,
      },
    );
    assert.equal(intakeBadSignatureRes.status, 401);
    const intakeCreatedRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/jira/webhook`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-intake-token": initiativeIntakeToken,
          "x-intake-event-id": "jira-event-1",
          "x-intake-timestamp": intakeTimestamp,
          "x-intake-signature": intakeGoodSignature,
        },
        body: jiraWebhookPayload,
      },
    );
    assert.equal(intakeCreatedRes.status, 201);
    const intakeCreatedJson = await intakeCreatedRes.json();
    assert.equal(intakeCreatedJson.ok, true);
    assert.equal(intakeCreatedJson.created, true);
    assert.equal(intakeCreatedJson.provider, "jira");
    assert.equal(typeof intakeCreatedJson.template?.template_id, "string");
    assert.equal(intakeCreatedJson.template?.template_id, "jira.issue.notify-triage.v1");
    assert.equal(Array.isArray(intakeCreatedJson.tasks), true);
    assert.equal(intakeCreatedJson.tasks.length, 2);
    assert.equal(intakeCreatedJson.tasks[0].task_type, "channel.send");
    assert.equal(intakeCreatedJson.tasks[1].task_type, "channel.send");
    const intakeReplayRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/jira/webhook`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-intake-token": initiativeIntakeToken,
          "x-intake-event-id": "jira-event-1",
          "x-intake-timestamp": intakeTimestamp,
          "x-intake-signature": intakeGoodSignature,
        },
        body: jiraWebhookPayload,
      },
    );
    assert.equal(intakeReplayRes.status, 409);
    const intakeDedupeTimestamp = String(Math.floor(Date.now() / 1000) + 1);
    const intakeDedupeSignature = intakeSignature(
      initiativeIntakeHmacSecret,
      jiraWebhookPayload,
      intakeDedupeTimestamp,
    );
    const intakeDedupeRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/jira/webhook`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-intake-token": initiativeIntakeToken,
          "x-intake-event-id": "jira-event-2",
          "x-intake-timestamp": intakeDedupeTimestamp,
          "x-intake-signature": intakeDedupeSignature,
        },
        body: jiraWebhookPayload,
      },
    );
    assert.equal(intakeDedupeRes.status, 200);
    const intakeDedupeJson = await intakeDedupeRes.json();
    assert.equal(intakeDedupeJson.created, false);
    assert.equal(intakeDedupeJson.template?.template_id, "jira.issue.notify-triage.v1");

    const openclawWorkItemPayload = JSON.stringify({
      event_id: "ocw-evt-1",
      agent_id: "openclaw-dev-1",
      work_type: "task_assigned",
      source_ref: "OC-321",
      title: "Prepare release notes",
      description: "Compile and post release notes draft.",
      channel: "slack",
      destination: "openclaw-ops",
      metadata: { origin: "openclaw-daemon" },
    });
    const openclawUnauthorizedRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/openclaw/work-item`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: openclawWorkItemPayload,
      },
    );
    assert.equal(openclawUnauthorizedRes.status, 401);
    const openclawTimestamp = String(Math.floor(Date.now() / 1000));
    const openclawSignature = intakeSignature(
      openclawIntakeHmacSecret,
      openclawWorkItemPayload,
      openclawTimestamp,
    );
    const openclawBadSignatureRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/openclaw/work-item`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openclaw-token": openclawIntakeToken,
          "x-openclaw-timestamp": openclawTimestamp,
          "x-openclaw-signature": "sha256=bad",
        },
        body: openclawWorkItemPayload,
      },
    );
    assert.equal(openclawBadSignatureRes.status, 401);
    const openclawCreatedRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/openclaw/work-item`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openclaw-token": openclawIntakeToken,
          "x-openclaw-event-id": "ocw-evt-1",
          "x-openclaw-timestamp": openclawTimestamp,
          "x-openclaw-signature": openclawSignature,
        },
        body: openclawWorkItemPayload,
      },
    );
    assert.equal(openclawCreatedRes.status, 201);
    const openclawCreatedJson = await openclawCreatedRes.json();
    assert.equal(openclawCreatedJson.ok, true);
    assert.equal(openclawCreatedJson.provider, "openclaw");
    assert.equal(openclawCreatedJson.created, true);
    assert.equal(openclawCreatedJson.normalization?.template_id, "openclaw.task.notify-execute.v1");
    assert.equal(Array.isArray(openclawCreatedJson.tasks), true);
    assert.equal(openclawCreatedJson.tasks.length, 2);
    const openclawReplayRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/openclaw/work-item`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openclaw-token": openclawIntakeToken,
          "x-openclaw-event-id": "ocw-evt-1",
          "x-openclaw-timestamp": openclawTimestamp,
          "x-openclaw-signature": openclawSignature,
        },
        body: openclawWorkItemPayload,
      },
    );
    assert.equal(openclawReplayRes.status, 409);
    const openclawDedupeTimestamp = String(Math.floor(Date.now() / 1000) + 1);
    const openclawDedupeSignature = intakeSignature(
      openclawIntakeHmacSecret,
      openclawWorkItemPayload,
      openclawDedupeTimestamp,
    );
    const openclawDedupeRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/openclaw/work-item`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openclaw-token": openclawIntakeToken,
          "x-openclaw-event-id": "ocw-evt-2",
          "x-openclaw-timestamp": openclawDedupeTimestamp,
          "x-openclaw-signature": openclawDedupeSignature,
        },
        body: openclawWorkItemPayload,
      },
    );
    assert.equal(openclawDedupeRes.status, 200);
    const openclawDedupeJson = await openclawDedupeRes.json();
    assert.equal(openclawDedupeJson.created, false);
    assert.equal(openclawDedupeJson.normalization?.template_id, "openclaw.task.notify-execute.v1");
    const openclawHeartbeatPayload = JSON.stringify({
      event_id: "och-evt-1",
      agent_id: "openclaw-dev-1",
      status: "online",
      queue_depth: 3,
      active_task_id: "task-1",
      timestamp: new Date().toISOString(),
      metadata: { host: "oc-node-1" },
    });
    const openclawHeartbeatTs = String(Math.floor(Date.now() / 1000) + 2);
    const openclawHeartbeatSig = intakeSignature(
      openclawIntakeHmacSecret,
      openclawHeartbeatPayload,
      openclawHeartbeatTs,
    );
    const openclawHeartbeatRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/intake/openclaw/heartbeat`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openclaw-token": openclawIntakeToken,
          "x-openclaw-event-id": "och-evt-1",
          "x-openclaw-timestamp": openclawHeartbeatTs,
          "x-openclaw-signature": openclawHeartbeatSig,
        },
        body: openclawHeartbeatPayload,
      },
    );
    assert.equal(openclawHeartbeatRes.status, 200);
    const openclawHeartbeatJson = await openclawHeartbeatRes.json();
    assert.equal(openclawHeartbeatJson.ok, true);
    assert.equal(openclawHeartbeatJson.provider, "openclaw");
    assert.equal(openclawHeartbeatJson.heartbeat?.agent_id, "openclaw-dev-1");
    const metricsRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/metrics`, {
      headers: {
        authorization: `Bearer ${controlToken}`,
      },
    });
    assert.equal(metricsRes.status, 200);
    const metricsJson = await metricsRes.json();
    assert.equal(metricsJson.openclaw_adapter?.enabled, true);
    assert.equal(Number(metricsJson.openclaw_adapter?.work_items_ingested_total) >= 1, true);
    assert.equal(Number(metricsJson.openclaw_adapter?.work_items_deduped_total) >= 1, true);
    assert.equal(typeof metricsJson.openclaw_adapter?.last_heartbeat_at, "string");

    await waitFor(() => delivered.length > 0, 7000);
    assert.equal(delivered[0].path, "/channel/slack");
    assert.equal(delivered[0].body.text, "Need secret rotation update");
    assert.equal(typeof delivered[0].signature, "string");
    assert.ok(String(delivered[0].signature).startsWith("sha256="));

    const deliveryRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/channel/delivery?limit=20`,
      {
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(deliveryRes.status, 200);
    const deliveryJson = await deliveryRes.json();
    assert.ok(Array.isArray(deliveryJson.deliveries));
    assert.ok(deliveryJson.deliveries.some((item) => item.status === "sent"));

    const blockedQueueRes = await fetch(`http://127.0.0.1:${gatePort}/_clawee/control/channel/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${controlToken}`,
      },
      body: JSON.stringify({
        channel: "webhook",
        destination: "external-test",
        text: "egress policy should deny this connector",
      }),
    });
    assert.equal(blockedQueueRes.status, 200);

    await waitFor(async () => {
      const response = await fetch(
        `http://127.0.0.1:${gatePort}/_clawee/control/channel/delivery?limit=50`,
        {
          headers: {
            authorization: `Bearer ${controlToken}`,
          },
        },
      );
      if (response.status !== 200) {
        return false;
      }
      const payload = await response.json();
      return payload.deliveries.some(
        (item) => item.channel === "webhook" && item.status === "failed",
      );
    }, 7000);

    const attestationRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/approvals/attestation?limit=100`,
      {
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(attestationRes.status, 200);
    const attestation = await attestationRes.json();
    assert.ok(typeof attestation.final_hash === "string");

    const attestationExportRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/approvals/attestation/export`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({ limit: 100 }),
      },
    );
    assert.equal(attestationExportRes.status, 200);
    const exported = await attestationExportRes.json();
    assert.equal(exported.ok, true);
    assert.equal(fs.existsSync(exported.snapshot_path), true);
    assert.equal(fs.existsSync(exported.chain_path), true);

    const verifyRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/approvals/attestation/verify`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          snapshot_path: exported.snapshot_path,
          chain_path: exported.chain_path,
        }),
      },
    );
    assert.equal(verifyRes.status, 200);
    const verifyJson = await verifyRes.json();
    assert.equal(verifyJson.ok, true);

    const auditVerifyRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/audit/verify`,
      {
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(auditVerifyRes.status, 200);
    const auditVerifyJson = await auditVerifyRes.json();
    assert.equal(auditVerifyJson.ok, true);
    assert.equal(auditVerifyJson.report.valid, true);
    assert.ok(Number(auditVerifyJson.report.checked_rows) > 0);

    const auditAttestationRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/audit/attestation?limit=500`,
      {
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(auditAttestationRes.status, 200);
    const auditAttestationJson = await auditAttestationRes.json();
    assert.ok(typeof auditAttestationJson.final_hash === "string");
    assert.ok(Number(auditAttestationJson.count) > 0);

    const auditSnapshotPath = path.join(tmpDir, "audit-attestation-snapshot.json");
    const auditChainPath = path.join(tmpDir, "audit-attestation-chain.jsonl");
    const auditExportRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/audit/attestation/export`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          snapshot_path: auditSnapshotPath,
          chain_path: auditChainPath,
          limit: 500,
        }),
      },
    );
    assert.equal(auditExportRes.status, 200);
    const auditExportJson = await auditExportRes.json();
    assert.equal(auditExportJson.ok, true);
    assert.equal(fs.existsSync(auditSnapshotPath), true);
    assert.equal(fs.existsSync(auditChainPath), true);

    const auditVerifySnapshotRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/audit/attestation/verify`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          snapshot_path: auditSnapshotPath,
          chain_path: auditChainPath,
        }),
      },
    );
    assert.equal(auditVerifySnapshotRes.status, 200);
    const auditVerifySnapshotJson = await auditVerifySnapshotRes.json();
    assert.equal(auditVerifySnapshotJson.ok, true);

    const invariantsRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/security/invariants`,
      {
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(invariantsRes.status, 200);
    const invariantsJson = await invariantsRes.json();
    assert.equal(typeof invariantsJson.definition_hash, "string");
    assert.equal(invariantsJson.enforcement_mode, "block");
    assert.ok(Array.isArray(invariantsJson.invariants));

    const conformanceReportPath = path.join(tmpDir, "security-conformance-report.json");
    const conformanceChainPath = path.join(tmpDir, "security-conformance-chain.jsonl");
    const conformanceExportRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/security/conformance/export`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          report_path: conformanceReportPath,
          chain_path: conformanceChainPath,
        }),
      },
    );
    assert.equal(conformanceExportRes.status, 200);
    const conformanceExportJson = await conformanceExportRes.json();
    assert.equal(conformanceExportJson.ok, true);
    assert.equal(fs.existsSync(conformanceReportPath), true);
    assert.equal(fs.existsSync(conformanceChainPath), true);

    const conformanceVerifyRes = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/security/conformance/verify`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${controlToken}`,
        },
        body: JSON.stringify({
          report_path: conformanceReportPath,
          chain_path: conformanceChainPath,
        }),
      },
    );
    assert.equal(conformanceVerifyRes.status, 200);
    const conformanceVerifyJson = await conformanceVerifyRes.json();
    assert.equal(conformanceVerifyJson.ok, true);

    const signingReloadDenied = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/approval-attestation-signing`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${approverToken}`,
        },
      },
    );
    assert.equal(signingReloadDenied.status, 403);
    const signingReloadAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/approval-attestation-signing`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(signingReloadAllowed.status, 200);
    const auditSigningReloadAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/audit-attestation-signing`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(auditSigningReloadAllowed.status, 200);
    const conformanceSigningReloadAllowed = await fetch(
      `http://127.0.0.1:${gatePort}/_clawee/control/reload/security-conformance-signing`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${controlToken}`,
        },
      },
    );
    assert.equal(conformanceSigningReloadAllowed.status, 200);
  } finally {
    if (gate) {
      await gate.close();
    }
    channelDelivery.stop();
    await initiativeEngine.stop();
    initiativeStore.close();
    interactionStore.close();
    approvalService.close();
    budgetController.close();
    ledger.close();
    await closeServer(upstreamServer);
    await closeServer(connectorServer);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log("gate-integration-smoke: ok", {
    gatePort,
    upstreamPort,
    connectorPort,
  });
}

main().catch((error) => {
  console.error("gate-integration-smoke: failed", error);
  process.exit(1);
});
