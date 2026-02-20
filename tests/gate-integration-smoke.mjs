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
import { InteractionStore } from "../dist/interaction-store.js";
import { ModelRegistry } from "../dist/model-registry.js";
import { ModalityHub } from "../dist/modality-hub.js";
import { loadSignedPolicyCatalog } from "../dist/policy-catalog.js";
import { PolicyEngine } from "../dist/policy-engine.js";
import { RuntimeEgressGuard } from "../dist/runtime-egress-guard.js";
import { startUncertaintyGate } from "../dist/uncertainty-gate.js";

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

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claw-ee-smoke-"));
  const controlToken = "control-secret";
  const readonlyToken = "readonly-secret";
  const approverToken = "approver-secret";
  const approverTokenTwo = "approver-two-secret";
  const ingestToken = "ingest-secret";
  const hmacSecret = "channel-hmac-secret";
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
  destinationPolicy.reload();
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
        modelRegistryFingerprint: modelRegistry.getFingerprint(),
        enforcementMode: "block",
        controlAuthz,
        channelIngestToken: ingestToken,
        channelIngressHmacSecret: hmacSecret,
        channelIngressMaxSkewSeconds: 120,
        channelIngressEventTtlSeconds: 86400,
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
  } finally {
    if (gate) {
      await gate.close();
    }
    channelDelivery.stop();
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
