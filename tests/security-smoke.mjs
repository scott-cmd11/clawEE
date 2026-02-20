import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import Database from "better-sqlite3";

import { loadChannelConnectorCatalog } from "../dist/channel-connector-catalog.js";
import { ChannelDestinationPolicy } from "../dist/channel-destination-policy.js";
import { ControlAuthz } from "../dist/control-authz.js";
import { ApprovalService } from "../dist/approval-service.js";
import { ApprovalAttestationService } from "../dist/approval-attestation.js";
import { ApprovalAttestationJobService } from "../dist/approval-attestation-job.js";
import {
  ApprovalPolicyEngine,
  loadSignedApprovalPolicyCatalog,
} from "../dist/approval-policy.js";
import { SqliteAuditLedger } from "../dist/audit-ledger.js";
import {
  CapabilityPolicyEngine,
  loadSignedCapabilityCatalog,
} from "../dist/capability-policy.js";
import { ModelRegistry } from "../dist/model-registry.js";
import { loadSignedPolicyCatalog } from "../dist/policy-catalog.js";
import { PolicyEngine } from "../dist/policy-engine.js";
import { FixedWindowRateLimiter } from "../dist/rate-limiter.js";
import { RuntimeEgressGuard } from "../dist/runtime-egress-guard.js";
import { buildTransportAgents } from "../dist/transport-security.js";
import { stableStringify } from "../dist/utils.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");

async function main() {
  const modelRegistry = new ModelRegistry(
    path.join(projectRoot, "config", "model-registry.v1.json"),
    "change_me_registry_key",
  );
  modelRegistry.init();
  const policyCatalog = loadSignedPolicyCatalog(
    path.join(projectRoot, "config", "policy-catalog.v1.json"),
    "change_me_policy_key",
  );
  const capabilityCatalog = loadSignedCapabilityCatalog(
    path.join(projectRoot, "config", "capability-catalog.v1.json"),
    "change_me_capability_key",
  );
  const approvalPolicyCatalog = loadSignedApprovalPolicyCatalog(
    path.join(projectRoot, "config", "approval-policy-catalog.v1.json"),
    "change_me_approval_policy_key",
  );
  const approvalPolicy = new ApprovalPolicyEngine();
  approvalPolicy.updateRules(approvalPolicyCatalog);
  const capabilityPolicy = new CapabilityPolicyEngine();
  capabilityPolicy.updateRules(capabilityCatalog);
  assert.ok(policyCatalog.fingerprint.length > 10);
  assert.ok(capabilityCatalog.fingerprint.length > 10);
  assert.equal(modelRegistry.evaluate("gpt-4.1-mini", "text").allowed, true);
  assert.equal(modelRegistry.evaluate("gpt-4.1-mini", "audio").allowed, false);
  assert.equal(capabilityPolicy.evaluateToolExecution(["execute_bash"]).allowed, false);
  assert.equal(capabilityPolicy.evaluateChannelAction("channel.ingest", "email").allowed, true);
  assert.equal(capabilityPolicy.evaluateChannelAction("channel.send", "email").allowed, false);
  const approvalPolicyEval = approvalPolicy.evaluate({
    policyDecision: {
      decision: "require_approval",
      reason: "test",
      riskClass: "high",
      matchedSignals: [],
    },
    toolNames: ["execute_sql"],
    channel: "email",
    action: "channel.send",
  });
  assert.equal(approvalPolicyEval.requiredApprovals >= 3, true);
  assert.equal(approvalPolicyEval.requiredRoles.includes("approver"), true);
  assert.equal(approvalPolicyEval.requiredRoles.includes("superadmin"), true);

  const policy = new PolicyEngine(policyCatalog.policyOptions);
  const requireApproval = policy.evaluate({
    path: "/v1/responses",
    method: "POST",
    body: { action: "maintenance" },
    model: "gpt-4.1-mini",
    modality: "text",
    intent: { hasToolIntent: true, toolNames: ["execute_bash"] },
  });
  assert.equal(requireApproval.decision, "require_approval");

  const blockDecision = policy.evaluate({
    path: "/v1/responses",
    method: "POST",
    body: { command: "DROP TABLE users" },
    model: "gpt-4.1-mini",
    modality: "text",
    intent: { hasToolIntent: true, toolNames: ["execute_sql"] },
  });
  assert.equal(blockDecision.decision, "block");

  const allowGuard = new RuntimeEgressGuard({
    policy: "deny",
    allowlistedHosts: [],
    revalidationIntervalMs: 1000,
    targets: [{ name: "local", url: "http://localhost:11434/v1" }],
  });
  const allowResult = await allowGuard.assertAllowed("local");
  assert.equal(allowResult.allowed, true);

  const denyGuard = new RuntimeEgressGuard({
    policy: "deny",
    allowlistedHosts: [],
    revalidationIntervalMs: 1000,
    targets: [{ name: "public", url: "https://api.openai.com/v1" }],
  });
  let denied = false;
  try {
    await denyGuard.assertAllowed("public");
  } catch {
    denied = true;
  }
  assert.equal(denied, true);

  const transport = buildTransportAgents(
    {
      targetName: "upstream_base_url",
      targetUrl: "http://localhost:11434/v1",
      enforceTls: false,
      tlsPinsSha256: "",
      caCertPath: "",
      clientCertPath: "",
      clientKeyPath: "",
    },
    {
      targetName: "internal_inference_base_url",
      targetUrl: "http://localhost:11434/v1",
      enforceTls: false,
      tlsPinsSha256: "",
      caCertPath: "",
      clientCertPath: "",
      clientKeyPath: "",
    },
  );
  assert.equal(transport.summary.length, 2);

  let tlsConfigDenied = false;
  try {
    buildTransportAgents(
      {
        targetName: "upstream_base_url",
        targetUrl: "https://internal.example/v1",
        enforceTls: true,
        tlsPinsSha256: "",
        caCertPath: "",
        clientCertPath: "",
        clientKeyPath: "",
      },
      {
        targetName: "internal_inference_base_url",
        targetUrl: "http://localhost:11434/v1",
        enforceTls: false,
        tlsPinsSha256: "",
        caCertPath: "",
        clientCertPath: "",
        clientKeyPath: "",
      },
    );
  } catch {
    tlsConfigDenied = true;
  }
  assert.equal(tlsConfigDenied, true);
  const tempConnectorPath = path.join(os.tmpdir(), `claw-ee-connector-${Date.now()}.json`);
  const connectorCanonical = {
    version: "v1",
    default_timeout_ms: 10000,
    channels: {
      slack: {
        webhook_url: "http://localhost:9001/channel/slack",
      },
    },
  };
  const connectorSigningKey = "connector-signing-key";
  const signature = crypto
    .createHmac("sha256", connectorSigningKey)
    .update(stableStringify(connectorCanonical))
    .digest("hex");
  fs.writeFileSync(
    tempConnectorPath,
    JSON.stringify({
      ...connectorCanonical,
      signature,
    }),
    "utf8",
  );
  const loadedConnector = loadChannelConnectorCatalog(tempConnectorPath, connectorSigningKey);
  assert.equal(loadedConnector.signed, true);
  assert.ok(loadedConnector.fingerprint.length > 10);

  let badConnectorDenied = false;
  try {
    loadChannelConnectorCatalog(tempConnectorPath, "wrong-signing-key");
  } catch {
    badConnectorDenied = true;
  }
  assert.equal(badConnectorDenied, true);
  fs.rmSync(tempConnectorPath, { force: true });
  const limiter = new FixedWindowRateLimiter(1, 2);
  const a = limiter.check("k");
  const b = limiter.check("k");
  const c = limiter.check("k");
  assert.equal(a.allowed, true);
  assert.equal(b.allowed, true);
  assert.equal(c.allowed, false);
  assert.ok(c.retryAfterSeconds >= 1);
  const tempControlTokensPath = path.join(os.tmpdir(), `claw-ee-control-${Date.now()}.json`);
  const observerToken = "observer-token";
  fs.writeFileSync(
    tempControlTokensPath,
    JSON.stringify(
      {
        version: "v1",
        tokens: [
          {
            principal: "observer",
            role: "observer",
            token_hash: crypto.createHash("sha256").update(observerToken).digest("hex"),
            permissions: ["system.read"],
          },
        ],
      },
      null,
      2,
    ),
    "utf8",
  );
  const authz = new ControlAuthz("legacy-token", tempControlTokensPath);
  const observerIdentity = authz.authenticate(observerToken);
  assert.ok(observerIdentity !== null);
  assert.equal(authz.can(observerIdentity, "system.read"), true);
  assert.equal(authz.can(observerIdentity, "budget.control"), false);
  const state = authz.reload();
  assert.equal(state.hasCatalog, true);
  assert.ok(state.tokenCount >= 2);
  const signedControlTokensPath = path.join(
    os.tmpdir(),
    `claw-ee-control-signed-${Date.now()}.json`,
  );
  const signingKey = "control-signing-key";
  const canonicalControl = {
    version: "v1",
    tokens: [
      {
        principal: "observer",
        role: "observer",
        token_hash: crypto.createHash("sha256").update(observerToken).digest("hex"),
        permissions: ["system.read"],
      },
    ],
  };
  const signedControlPayload = {
    ...canonicalControl,
    signature: crypto
      .createHmac("sha256", signingKey)
      .update(stableStringify(canonicalControl))
      .digest("hex"),
  };
  fs.writeFileSync(signedControlTokensPath, JSON.stringify(signedControlPayload, null, 2), "utf8");
  const signedAuthz = new ControlAuthz("legacy-token", signedControlTokensPath, signingKey);
  assert.ok(signedAuthz.authenticate(observerToken) !== null);
  let signedControlDenied = false;
  try {
    // wrong key must reject catalog integrity
    new ControlAuthz("legacy-token", signedControlTokensPath, "bad-key");
  } catch {
    signedControlDenied = true;
  }
  assert.equal(signedControlDenied, true);
  const keyringPath = path.join(os.tmpdir(), `claw-ee-control-keyring-${Date.now()}.json`);
  fs.writeFileSync(
    keyringPath,
    JSON.stringify(
      {
        version: "v1",
        active_kid: "k2",
        keys: {
          k1: "old-control-secret",
          k2: "new-control-secret",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const keyringCatalogPath = path.join(os.tmpdir(), `claw-ee-control-keyring-catalog-${Date.now()}.json`);
  const keyringCanonical = {
    version: "v1",
    tokens: [
      {
        principal: "observer",
        role: "observer",
        token_hash: crypto.createHash("sha256").update(observerToken).digest("hex"),
        permissions: ["system.read"],
      },
    ],
  };
  const keyringSig = crypto
    .createHmac("sha256", "new-control-secret")
    .update(stableStringify(keyringCanonical))
    .digest("hex");
  fs.writeFileSync(
    keyringCatalogPath,
    JSON.stringify(
      {
        ...keyringCanonical,
        signature_v2: {
          kid: "k2",
          sig: keyringSig,
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const keyringAuthz = new ControlAuthz("legacy-token", keyringCatalogPath, "", keyringPath);
  assert.ok(keyringAuthz.authenticate(observerToken) !== null);
  assert.equal(keyringAuthz.getState().signing_mode, "keyring");
  const policyKeyringPath = path.join(os.tmpdir(), `claw-ee-policy-keyring-${Date.now()}.json`);
  fs.writeFileSync(
    policyKeyringPath,
    JSON.stringify(
      {
        version: "v1",
        active_kid: "p2",
        keys: {
          p1: "old-policy-secret",
          p2: "new-policy-secret",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const policyCatalogV2Path = path.join(os.tmpdir(), `claw-ee-policy-v2-${Date.now()}.json`);
  const policyCanonical = {
    version: "v1",
    high_risk_tools: ["execute_bash"],
    critical_patterns: ["drop table"],
    high_risk_patterns: ["secret"],
  };
  const policySigV2 = crypto
    .createHmac("sha256", "new-policy-secret")
    .update(stableStringify(policyCanonical))
    .digest("hex");
  fs.writeFileSync(
    policyCatalogV2Path,
    JSON.stringify(
      {
        ...policyCanonical,
        signature_v2: {
          kid: "p2",
          sig: policySigV2,
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const policyV2 = loadSignedPolicyCatalog(policyCatalogV2Path, "", policyKeyringPath);
  assert.ok(policyV2.fingerprint.length > 10);
  const modelKeyringPath = path.join(os.tmpdir(), `claw-ee-model-keyring-${Date.now()}.json`);
  fs.writeFileSync(
    modelKeyringPath,
    JSON.stringify(
      {
        version: "v1",
        active_kid: "m2",
        keys: {
          m1: "old-model-secret",
          m2: "new-model-secret",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const modelRegistryV2Path = path.join(os.tmpdir(), `claw-ee-model-v2-${Date.now()}.json`);
  const modelEntryCanonical = {
    model_id: "internal-safe-model",
    modality: "safety",
    artifact_digest: "sha256:abc123",
    approved: true,
    valid_from: "",
    valid_to: "",
  };
  const modelSigV2 = crypto
    .createHmac("sha256", "new-model-secret")
    .update(JSON.stringify(modelEntryCanonical))
    .digest("hex");
  fs.writeFileSync(
    modelRegistryV2Path,
    JSON.stringify(
      {
        version: "v1",
        entries: [
          {
            model_id: "internal-safe-model",
            modality: "safety",
            artifact_digest: "sha256:abc123",
            approved: true,
            signature_v2: {
              kid: "m2",
              sig: modelSigV2,
            },
          },
        ],
      },
      null,
      2,
    ),
    "utf8",
  );
  const modelRegistryV2 = new ModelRegistry(modelRegistryV2Path, "", modelKeyringPath);
  modelRegistryV2.init();
  assert.equal(modelRegistryV2.evaluate("internal-safe-model", "safety").allowed, true);
  const capabilityKeyringPath = path.join(os.tmpdir(), `claw-ee-capability-keyring-${Date.now()}.json`);
  fs.writeFileSync(
    capabilityKeyringPath,
    JSON.stringify(
      {
        version: "v1",
        active_kid: "c2",
        keys: {
          c1: "old-capability-secret",
          c2: "new-capability-secret",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const capabilityCatalogV2Path = path.join(
    os.tmpdir(),
    `claw-ee-capability-v2-${Date.now()}.json`,
  );
  const capabilityCanonicalV2 = {
    version: "v1",
    defaults: {
      mode: "deny",
      allow_tools: ["safe_tool"],
      deny_tools: [],
      allow_actions: ["channel.ingest", "tool.execute"],
      deny_actions: [],
    },
    channels: {},
  };
  const capabilitySigV2 = crypto
    .createHmac("sha256", "new-capability-secret")
    .update(stableStringify(capabilityCanonicalV2))
    .digest("hex");
  fs.writeFileSync(
    capabilityCatalogV2Path,
    JSON.stringify(
      {
        ...capabilityCanonicalV2,
        signature_v2: {
          kid: "c2",
          sig: capabilitySigV2,
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const capabilityV2 = loadSignedCapabilityCatalog(capabilityCatalogV2Path, "", capabilityKeyringPath);
  const capabilityPolicyV2 = new CapabilityPolicyEngine();
  capabilityPolicyV2.updateRules(capabilityV2);
  assert.equal(capabilityPolicyV2.evaluateToolExecution(["safe_tool"]).allowed, true);
  assert.equal(capabilityPolicyV2.evaluateToolExecution(["execute_bash"]).allowed, false);
  const approvalPolicyKeyringPath = path.join(
    os.tmpdir(),
    `claw-ee-approval-policy-keyring-${Date.now()}.json`,
  );
  fs.writeFileSync(
    approvalPolicyKeyringPath,
    JSON.stringify(
      {
        version: "v1",
        active_kid: "ap2",
        keys: {
          ap1: "old-approval-policy-secret",
          ap2: "new-approval-policy-secret",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const approvalPolicyCatalogV2Path = path.join(
    os.tmpdir(),
    `claw-ee-approval-policy-v2-${Date.now()}.json`,
  );
  const approvalPolicyCanonicalV2 = {
    version: "v1",
    defaults: {
      required_approvals: 2,
      required_roles: ["approver"],
    },
    risk_class_overrides: {
      high: {
        required_approvals: 3,
        required_roles: ["approver", "superadmin"],
      },
    },
    tool_overrides: {},
    channel_action_overrides: {},
  };
  const approvalPolicySigV2 = crypto
    .createHmac("sha256", "new-approval-policy-secret")
    .update(stableStringify(approvalPolicyCanonicalV2))
    .digest("hex");
  fs.writeFileSync(
    approvalPolicyCatalogV2Path,
    JSON.stringify(
      {
        ...approvalPolicyCanonicalV2,
        signature_v2: {
          kid: "ap2",
          sig: approvalPolicySigV2,
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const approvalPolicyV2 = loadSignedApprovalPolicyCatalog(
    approvalPolicyCatalogV2Path,
    "",
    approvalPolicyKeyringPath,
  );
  const approvalPolicyEngineV2 = new ApprovalPolicyEngine();
  approvalPolicyEngineV2.updateRules(approvalPolicyV2);
  const approvalPolicyEvalV2 = approvalPolicyEngineV2.evaluate({
    policyDecision: {
      decision: "require_approval",
      reason: "test",
      riskClass: "high",
      matchedSignals: [],
    },
    toolNames: [],
    action: "tool.execute",
  });
  assert.equal(approvalPolicyEvalV2.requiredApprovals, 3);
  assert.equal(approvalPolicyEvalV2.requiredRoles.includes("superadmin"), true);
  const tempDestinationPolicyPath = path.join(
    os.tmpdir(),
    `claw-ee-destination-${Date.now()}.json`,
  );
  const destinationSigningKey = "destination-signing-key";
  const canonicalDestinationPolicy = {
    version: "v1",
    defaults: {
      mode: "allow",
      allow_patterns: ["^ops-.*$"],
      deny_patterns: ["^blocked$"],
    },
    channels: {},
  };
  const destinationSignature = crypto
    .createHmac("sha256", destinationSigningKey)
    .update(stableStringify(canonicalDestinationPolicy))
    .digest("hex");
  fs.writeFileSync(
    tempDestinationPolicyPath,
    JSON.stringify(
      {
        ...canonicalDestinationPolicy,
        signature: destinationSignature,
      },
      null,
      2,
    ),
    "utf8",
  );
  const destinationPolicy = new ChannelDestinationPolicy(
    tempDestinationPolicyPath,
    destinationSigningKey,
  );
  destinationPolicy.reload();
  assert.equal(destinationPolicy.evaluate("slack", "ops-room").allowed, true);
  assert.equal(destinationPolicy.evaluate("slack", "blocked").allowed, false);

  const tempApprovalsDbPath = path.join(os.tmpdir(), `claw-ee-approvals-${Date.now()}.db`);
  const tempApprovalExportPath = path.join(
    os.tmpdir(),
    `claw-ee-approval-attest-${Date.now()}.json`,
  );
  const approvals = new ApprovalService(tempApprovalsDbPath);
  approvals.init();
  const created = approvals.getOrCreatePending({
    requestFingerprint: "fingerprint-1",
    reason: "test-approval",
    metadata: { requested_by: "tester" },
    ttlSeconds: 1200,
  });
  approvals.approve(created.record.id, "approver");
  const quorum = approvals.getOrCreatePending({
    requestFingerprint: "fingerprint-2",
    reason: "test-approval-quorum",
    metadata: { requested_by: "tester2" },
    ttlSeconds: 1200,
    requiredApprovals: 2,
  });
  const quorumStepOne = approvals.approve(quorum.record.id, "approver-a");
  assert.equal(quorumStepOne.status, "pending");
  const quorumStepTwo = approvals.approve(quorum.record.id, "approver-b");
  assert.equal(quorumStepTwo.status, "approved");
  assert.equal(approvals.validateApproved(quorum.record.id, "fingerprint-2"), true);
  const roleGate = approvals.getOrCreatePending({
    requestFingerprint: "fingerprint-3",
    reason: "test-approval-role-gate",
    metadata: { requested_by: "tester3" },
    ttlSeconds: 1200,
    requiredApprovals: 2,
    requiredRoles: ["approver", "superadmin"],
  });
  const roleGateStepOne = approvals.approve(roleGate.record.id, "approver-x", "approver");
  assert.equal(roleGateStepOne.status, "pending");
  const roleGateStepTwo = approvals.approve(roleGate.record.id, "approver-y", "approver");
  assert.equal(roleGateStepTwo.status, "pending");
  const roleGateStepThree = approvals.approve(roleGate.record.id, "security-admin", "superadmin");
  assert.equal(roleGateStepThree.status, "approved");
  assert.equal(approvals.validateApproved(roleGate.record.id, "fingerprint-3"), true);
  assert.equal(approvals.consumeApproved(roleGate.record.id, "fingerprint-3"), true);
  assert.equal(approvals.consumeApproved(roleGate.record.id, "fingerprint-3"), false);
  const attestationService = new ApprovalAttestationService(
    approvals,
    tempApprovalExportPath,
    "attestation-signing-key",
  );
  const attestation = attestationService.generate(100);
  assert.equal(attestation.count >= 1, true);
  assert.equal(typeof attestation.final_hash, "string");
  assert.equal(typeof attestation.signature, "string");
  const exportedAttestation = attestationService.exportToFile({ limit: 100 });
  assert.equal(fs.existsSync(exportedAttestation.output_path), true);
  const verifySnapshot = attestationService.verifySnapshotFile(exportedAttestation.output_path);
  assert.equal(verifySnapshot.valid, true);
  const attestationKeyringPath = path.join(
    os.tmpdir(),
    `claw-ee-attestation-keyring-${Date.now()}.json`,
  );
  fs.writeFileSync(
    attestationKeyringPath,
    JSON.stringify(
      {
        version: "v1",
        active_kid: "a2",
        keys: {
          a1: "old-attestation-secret",
          a2: "new-attestation-secret",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  const attestationServiceKeyring = new ApprovalAttestationService(
    approvals,
    tempApprovalExportPath,
    "",
    attestationKeyringPath,
  );
  const keyringPayload = attestationServiceKeyring.generate(100);
  assert.equal(keyringPayload.signature_kid, "a2");
  const keyringVerify = attestationServiceKeyring.verifyPayload(keyringPayload);
  assert.equal(keyringVerify.valid, true);
  const sealed = attestationService.exportSealedSnapshot({
    snapshotPath: tempApprovalExportPath,
    chainPath: `${tempApprovalExportPath}.chain.jsonl`,
    limit: 100,
  });
  const verifyChainSingle = attestationService.verifySealedChain(sealed.chain_path, {
    verifySnapshots: true,
  });
  assert.equal(verifyChainSingle.valid, true);
  const tempAuditDbPath = path.join(os.tmpdir(), `claw-ee-audit-${Date.now()}.db`);
  const tempSnapshotDir = path.join(os.tmpdir(), `claw-ee-attn-snap-${Date.now()}`);
  const tempChainPath = path.join(os.tmpdir(), `claw-ee-attn-chain-${Date.now()}.jsonl`);
  const tempLedger = new SqliteAuditLedger(tempAuditDbPath);
  tempLedger.init();
  const job = new ApprovalAttestationJobService(
    {
      enabled: true,
      intervalSeconds: 600,
      snapshotDirectory: tempSnapshotDir,
      chainPath: tempChainPath,
      maxRecordsPerExport: 100,
      incremental: true,
      retentionMaxFiles: 1,
    },
    attestationService,
    tempLedger,
  );
  await job.runNow();
  await job.runNow();
  const snapshots = fs.readdirSync(tempSnapshotDir);
  assert.equal(snapshots.length <= 1, true);
  assert.equal(fs.existsSync(tempChainPath), true);
  const chainLines = fs
    .readFileSync(tempChainPath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  assert.equal(chainLines.length >= 2, true);
  const first = chainLines[0];
  const second = chainLines[1];
  assert.equal(second.previous_snapshot_hash, first.current_snapshot_hash);
  const auditIntegrity = tempLedger.verifyIntegrity();
  assert.equal(auditIntegrity.valid, true);
  tempLedger.close();

  const tamperedDb = new Database(tempAuditDbPath);
  tamperedDb
    .prepare("UPDATE audit_logs SET current_hash = ? WHERE id = (SELECT MIN(id) FROM audit_logs)")
    .run("0".repeat(64));
  tamperedDb.close();
  const tamperedLedger = new SqliteAuditLedger(tempAuditDbPath);
  tamperedLedger.init();
  const tamperedIntegrity = tamperedLedger.verifyIntegrity();
  assert.equal(tamperedIntegrity.valid, false);
  assert.equal(typeof tamperedIntegrity.reason, "string");
  tamperedLedger.close();
  approvals.close();

  fs.rmSync(tempControlTokensPath, { force: true });
  fs.rmSync(signedControlTokensPath, { force: true });
  fs.rmSync(keyringPath, { force: true });
  fs.rmSync(keyringCatalogPath, { force: true });
  fs.rmSync(policyKeyringPath, { force: true });
  fs.rmSync(policyCatalogV2Path, { force: true });
  fs.rmSync(modelKeyringPath, { force: true });
  fs.rmSync(modelRegistryV2Path, { force: true });
  fs.rmSync(capabilityKeyringPath, { force: true });
  fs.rmSync(capabilityCatalogV2Path, { force: true });
  fs.rmSync(approvalPolicyKeyringPath, { force: true });
  fs.rmSync(approvalPolicyCatalogV2Path, { force: true });
  fs.rmSync(tempDestinationPolicyPath, { force: true });
  fs.rmSync(tempApprovalsDbPath, { force: true });
  fs.rmSync(tempApprovalExportPath, { force: true });
  fs.rmSync(attestationKeyringPath, { force: true });
  fs.rmSync(tempAuditDbPath, { force: true });
  fs.rmSync(tempSnapshotDir, { recursive: true, force: true });
  fs.rmSync(tempChainPath, { force: true });
  fs.rmSync(`${tempApprovalExportPath}.chain.jsonl`, { force: true });

  console.log("security-smoke: ok", {
    host: os.hostname(),
    model_registry_fingerprint: modelRegistry.getFingerprint(),
    policy_catalog_fingerprint: policyCatalog.fingerprint,
  });
}

main().catch((error) => {
  console.error("security-smoke: failed", error);
  process.exit(1);
});
