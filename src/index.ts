import path from "node:path";
import { ApprovalService } from "./approval-service";
import { ApprovalAttestationService } from "./approval-attestation";
import { ApprovalAttestationJobService } from "./approval-attestation-job";
import {
  ApprovalPolicyEngine,
  loadSignedApprovalPolicyCatalog,
} from "./approval-policy";
import { SqliteAuditLedger } from "./audit-ledger";
import { AffectiveMemoryService } from "./affective-memory";
import { AirgapPolicyError, enforceAndAttestAirgapPolicy } from "./airgap-policy";
import { AlertNotifier } from "./alert-notifier";
import { BudgetController } from "./budget-controller";
import {
  CapabilityPolicyEngine,
  loadSignedCapabilityCatalog,
} from "./capability-policy";
import { ChannelHub } from "./channel-hub";
import { ChannelDeliveryService } from "./channel-delivery-service";
import { ChannelDestinationPolicy } from "./channel-destination-policy";
import { loadConfig } from "./config";
import { ControlAuthz } from "./control-authz";
import { HeartbeatService } from "./heartbeat-service";
import { InternalGatewayRiskEvaluator } from "./inference-provider";
import { InteractionStore } from "./interaction-store";
import { ModelRegistry } from "./model-registry";
import { ModalityHub } from "./modality-hub";
import { loadSignedPolicyCatalog } from "./policy-catalog";
import { PolicyEngine } from "./policy-engine";
import { createReplayStore } from "./replay-store";
import { RuntimeEgressGuard } from "./runtime-egress-guard";
import { buildTransportAgents } from "./transport-security";
import { startUncertaintyGate } from "./uncertainty-gate";

function printBanner(port: number, upstreamBaseUrl: string): void {
  const banner = `
    _____ _                 _____ _____
   / ____| |               |  ___|  ___|
  | |    | | __ ___      __| |__ | |__
  | |    | |/ _\` \\ \\ /\\ / /|  __||  __|
  | |____| | (_| |\\ V  V / | |___| |___
   \\_____|_|\\__,_| \\_/\\_/  \\____/\\____/

  Claw-EE Enterprise Protocol Online
`;
  // eslint-disable-next-line no-console
  console.log(banner);
  // eslint-disable-next-line no-console
  console.log(`Proxy listening on :${port}`);
  // eslint-disable-next-line no-console
  console.log(`Forwarding upstream to: ${upstreamBaseUrl}`);
}

async function main(): Promise<void> {
  const config = loadConfig();
  const ledger = new SqliteAuditLedger(path.join(config.openclawHome, "enterprise_audit.db"));
  ledger.init();
  const startupAuditIntegrity = ledger.verifyIntegrity();
  if (!startupAuditIntegrity.valid) {
    const message = `Audit ledger integrity check failed at startup: ${startupAuditIntegrity.reason || "unknown"}`;
    if (config.auditStartupVerifyMode === "block") {
      ledger.close();
      throw new Error(message);
    }
    if (config.auditStartupVerifyMode === "warn") {
      // eslint-disable-next-line no-console
      console.warn(message, startupAuditIntegrity);
    }
  } else if (config.auditStartupVerifyMode !== "off") {
    ledger.logAndSignAction("AUDIT_CHAIN_VERIFIED", {
      stage: "startup",
      report: startupAuditIntegrity,
    });
  }

  try {
    const attestation = enforceAndAttestAirgapPolicy({
      outboundInternetPolicy: config.outboundInternetPolicy,
      allowedOutboundHosts: config.allowedOutboundHosts,
      airgapAttestationPath: config.airgapAttestationPath,
      endpoints: [
        { name: "upstream_base_url", url: config.upstreamBaseUrl },
        { name: "internal_inference_base_url", url: config.internalInferenceBaseUrl },
      ],
    });
    ledger.logAndSignAction("AIRGAP_ATTESTED", {
      attestation_path: config.airgapAttestationPath,
      policy_hash: attestation.policy_hash,
      outbound_policy: attestation.outbound_policy,
    });
  } catch (error) {
    if (error instanceof AirgapPolicyError) {
      ledger.logAndSignAction("AIRGAP_POLICY_VIOLATION", {
        violations: error.violations,
        attestation_path: config.airgapAttestationPath,
      });
    } else {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "index",
        stage: "airgap-attestation",
        message: error instanceof Error ? error.message : String(error),
      });
    }
    ledger.close();
    throw error;
  }

  const budgetController = new BudgetController(
    {
      hourlyUsdCap: config.hourlyUsdCap,
      dailyUsdCap: config.dailyUsdCap,
    },
    config.pricingCatalogPath,
    path.join(config.openclawHome, "enterprise_budget.db"),
  );
  budgetController.init();
  const approvalService = new ApprovalService(path.join(config.openclawHome, "enterprise_approvals.db"));
  approvalService.init();
  const approvalAttestationService = new ApprovalAttestationService(
    approvalService,
    config.approvalAttestationDefaultPath,
    config.approvalAttestationSigningKey,
    config.approvalAttestationSigningKeyringPath,
  );
  const approvalAttestationJob = new ApprovalAttestationJobService(
    {
      enabled: config.approvalAttestationPeriodicEnabled,
      intervalSeconds: config.approvalAttestationPeriodicIntervalSeconds,
      snapshotDirectory: config.approvalAttestationSnapshotDirectory,
      chainPath: config.approvalAttestationChainPath,
      maxRecordsPerExport: config.approvalAttestationMaxRecordsPerExport,
      incremental: config.approvalAttestationIncremental,
      retentionMaxFiles: config.approvalAttestationRetentionMaxFiles,
    },
    approvalAttestationService,
    ledger,
  );

  const policyCatalog = loadSignedPolicyCatalog(
    config.policyCatalogPath,
    config.policyCatalogSigningKey,
    config.policyCatalogSigningKeyringPath,
  );
  ledger.logAndSignAction("POLICY_CATALOG_LOADED", {
    policy_catalog_path: config.policyCatalogPath,
    fingerprint: policyCatalog.fingerprint,
  });
  const policyEngine = new PolicyEngine(policyCatalog.policyOptions);
  const approvalPolicy = new ApprovalPolicyEngine();
  try {
    const loaded = loadSignedApprovalPolicyCatalog(
      config.approvalPolicyCatalogPath,
      config.approvalPolicyCatalogSigningKey,
      config.approvalPolicyCatalogSigningKeyringPath,
    );
    approvalPolicy.updateRules(loaded);
  } catch (error) {
    if (config.approvalPolicyCatalogSigningKey || config.approvalPolicyCatalogSigningKeyringPath) {
      throw error;
    }
    approvalPolicy.updateRules({
      version: "v1",
      fingerprint: "inline-default",
      signing_mode: "none",
      keyring_active_kid: null,
      keyring_key_count: 0,
      defaults: {
        requiredApprovals: Math.min(5, Math.max(1, Math.floor(config.approvalRequiredCount))),
        requiredRoles: ["approver"],
      },
      riskClassOverrides: new Map(),
      toolOverrides: new Map(),
      channelActionOverrides: new Map(),
    });
  }
  ledger.logAndSignAction("APPROVAL_POLICY_LOADED", {
    approval_policy_catalog_path: config.approvalPolicyCatalogPath,
    approval_policy: approvalPolicy.getState(),
  });
  const capabilityCatalog = loadSignedCapabilityCatalog(
    config.capabilityCatalogPath,
    config.capabilityCatalogSigningKey,
    config.capabilityCatalogSigningKeyringPath,
  );
  const capabilityPolicy = new CapabilityPolicyEngine();
  capabilityPolicy.updateRules(capabilityCatalog);
  ledger.logAndSignAction("CAPABILITY_CATALOG_LOADED", {
    capability_catalog_path: config.capabilityCatalogPath,
    ...capabilityPolicy.getState(),
  });
  const controlAuthz = new ControlAuthz(
    config.controlApiToken,
    config.controlTokensPath,
    config.controlTokensSigningKey,
    config.controlTokensSigningKeyringPath,
  );
  ledger.logAndSignAction("CONTROL_TOKEN_CATALOG_LOADED", {
    control_tokens_path: config.controlTokensPath || null,
    ...controlAuthz.getState(),
  });
  const modalityHub = new ModalityHub(2000);
  const channelHub = new ChannelHub(2000);
  const interactionStore = new InteractionStore(config.interactionDbPath);
  interactionStore.init();
  const replayStore = createReplayStore(
    {
      mode: config.replayStoreMode,
      redisUrl: config.replayRedisUrl,
      redisPrefix: config.replayRedisPrefix,
    },
    interactionStore,
  );
  await replayStore.warmup();
  ledger.logAndSignAction("REPLAY_STORE_READY", replayStore.getState());
  const alertNotifier = new AlertNotifier({
    webhookUrl: config.alertWebhookUrl,
    minIntervalMs: config.alertMinIntervalMs,
  });

  const modelRegistry = new ModelRegistry(
    config.modelRegistryPath,
    config.modelRegistrySigningKey,
    config.modelRegistrySigningKeyringPath,
  );
  modelRegistry.init();
  modelRegistry.assertAllowed(config.evaluatorModel, "safety");
  ledger.logAndSignAction("MODEL_REGISTRY_LOADED", {
    registry_path: config.modelRegistryPath,
    registry_fingerprint: modelRegistry.getFingerprint(),
    evaluator_model: config.evaluatorModel,
  });

  let transportAgents;
  try {
    transportAgents = buildTransportAgents(
      {
        targetName: "upstream_base_url",
        targetUrl: config.upstreamBaseUrl,
        enforceTls: config.upstreamEnforceTls,
        tlsPinsSha256: config.upstreamTlsPinSha256,
        caCertPath: config.upstreamCaCertPath,
        clientCertPath: config.upstreamClientCertPath,
        clientKeyPath: config.upstreamClientKeyPath,
      },
      {
        targetName: "internal_inference_base_url",
        targetUrl: config.internalInferenceBaseUrl,
        enforceTls: config.inferenceEnforceTls,
        tlsPinsSha256: config.inferenceTlsPinSha256,
        caCertPath: config.inferenceCaCertPath,
        clientCertPath: config.inferenceClientCertPath,
        clientKeyPath: config.inferenceClientKeyPath,
      },
    );
    ledger.logAndSignAction("TRANSPORT_SECURITY_READY", {
      summary: transportAgents.summary,
    });
  } catch (error) {
    ledger.logAndSignAction("TRANSPORT_SECURITY_VIOLATION", {
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }

  const runtimeEgressGuard = new RuntimeEgressGuard({
    policy: config.outboundInternetPolicy,
    allowlistedHosts: config.allowedOutboundHosts,
    revalidationIntervalMs: config.runtimeEgressRevalidationMs,
    targets: [
      { name: "upstream_base_url", url: config.upstreamBaseUrl },
      { name: "internal_inference_base_url", url: config.internalInferenceBaseUrl },
    ],
  });

  const riskEvaluator = new InternalGatewayRiskEvaluator(
    config.internalInferenceBaseUrl,
    config.internalInferenceApiKey,
    async () => {
      await runtimeEgressGuard.assertAllowed("internal_inference_base_url");
    },
    transportAgents.inferenceAgent,
  );

  const affective = new AffectiveMemoryService(
    {
      agentsRootPath: config.agentsRootPath,
      soulFilePath: config.soulFilePath,
    },
    ledger,
  );
  const heartbeat = new HeartbeatService(
    {
      intervalSeconds: config.heartbeatIntervalSeconds,
      tasksPath: config.heartbeatTasksPath,
    },
    ledger,
  );
  const channelDestinationPolicy = new ChannelDestinationPolicy(
    config.channelDestinationPolicyPath,
    config.channelDestinationPolicySigningKey,
  );
  const destinationPolicyState = channelDestinationPolicy.reload();
  ledger.logAndSignAction("CHANNEL_DESTINATION_POLICY_LOADED", {
    path: config.channelDestinationPolicyPath,
    ...destinationPolicyState,
  });
  const channelDelivery = new ChannelDeliveryService(
    {
      pollSeconds: config.channelDeliveryPollSeconds,
      batchSize: config.channelDeliveryBatchSize,
      maxAttempts: config.channelDeliveryMaxAttempts,
      retryBaseSeconds: config.channelDeliveryRetryBaseSeconds,
      connectorConfigPath: config.channelConnectorConfigPath,
      connectorSigningKey: config.channelConnectorSigningKey,
    },
    interactionStore,
    ledger,
    alertNotifier,
    runtimeEgressGuard,
    channelDestinationPolicy,
  );
  channelDelivery.start();
  ledger.logAndSignAction("CHANNEL_CONNECTOR_CATALOG_LOADED", {
    path: config.channelConnectorConfigPath,
    ...channelDelivery.getConnectorState(),
  });

  const gate = await startUncertaintyGate(
    {
      port: config.port,
      upstreamBaseUrl: config.upstreamBaseUrl,
      warnThreshold: config.warnThreshold,
      evaluatorModel: config.evaluatorModel,
      riskEvaluatorFailMode: config.riskEvaluatorFailMode,
      auditStartupVerifyMode: config.auditStartupVerifyMode,
      modelRegistryFingerprint: modelRegistry.getFingerprint(),
      enforcementMode: config.enforcementMode,
      controlAuthz,
      channelIngestToken: config.channelIngestToken,
      channelIngressHmacSecret: config.channelIngressHmacSecret,
      channelIngressMaxSkewSeconds: config.channelIngressMaxSkewSeconds,
      channelIngressEventTtlSeconds: config.channelIngressEventTtlSeconds,
      controlRateLimitWindowSeconds: config.controlRateLimitWindowSeconds,
      controlRateLimitMaxRequests: config.controlRateLimitMaxRequests,
      channelIngressRateLimitWindowSeconds: config.channelIngressRateLimitWindowSeconds,
      channelIngressRateLimitMaxRequests: config.channelIngressRateLimitMaxRequests,
      channelMaxOutboundChars: config.channelMaxOutboundChars,
      maxRequestInputTokens: config.maxRequestInputTokens,
      maxRequestOutputTokens: config.maxRequestOutputTokens,
      approvalTtlSeconds: config.approvalTtlSeconds,
      approvalRequiredCount: config.approvalRequiredCount,
      approvalMaxUses: config.approvalMaxUses,
      upstreamAgent: transportAgents.upstreamAgent,
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
    channelDestinationPolicy,
    approvalAttestationService,
    {
      reloadPolicyCatalog: () => {
        const reloaded = loadSignedPolicyCatalog(
          config.policyCatalogPath,
          config.policyCatalogSigningKey,
          config.policyCatalogSigningKeyringPath,
        );
        policyEngine.updateRules(reloaded.policyOptions);
        return { fingerprint: reloaded.fingerprint };
      },
      reloadModelRegistry: () => {
        modelRegistry.init();
        modelRegistry.assertAllowed(config.evaluatorModel, "safety");
        return { fingerprint: modelRegistry.getFingerprint() };
      },
      reloadApprovalPolicyCatalog: () => {
        const reloaded = loadSignedApprovalPolicyCatalog(
          config.approvalPolicyCatalogPath,
          config.approvalPolicyCatalogSigningKey,
          config.approvalPolicyCatalogSigningKeyringPath,
        );
        approvalPolicy.updateRules(reloaded);
        return { fingerprint: reloaded.fingerprint };
      },
      reloadCapabilityCatalog: () => {
        const reloaded = loadSignedCapabilityCatalog(
          config.capabilityCatalogPath,
          config.capabilityCatalogSigningKey,
          config.capabilityCatalogSigningKeyringPath,
        );
        capabilityPolicy.updateRules(reloaded);
        return { fingerprint: reloaded.fingerprint };
      },
    },
  );

  await affective.start();
  await heartbeat.start();
  approvalAttestationJob.start();
  printBanner(config.port, config.upstreamBaseUrl);

  let shuttingDown = false;

  const shutdown = async (signal: string) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    // eslint-disable-next-line no-console
    console.log(`Received ${signal}. Shutting down...`);
    try {
      await affective.stop();
      await heartbeat.stop();
      approvalAttestationJob.stop();
      await gate.close();
      await replayStore.close();
      channelDelivery.stop();
      interactionStore.close();
      approvalService.close();
      budgetController.close();
      ledger.close();
      // eslint-disable-next-line no-console
      console.log("Shutdown complete.");
      process.exit(0);
    } catch (error) {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "index",
        stage: "shutdown",
        message: error instanceof Error ? error.message : String(error),
      });
      process.exit(1);
    }
  };

  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
}

void main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error("Fatal startup error:", error);
  process.exit(1);
});
