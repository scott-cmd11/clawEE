import path from "node:path";
import { ApprovalService } from "./approval-service";
import { ApprovalAttestationService } from "./approval-attestation";
import { ApprovalAttestationJobService } from "./approval-attestation-job";
import { AuditAttestationJobService } from "./audit-attestation-job";
import { AuditAttestationService } from "./audit-attestation";
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
import { InitiativeEngine } from "./initiative-engine";
import { InitiativeStore } from "./initiative-store";
import { InteractionStore } from "./interaction-store";
import { ModelRegistry } from "./model-registry";
import { ModalityHub } from "./modality-hub";
import { loadSignedPolicyCatalog } from "./policy-catalog";
import { PolicyEngine } from "./policy-engine";
import { createReplayStore } from "./replay-store";
import { RuntimeEgressGuard } from "./runtime-egress-guard";
import { SecurityConformanceService } from "./security-conformance";
import { SecurityConformanceJobService } from "./security-conformance-job";
import { SecurityInvariantRegistry } from "./security-invariants";
import { buildTransportAgents } from "./transport-security";
import { startUncertaintyGate } from "./uncertainty-gate";
import { sha256Hex, stableStringify } from "./utils";

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
  const auditAttestationService = new AuditAttestationService(
    ledger,
    config.auditAttestationDefaultPath,
    config.auditAttestationSigningKey,
    config.auditAttestationSigningKeyringPath,
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
  const auditAttestationJob = new AuditAttestationJobService(
    {
      enabled: config.auditAttestationPeriodicEnabled,
      intervalSeconds: config.auditAttestationPeriodicIntervalSeconds,
      snapshotDirectory: config.auditAttestationSnapshotDirectory,
      chainPath: config.auditAttestationChainPath,
      maxRecordsPerExport: config.auditAttestationMaxRecordsPerExport,
      incremental: config.auditAttestationIncremental,
      retentionMaxFiles: config.auditAttestationRetentionMaxFiles,
    },
    auditAttestationService,
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
  let initiativeStore: InitiativeStore | null = null;
  let initiativeEngine: InitiativeEngine | null = null;
  if (config.initiativeEngineEnabled) {
    initiativeStore = new InitiativeStore(config.initiativeDbPath);
    initiativeStore.init();
    initiativeEngine = new InitiativeEngine(
      {
        enabled: config.initiativeEngineEnabled,
        pollSeconds: config.initiativePollSeconds,
        maxTaskRetries: config.initiativeMaxTaskRetries,
        nodeId: config.nodeId,
      },
      initiativeStore,
      channelHub,
      interactionStore,
      ledger,
    );
    await initiativeEngine.start();
  }
  const replayStore = createReplayStore(
    {
      mode: config.replayStoreMode,
      redisUrl: config.replayRedisUrl,
      redisPrefix: config.replayRedisPrefix,
      postgresUrl: config.replayPostgresUrl,
      postgresSchema: config.replayPostgresSchema,
      postgresTablePrefix: config.replayPostgresTablePrefix,
      postgresConnectTimeoutMs: config.replayPostgresConnectTimeoutMs,
      postgresSslMode: config.replayPostgresSslMode,
    },
    interactionStore,
  );
  await replayStore.warmup();
  ledger.logAndSignAction("REPLAY_STORE_READY", replayStore.getState());
  if (config.clusterId !== "local" && config.replayStoreMode === "sqlite") {
    ledger.logAndSignAction("CLUSTER_CONFIG_WARNING", {
      node_id: config.nodeId,
      cluster_id: config.clusterId,
      reason: "sqlite replay mode is node-local and does not provide cross-node dedupe",
      recommendation: "use REPLAY_STORE_MODE=redis or postgres",
    });
  }
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
  const invariantRegistry = new SecurityInvariantRegistry();

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
  const configFingerprints: Record<string, string> = {
    policy_catalog: policyCatalog.fingerprint,
    model_registry: modelRegistry.getFingerprint(),
    capability_catalog: capabilityPolicy.getState().fingerprint,
    approval_policy: approvalPolicy.getState().fingerprint,
    channel_destination_policy: destinationPolicyState.fingerprint,
    channel_connector_catalog: channelDelivery.getConnectorState().fingerprint,
  };
  const codeFingerprint = sha256Hex(
    stableStringify({
      ...configFingerprints,
      replay_store_mode: config.replayStoreMode,
      security_invariants_enforcement: config.securityInvariantsEnforcement,
      initiative_engine_enabled: config.initiativeEngineEnabled,
      initiative_poll_seconds: config.initiativePollSeconds,
      initiative_intake_enabled: config.initiativeIntakeEnabled,
      initiative_intake_hmac_enabled: Boolean(config.initiativeIntakeHmacSecret),
      openclaw_intake_enabled: config.openclawIntakeEnabled,
      openclaw_intake_hmac_enabled: Boolean(config.openclawIntakeHmacSecret),
      node_id: config.nodeId,
      cluster_id: config.clusterId,
    }),
  );
  const securityConformanceService = new SecurityConformanceService({
    defaultExportPath: config.securityConformanceExportPath,
    codeFingerprint,
    runtimeContext: {
      node_id: config.nodeId,
      cluster_id: config.clusterId,
      enforcement_mode: config.enforcementMode,
      risk_evaluator_fail_mode: config.riskEvaluatorFailMode,
      security_invariants_enforcement: config.securityInvariantsEnforcement,
      model_registry_fingerprint: modelRegistry.getFingerprint(),
      replay_store_mode: config.replayStoreMode,
      replay_store_state: replayStore.getState(),
      initiative_engine_enabled: config.initiativeEngineEnabled,
      initiative_poll_seconds: config.initiativePollSeconds,
      initiative_max_task_retries: config.initiativeMaxTaskRetries,
      initiative_intake_enabled: config.initiativeIntakeEnabled,
      initiative_intake_hmac_enabled: Boolean(config.initiativeIntakeHmacSecret),
      initiative_intake_event_ttl_seconds: config.initiativeIntakeEventTtlSeconds,
      openclaw_intake_enabled: config.openclawIntakeEnabled,
      openclaw_intake_hmac_enabled: Boolean(config.openclawIntakeHmacSecret),
      openclaw_intake_event_ttl_seconds: config.openclawIntakeEventTtlSeconds,
      config_fingerprints: configFingerprints,
    },
    signingKey: config.securityConformanceSigningKey,
    signingKeyringPath: config.securityConformanceSigningKeyringPath,
  });
  const securityConformanceJob = new SecurityConformanceJobService(
    {
      enabled: config.securityConformancePeriodicEnabled,
      intervalSeconds: config.securityConformancePeriodicIntervalSeconds,
      snapshotDirectory: config.securityConformanceSnapshotDirectory,
      chainPath: config.securityConformanceChainPath,
      retentionMaxFiles: config.securityConformanceRetentionMaxFiles,
    },
    securityConformanceService,
    invariantRegistry,
    ledger,
  );
  ledger.logAndSignAction("INITIATIVE_ENGINE_READY", {
    enabled: config.initiativeEngineEnabled,
    poll_seconds: config.initiativePollSeconds,
    max_task_retries: config.initiativeMaxTaskRetries,
    db_path: config.initiativeDbPath,
  });

  const gate = await startUncertaintyGate(
    {
      port: config.port,
      upstreamBaseUrl: config.upstreamBaseUrl,
      warnThreshold: config.warnThreshold,
      evaluatorModel: config.evaluatorModel,
      riskEvaluatorFailMode: config.riskEvaluatorFailMode,
      auditStartupVerifyMode: config.auditStartupVerifyMode,
      securityInvariantsEnforcement: config.securityInvariantsEnforcement,
      nodeId: config.nodeId,
      clusterId: config.clusterId,
      configFingerprints,
      modelRegistryFingerprint: modelRegistry.getFingerprint(),
      enforcementMode: config.enforcementMode,
      controlAuthz,
      channelIngestToken: config.channelIngestToken,
      channelIngressHmacSecret: config.channelIngressHmacSecret,
      channelIngressMaxSkewSeconds: config.channelIngressMaxSkewSeconds,
      channelIngressEventTtlSeconds: config.channelIngressEventTtlSeconds,
      initiativeIntakeEnabled: config.initiativeIntakeEnabled,
      initiativeIntakeToken: config.initiativeIntakeToken,
      initiativeIntakeHmacSecret: config.initiativeIntakeHmacSecret,
      initiativeIntakeMaxSkewSeconds: config.initiativeIntakeMaxSkewSeconds,
      initiativeIntakeEventTtlSeconds: config.initiativeIntakeEventTtlSeconds,
      openclawIntakeEnabled: config.openclawIntakeEnabled,
      openclawIntakeToken: config.openclawIntakeToken,
      openclawIntakeHmacSecret: config.openclawIntakeHmacSecret,
      openclawIntakeMaxSkewSeconds: config.openclawIntakeMaxSkewSeconds,
      openclawIntakeEventTtlSeconds: config.openclawIntakeEventTtlSeconds,
      modalityTextMaxPayloadBytes: config.modalityTextMaxPayloadBytes,
      modalityVisionMaxPayloadBytes: config.modalityVisionMaxPayloadBytes,
      modalityAudioMaxPayloadBytes: config.modalityAudioMaxPayloadBytes,
      modalityActionMaxPayloadBytes: config.modalityActionMaxPayloadBytes,
      modalityTextMaxChars: config.modalityTextMaxChars,
      channelIngressMaxTextChars: config.channelIngressMaxTextChars,
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
    auditAttestationService,
    invariantRegistry,
    securityConformanceService,
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
    initiativeEngine || undefined,
  );

  await affective.start();
  await heartbeat.start();
  approvalAttestationJob.start();
  auditAttestationJob.start();
  securityConformanceJob.start();
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
      if (initiativeEngine) {
        await initiativeEngine.stop();
      }
      approvalAttestationJob.stop();
      auditAttestationJob.stop();
      securityConformanceJob.stop();
      await gate.close();
      await replayStore.close();
      channelDelivery.stop();
      initiativeStore?.close();
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
