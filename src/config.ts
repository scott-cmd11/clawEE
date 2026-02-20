import os from "node:os";
import path from "node:path";
import dotenv from "dotenv";

dotenv.config();

export type EnforcementMode = "warn" | "block";
export type OutboundInternetPolicy = "deny" | "allow";
export type RiskEvaluatorFailMode = "allow" | "block";
export type ReplayStoreMode = "sqlite" | "redis";
export type AuditStartupVerifyMode = "off" | "warn" | "block";

export interface AppConfig {
  port: number;
  upstreamBaseUrl: string;
  internalInferenceBaseUrl: string;
  internalInferenceApiKey: string;
  warnThreshold: number;
  evaluatorModel: string;
  riskEvaluatorFailMode: RiskEvaluatorFailMode;
  enforcementMode: EnforcementMode;
  controlApiToken: string;
  controlTokensPath: string;
  controlTokensSigningKey: string;
  controlTokensSigningKeyringPath: string;
  channelIngestToken: string;
  channelIngressHmacSecret: string;
  channelIngressMaxSkewSeconds: number;
  channelIngressEventTtlSeconds: number;
  controlRateLimitWindowSeconds: number;
  controlRateLimitMaxRequests: number;
  channelIngressRateLimitWindowSeconds: number;
  channelIngressRateLimitMaxRequests: number;
  replayStoreMode: ReplayStoreMode;
  replayRedisUrl: string;
  replayRedisPrefix: string;
  auditStartupVerifyMode: AuditStartupVerifyMode;
  modalityTextMaxPayloadBytes: number;
  modalityVisionMaxPayloadBytes: number;
  modalityAudioMaxPayloadBytes: number;
  modalityActionMaxPayloadBytes: number;
  modalityTextMaxChars: number;
  channelIngressMaxTextChars: number;
  pricingCatalogPath: string;
  hourlyUsdCap: number;
  dailyUsdCap: number;
  maxRequestInputTokens: number;
  maxRequestOutputTokens: number;
  approvalTtlSeconds: number;
  approvalRequiredCount: number;
  approvalMaxUses: number;
  approvalPolicyCatalogPath: string;
  approvalPolicyCatalogSigningKey: string;
  approvalPolicyCatalogSigningKeyringPath: string;
  approvalAttestationPeriodicEnabled: boolean;
  approvalAttestationPeriodicIntervalSeconds: number;
  approvalAttestationSnapshotDirectory: string;
  approvalAttestationChainPath: string;
  approvalAttestationMaxRecordsPerExport: number;
  approvalAttestationIncremental: boolean;
  approvalAttestationRetentionMaxFiles: number;
  alertWebhookUrl: string;
  alertMinIntervalMs: number;
  policyCatalogPath: string;
  policyCatalogSigningKey: string;
  policyCatalogSigningKeyringPath: string;
  capabilityCatalogPath: string;
  capabilityCatalogSigningKey: string;
  capabilityCatalogSigningKeyringPath: string;
  modelRegistryPath: string;
  modelRegistrySigningKey: string;
  modelRegistrySigningKeyringPath: string;
  runtimeEgressRevalidationMs: number;
  upstreamEnforceTls: boolean;
  upstreamTlsPinSha256: string;
  upstreamCaCertPath: string;
  upstreamClientCertPath: string;
  upstreamClientKeyPath: string;
  inferenceEnforceTls: boolean;
  inferenceTlsPinSha256: string;
  inferenceCaCertPath: string;
  inferenceClientCertPath: string;
  inferenceClientKeyPath: string;
  outboundInternetPolicy: OutboundInternetPolicy;
  allowedOutboundHosts: string[];
  airgapAttestationPath: string;
  heartbeatIntervalSeconds: number;
  heartbeatTasksPath: string;
  interactionDbPath: string;
  channelConnectorConfigPath: string;
  channelConnectorSigningKey: string;
  channelDestinationPolicyPath: string;
  channelDestinationPolicySigningKey: string;
  channelDeliveryPollSeconds: number;
  channelDeliveryBatchSize: number;
  channelDeliveryMaxAttempts: number;
  channelDeliveryRetryBaseSeconds: number;
  channelMaxOutboundChars: number;
  approvalAttestationDefaultPath: string;
  approvalAttestationSigningKey: string;
  approvalAttestationSigningKeyringPath: string;
  auditAttestationDefaultPath: string;
  auditAttestationSigningKey: string;
  auditAttestationSigningKeyringPath: string;
  openclawHome: string;
  soulFilePath: string;
  agentsRootPath: string;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

function numberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw || !raw.trim()) {
    return fallback;
  }
  const value = Number(raw);
  if (Number.isNaN(value)) {
    throw new Error(`Invalid numeric environment variable: ${name}`);
  }
  return value;
}

function booleanEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (!raw || !raw.trim()) {
    return fallback;
  }
  const value = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(value)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(value)) {
    return false;
  }
  throw new Error(`Invalid boolean environment variable: ${name}`);
}

function enumEnv<T extends string>(name: string, fallback: T, values: readonly T[]): T {
  const raw = process.env[name];
  if (!raw || !raw.trim()) {
    return fallback;
  }
  const normalized = raw.trim() as T;
  if (!values.includes(normalized)) {
    throw new Error(`Invalid value for ${name}: ${raw}`);
  }
  return normalized;
}

function stringListEnv(name: string): string[] {
  const raw = process.env[name];
  if (!raw || !raw.trim()) {
    return [];
  }
  return raw
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
}

export function loadConfig(): AppConfig {
  const openclawHome = process.env.OPENCLAW_HOME?.trim() || path.join(os.homedir(), ".openclaw");
  const soulFilePath =
    process.env.SOUL_FILE_PATH?.trim() || path.join(openclawHome, "workspace", "SOUL.md");
  const agentsRootPath =
    process.env.AGENTS_ROOT_PATH?.trim() || path.join(openclawHome, "agents");
  const pricingCatalogPath =
    process.env.PRICING_CATALOG_PATH?.trim() || path.join(process.cwd(), "config", "pricing.v1.json");
  const policyCatalogPath =
    process.env.POLICY_CATALOG_PATH?.trim() || path.join(process.cwd(), "config", "policy-catalog.v1.json");
  const capabilityCatalogPath =
    process.env.CAPABILITY_CATALOG_PATH?.trim() ||
    path.join(process.cwd(), "config", "capability-catalog.v1.json");
  const modelRegistryPath =
    process.env.MODEL_REGISTRY_PATH?.trim() ||
    path.join(process.cwd(), "config", "model-registry.v1.json");
  const airgapAttestationPath =
    process.env.AIRGAP_ATTESTATION_PATH?.trim() ||
    path.join(openclawHome, "airgap_attestation.json");
  const heartbeatTasksPath =
    process.env.HEARTBEAT_TASKS_PATH?.trim() || path.join(openclawHome, "heartbeat_tasks.json");
  const interactionDbPath =
    process.env.INTERACTION_DB_PATH?.trim() ||
    path.join(openclawHome, "enterprise_interactions.db");
  const channelConnectorConfigPath =
    process.env.CHANNEL_CONNECTOR_CONFIG_PATH?.trim() ||
    path.join(process.cwd(), "config", "channel-connectors.v1.json");
  const channelDestinationPolicyPath =
    process.env.CHANNEL_DESTINATION_POLICY_PATH?.trim() ||
    path.join(process.cwd(), "config", "channel-destination-policy.v1.json");
  const approvalAttestationDefaultPath =
    process.env.APPROVAL_ATTESTATION_DEFAULT_PATH?.trim() ||
    path.join(openclawHome, "approval_attestation.json");
  const auditAttestationDefaultPath =
    process.env.AUDIT_ATTESTATION_DEFAULT_PATH?.trim() ||
    path.join(openclawHome, "audit_attestation.json");
  const approvalPolicyCatalogPath =
    process.env.APPROVAL_POLICY_CATALOG_PATH?.trim() ||
    path.join(process.cwd(), "config", "approval-policy-catalog.v1.json");
  const approvalAttestationSnapshotDirectory =
    process.env.APPROVAL_ATTESTATION_SNAPSHOT_DIRECTORY?.trim() ||
    path.join(openclawHome, "approval_attestation_snapshots");
  const approvalAttestationChainPath =
    process.env.APPROVAL_ATTESTATION_CHAIN_PATH?.trim() ||
    path.join(openclawHome, "approval_attestation_chain.jsonl");

  return {
    port: numberEnv("PORT", 8080),
    upstreamBaseUrl: requiredEnv("UPSTREAM_BASE_URL"),
    internalInferenceBaseUrl: requiredEnv("INTERNAL_INFERENCE_BASE_URL"),
    internalInferenceApiKey: requiredEnv("INTERNAL_INFERENCE_API_KEY"),
    warnThreshold: numberEnv("WARN_THRESHOLD", 0.85),
    evaluatorModel: process.env.EVALUATOR_MODEL?.trim() || "gpt-4.1-mini",
    riskEvaluatorFailMode: enumEnv<RiskEvaluatorFailMode>("RISK_EVALUATOR_FAIL_MODE", "block", [
      "allow",
      "block",
    ]),
    enforcementMode: enumEnv<EnforcementMode>("ENFORCEMENT_MODE", "block", ["warn", "block"]),
    controlApiToken: requiredEnv("CONTROL_API_TOKEN"),
    controlTokensPath: process.env.CONTROL_TOKENS_PATH?.trim() || "",
    controlTokensSigningKey: process.env.CONTROL_TOKENS_SIGNING_KEY?.trim() || "",
    controlTokensSigningKeyringPath:
      process.env.CONTROL_TOKENS_SIGNING_KEYRING_PATH?.trim() || "",
    channelIngestToken: process.env.CHANNEL_INGEST_TOKEN?.trim() || requiredEnv("CONTROL_API_TOKEN"),
    channelIngressHmacSecret: process.env.CHANNEL_INGRESS_HMAC_SECRET?.trim() || "",
    channelIngressMaxSkewSeconds: numberEnv("CHANNEL_INGRESS_MAX_SKEW_SECONDS", 300),
    channelIngressEventTtlSeconds: numberEnv("CHANNEL_INGRESS_EVENT_TTL_SECONDS", 86400),
    controlRateLimitWindowSeconds: numberEnv("CONTROL_RATE_LIMIT_WINDOW_SECONDS", 60),
    controlRateLimitMaxRequests: numberEnv("CONTROL_RATE_LIMIT_MAX_REQUESTS", 300),
    channelIngressRateLimitWindowSeconds: numberEnv("CHANNEL_INGRESS_RATE_LIMIT_WINDOW_SECONDS", 60),
    channelIngressRateLimitMaxRequests: numberEnv("CHANNEL_INGRESS_RATE_LIMIT_MAX_REQUESTS", 300),
    replayStoreMode: enumEnv<ReplayStoreMode>("REPLAY_STORE_MODE", "sqlite", ["sqlite", "redis"]),
    replayRedisUrl: process.env.REPLAY_REDIS_URL?.trim() || "",
    replayRedisPrefix: process.env.REPLAY_REDIS_PREFIX?.trim() || "clawee",
    auditStartupVerifyMode: enumEnv<AuditStartupVerifyMode>(
      "AUDIT_STARTUP_VERIFY_MODE",
      "block",
      ["off", "warn", "block"],
    ),
    modalityTextMaxPayloadBytes: numberEnv("MODALITY_TEXT_MAX_PAYLOAD_BYTES", 65536),
    modalityVisionMaxPayloadBytes: numberEnv("MODALITY_VISION_MAX_PAYLOAD_BYTES", 1048576),
    modalityAudioMaxPayloadBytes: numberEnv("MODALITY_AUDIO_MAX_PAYLOAD_BYTES", 1048576),
    modalityActionMaxPayloadBytes: numberEnv("MODALITY_ACTION_MAX_PAYLOAD_BYTES", 65536),
    modalityTextMaxChars: numberEnv("MODALITY_TEXT_MAX_CHARS", 16000),
    channelIngressMaxTextChars: numberEnv("CHANNEL_INGRESS_MAX_TEXT_CHARS", 8000),
    pricingCatalogPath,
    hourlyUsdCap: numberEnv("HOURLY_USD_CAP", 15),
    dailyUsdCap: numberEnv("DAILY_USD_CAP", 150),
    maxRequestInputTokens: numberEnv("MAX_REQUEST_INPUT_TOKENS", 200000),
    maxRequestOutputTokens: numberEnv("MAX_REQUEST_OUTPUT_TOKENS", 32000),
    approvalTtlSeconds: numberEnv("APPROVAL_TTL_SECONDS", 3600),
    approvalRequiredCount: numberEnv("APPROVAL_REQUIRED_COUNT", 2),
    approvalMaxUses: numberEnv("APPROVAL_MAX_USES", 1),
    approvalPolicyCatalogPath,
    approvalPolicyCatalogSigningKey:
      process.env.APPROVAL_POLICY_CATALOG_SIGNING_KEY?.trim() || "",
    approvalPolicyCatalogSigningKeyringPath:
      process.env.APPROVAL_POLICY_CATALOG_SIGNING_KEYRING_PATH?.trim() || "",
    approvalAttestationPeriodicEnabled: booleanEnv("APPROVAL_ATTESTATION_PERIODIC_ENABLED", false),
    approvalAttestationPeriodicIntervalSeconds: numberEnv(
      "APPROVAL_ATTESTATION_PERIODIC_INTERVAL_SECONDS",
      3600,
    ),
    approvalAttestationSnapshotDirectory,
    approvalAttestationChainPath,
    approvalAttestationMaxRecordsPerExport: numberEnv(
      "APPROVAL_ATTESTATION_MAX_RECORDS_PER_EXPORT",
      5000,
    ),
    approvalAttestationIncremental: booleanEnv("APPROVAL_ATTESTATION_INCREMENTAL", true),
    approvalAttestationRetentionMaxFiles: numberEnv(
      "APPROVAL_ATTESTATION_RETENTION_MAX_FILES",
      0,
    ),
    alertWebhookUrl: process.env.ALERT_WEBHOOK_URL?.trim() || "",
    alertMinIntervalMs: numberEnv("ALERT_MIN_INTERVAL_MS", 60000),
    policyCatalogPath,
    policyCatalogSigningKey: requiredEnv("POLICY_CATALOG_SIGNING_KEY"),
    policyCatalogSigningKeyringPath:
      process.env.POLICY_CATALOG_SIGNING_KEYRING_PATH?.trim() || "",
    capabilityCatalogPath,
    capabilityCatalogSigningKey: requiredEnv("CAPABILITY_CATALOG_SIGNING_KEY"),
    capabilityCatalogSigningKeyringPath:
      process.env.CAPABILITY_CATALOG_SIGNING_KEYRING_PATH?.trim() || "",
    modelRegistryPath,
    modelRegistrySigningKey: requiredEnv("MODEL_REGISTRY_SIGNING_KEY"),
    modelRegistrySigningKeyringPath:
      process.env.MODEL_REGISTRY_SIGNING_KEYRING_PATH?.trim() || "",
    runtimeEgressRevalidationMs: numberEnv("RUNTIME_EGRESS_REVALIDATION_MS", 30000),
    upstreamEnforceTls: booleanEnv("UPSTREAM_ENFORCE_TLS", false),
    upstreamTlsPinSha256: process.env.UPSTREAM_TLS_PIN_SHA256?.trim() || "",
    upstreamCaCertPath: process.env.UPSTREAM_CA_CERT_PATH?.trim() || "",
    upstreamClientCertPath: process.env.UPSTREAM_CLIENT_CERT_PATH?.trim() || "",
    upstreamClientKeyPath: process.env.UPSTREAM_CLIENT_KEY_PATH?.trim() || "",
    inferenceEnforceTls: booleanEnv("INFERENCE_ENFORCE_TLS", false),
    inferenceTlsPinSha256: process.env.INFERENCE_TLS_PIN_SHA256?.trim() || "",
    inferenceCaCertPath: process.env.INFERENCE_CA_CERT_PATH?.trim() || "",
    inferenceClientCertPath: process.env.INFERENCE_CLIENT_CERT_PATH?.trim() || "",
    inferenceClientKeyPath: process.env.INFERENCE_CLIENT_KEY_PATH?.trim() || "",
    outboundInternetPolicy: enumEnv<OutboundInternetPolicy>("OUTBOUND_INTERNET_POLICY", "deny", [
      "deny",
      "allow",
    ]),
    allowedOutboundHosts: stringListEnv("ALLOWED_OUTBOUND_HOSTS"),
    airgapAttestationPath,
    heartbeatIntervalSeconds: numberEnv("HEARTBEAT_INTERVAL_SECONDS", 30),
    heartbeatTasksPath,
    interactionDbPath,
    channelConnectorConfigPath,
    channelConnectorSigningKey: process.env.CHANNEL_CONNECTOR_SIGNING_KEY?.trim() || "",
    channelDestinationPolicyPath,
    channelDestinationPolicySigningKey:
      process.env.CHANNEL_DESTINATION_POLICY_SIGNING_KEY?.trim() || "",
    channelDeliveryPollSeconds: numberEnv("CHANNEL_DELIVERY_POLL_SECONDS", 5),
    channelDeliveryBatchSize: numberEnv("CHANNEL_DELIVERY_BATCH_SIZE", 20),
    channelDeliveryMaxAttempts: numberEnv("CHANNEL_DELIVERY_MAX_ATTEMPTS", 6),
    channelDeliveryRetryBaseSeconds: numberEnv("CHANNEL_DELIVERY_RETRY_BASE_SECONDS", 10),
    channelMaxOutboundChars: numberEnv("CHANNEL_MAX_OUTBOUND_CHARS", 4000),
    approvalAttestationDefaultPath,
    approvalAttestationSigningKey: process.env.APPROVAL_ATTESTATION_SIGNING_KEY?.trim() || "",
    approvalAttestationSigningKeyringPath:
      process.env.APPROVAL_ATTESTATION_SIGNING_KEYRING_PATH?.trim() || "",
    auditAttestationDefaultPath,
    auditAttestationSigningKey: process.env.AUDIT_ATTESTATION_SIGNING_KEY?.trim() || "",
    auditAttestationSigningKeyringPath:
      process.env.AUDIT_ATTESTATION_SIGNING_KEYRING_PATH?.trim() || "",
    openclawHome,
    soulFilePath,
    agentsRootPath,
  };
}
