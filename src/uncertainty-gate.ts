import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import express, { type Request, type RequestHandler } from "express";
import {
  createProxyMiddleware,
  fixRequestBody,
  responseInterceptor,
  type RequestHandler as ProxyRequestHandler,
} from "http-proxy-middleware";
import type { AuditLedger } from "./audit-ledger";
import { ApprovalService } from "./approval-service";
import { ApprovalAttestationService } from "./approval-attestation";
import { ApprovalPolicyEngine } from "./approval-policy";
import { AuditAttestationService } from "./audit-attestation";
import { AlertNotifier } from "./alert-notifier";
import {
  CapabilityPolicyEngine,
} from "./capability-policy";
import { ChannelHub, type ChannelKind } from "./channel-hub";
import { ChannelDeliveryService } from "./channel-delivery-service";
import { ChannelDestinationPolicy } from "./channel-destination-policy";
import { BudgetController, type CostEstimate } from "./budget-controller";
import type {
  AuditStartupVerifyMode,
  EnforcementMode,
  RiskEvaluatorFailMode,
  SecurityInvariantsEnforcement,
} from "./config";
import { type ControlPermission, type ControlIdentity, ControlAuthz } from "./control-authz";
import type { RiskEvaluator, ToolIntent } from "./inference-provider";
import { InteractionStore } from "./interaction-store";
import { parseInitiativeIntake, parseInitiativeProvider } from "./initiative-intake";
import type { InitiativeControlService } from "./initiative-engine";
import { parseOpenClawHeartbeat, parseOpenClawWorkItem } from "./openclaw-intake";
import { validateModalityPayload, type ModalityPayloadValidationOptions } from "./modality-validation";
import { ModelRegistry, type ModelModality } from "./model-registry";
import { ModalityHub, type ModalityType } from "./modality-hub";
import { PolicyEngine } from "./policy-engine";
import { FixedWindowRateLimiter } from "./rate-limiter";
import { ReplayStore } from "./replay-store";
import { RuntimeEgressGuard, RuntimeEgressPolicyError } from "./runtime-egress-guard";
import { SecurityConformanceService } from "./security-conformance";
import { SecurityInvariantRegistry } from "./security-invariants";
import { sha256Hex, stableStringify } from "./utils";
import type { VdiService } from "./vdi-service";

export interface UncertaintyGateOptions {
  port: number;
  upstreamBaseUrl: string;
  warnThreshold: number;
  evaluatorModel: string;
  riskEvaluatorFailMode: RiskEvaluatorFailMode;
  auditStartupVerifyMode: AuditStartupVerifyMode;
  securityInvariantsEnforcement: SecurityInvariantsEnforcement;
  nodeId: string;
  clusterId: string;
  configFingerprints: Record<string, string>;
  modelRegistryFingerprint: string;
  enforcementMode: EnforcementMode;
  controlAuthz: ControlAuthz;
  channelIngestToken: string;
  channelIngressHmacSecret: string;
  channelIngressMaxSkewSeconds: number;
  channelIngressEventTtlSeconds: number;
  initiativeIntakeEnabled?: boolean;
  initiativeIntakeToken?: string;
  initiativeIntakeHmacSecret?: string;
  initiativeIntakeMaxSkewSeconds?: number;
  initiativeIntakeEventTtlSeconds?: number;
  openclawIntakeEnabled?: boolean;
  openclawIntakeToken?: string;
  openclawIntakeHmacSecret?: string;
  openclawIntakeMaxSkewSeconds?: number;
  openclawIntakeEventTtlSeconds?: number;
  modalityTextMaxPayloadBytes: number;
  modalityVisionMaxPayloadBytes: number;
  modalityAudioMaxPayloadBytes: number;
  modalityActionMaxPayloadBytes: number;
  modalityTextMaxChars: number;
  channelIngressMaxTextChars: number;
  controlRateLimitWindowSeconds: number;
  controlRateLimitMaxRequests: number;
  channelIngressRateLimitWindowSeconds: number;
  channelIngressRateLimitMaxRequests: number;
  channelMaxOutboundChars: number;
  maxRequestInputTokens: number;
  maxRequestOutputTokens: number;
  approvalTtlSeconds: number;
  approvalRequiredCount: number;
  approvalMaxUses: number;
  upstreamAgent?: http.Agent | https.Agent;
}

export interface UncertaintyGateService {
  close(): Promise<void>;
}

const MAX_MODALITY_SESSION_ID_CHARS = 256;
const MAX_MODALITY_SOURCE_CHARS = 256;
const MAX_CHANNEL_SOURCE_CHARS = 256;
const MAX_CHANNEL_SENDER_CHARS = 256;

function nonEmptyStringWithMax(value: unknown, maxChars: number): string {
  if (typeof value !== "string") {
    return "";
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxChars) {
    return "";
  }
  return trimmed;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function parseApprovalMetadata(metadataRaw: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(metadataRaw);
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    return {};
  }
}

function parseApprovalActors(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map((value) => String(value || "").trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function remainingApprovals(record: {
  required_approvals: number;
  approval_actors: string;
}): number {
  const required = Math.max(1, Math.floor(Number(record.required_approvals || 1)));
  const current = parseApprovalActors(record.approval_actors).length;
  return Math.max(0, required - current);
}

function parseRequiredRoles(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean)
      .sort();
  } catch {
    return [];
  }
}

function parseApprovalActorRoles(raw: string): Record<string, string> {
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const out: Record<string, string> = {};
    for (const [actor, role] of Object.entries(parsed as Record<string, unknown>)) {
      const actorKey = String(actor || "").trim();
      const roleValue = String(role || "").trim().toLowerCase();
      if (!actorKey || !roleValue) {
        continue;
      }
      out[actorKey] = roleValue;
    }
    return out;
  } catch {
    return {};
  }
}

function missingRequiredRoles(record: {
  required_roles: string;
  approval_actor_roles: string;
}): string[] {
  const requiredRoles = parseRequiredRoles(record.required_roles);
  if (requiredRoles.length === 0) {
    return [];
  }
  const actorRoles = new Set(Object.values(parseApprovalActorRoles(record.approval_actor_roles)));
  return requiredRoles.filter((role) => !actorRoles.has(role));
}

function extractToolIntent(body: unknown): ToolIntent {
  if (!body || typeof body !== "object") {
    return { hasToolIntent: false, toolNames: [] };
  }

  const record = body as Record<string, unknown>;
  const names = new Set<string>();
  let hasToolIntent = false;

  if (Array.isArray(record.tools)) {
    hasToolIntent = true;
    for (const tool of record.tools) {
      if (tool && typeof tool === "object") {
        const maybeName = (tool as Record<string, unknown>).name;
        if (typeof maybeName === "string" && maybeName.trim()) {
          names.add(maybeName.trim());
        }
      }
    }
  }

  if (typeof record.tool === "string" && record.tool.trim()) {
    hasToolIntent = true;
    names.add(record.tool.trim());
  }

  if (Array.isArray(record.messages)) {
    for (const message of record.messages) {
      if (!message || typeof message !== "object") {
        continue;
      }
      const msg = message as Record<string, unknown>;
      if (Array.isArray(msg.tool_calls)) {
        hasToolIntent = true;
      }
    }
  }

  return {
    hasToolIntent,
    toolNames: [...names],
  };
}

function estimateInputTokens(payload: unknown): number {
  const raw = JSON.stringify(payload);
  return Math.max(1, Math.ceil(raw.length / 4));
}

function extractOutputTokens(payload: unknown): number {
  if (!payload || typeof payload !== "object") {
    return 512;
  }
  const record = payload as Record<string, unknown>;
  if (typeof record.max_output_tokens === "number" && record.max_output_tokens > 0) {
    return Math.floor(record.max_output_tokens);
  }
  if (typeof record.max_tokens === "number" && record.max_tokens > 0) {
    return Math.floor(record.max_tokens);
  }
  return 512;
}

function extractModel(payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return "unknown-model";
  }
  const record = payload as Record<string, unknown>;
  if (typeof record.model === "string" && record.model.trim()) {
    return record.model.trim();
  }
  return "unknown-model";
}

function inferModality(pathValue: string, payload: unknown): ModelModality {
  const pathLower = pathValue.toLowerCase();
  if (pathLower.includes("embeddings")) {
    return "embedding";
  }
  if (
    pathLower.includes("audio") ||
    pathLower.includes("speech") ||
    pathLower.includes("transcribe")
  ) {
    return "audio";
  }
  if (pathLower.includes("image") || pathLower.includes("vision")) {
    return "vision";
  }

  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;
    if ("input_audio" in record || "audio" in record) {
      return "audio";
    }
    if ("input_image" in record || "image" in record) {
      return "vision";
    }
  }

  return "text";
}

function extractChannelHint(payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const record = payload as Record<string, unknown>;
  const directChannel =
    typeof record.channel === "string" && record.channel.trim()
      ? record.channel.trim().toLowerCase()
      : "";
  if (directChannel) {
    return directChannel;
  }
  const sourceChannel =
    typeof record.source_channel === "string" && record.source_channel.trim()
      ? record.source_channel.trim().toLowerCase()
      : "";
  if (sourceChannel) {
    return sourceChannel;
  }
  const metadata =
    record.metadata && typeof record.metadata === "object"
      ? (record.metadata as Record<string, unknown>)
      : null;
  if (metadata) {
    const metadataChannel =
      typeof metadata.channel === "string" && metadata.channel.trim()
        ? metadata.channel.trim().toLowerCase()
        : "";
    if (metadataChannel) {
      return metadataChannel;
    }
    const metadataSourceChannel =
      typeof metadata.source_channel === "string" && metadata.source_channel.trim()
        ? metadata.source_channel.trim().toLowerCase()
        : "";
    if (metadataSourceChannel) {
      return metadataSourceChannel;
    }
  }
  return "";
}

function isControlPath(pathValue: string): boolean {
  return pathValue.startsWith("/_clawee/control");
}

function isChannelIngressPath(pathValue: string): boolean {
  return pathValue.startsWith("/_clawee/channel/");
}

function parseBearerToken(value: string | undefined): string {
  if (!value) {
    return "";
  }
  if (value.startsWith("Bearer ")) {
    return value.slice("Bearer ".length).trim();
  }
  return value.trim();
}

function controlTokenFromRequest(req: Request): string {
  const authHeader = parseBearerToken(req.header("authorization"));
  if (authHeader) {
    return authHeader;
  }
  return req.header("x-control-token")?.trim() || "";
}

function channelAuthorized(req: Request, token: string): boolean {
  const authHeader = parseBearerToken(req.header("authorization"));
  const tokenHeader = req.header("x-channel-token")?.trim() || "";
  return authHeader === token || tokenHeader === token;
}

function intakeAuthorized(req: Request, token: string): boolean {
  const authHeader = parseBearerToken(req.header("authorization"));
  const tokenHeader = req.header("x-intake-token")?.trim() || "";
  return authHeader === token || tokenHeader === token;
}

function openclawAuthorized(req: Request, token: string): boolean {
  const authHeader = parseBearerToken(req.header("authorization"));
  const tokenHeader = req.header("x-openclaw-token")?.trim() || "";
  return authHeader === token || tokenHeader === token;
}

interface ChannelHmacResult {
  ok: boolean;
  reason: string;
  nonceMaterial?: string;
}

function verifyChannelHmac(req: Request, secret: string, maxSkewSeconds: number): ChannelHmacResult {
  const normalizedSecret = secret.trim();
  if (!normalizedSecret) {
    return { ok: true, reason: "hmac-disabled" };
  }
  const signatureRaw = (req.header("x-channel-signature") || "").trim();
  if (!signatureRaw) {
    return { ok: false, reason: "missing-signature" };
  }

  const providedHex = signatureRaw.replace(/^sha256=/i, "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(providedHex)) {
    return { ok: false, reason: "invalid-signature-format" };
  }

  const rawBody = (req as Request & { rawBody?: string }).rawBody || "";
  const timestamp = (req.header("x-channel-timestamp") || "").trim();
  if (!timestamp.length) {
    return { ok: false, reason: "missing-timestamp" };
  }
  const payload = `${timestamp}.${rawBody}`;

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return { ok: false, reason: "invalid-timestamp" };
  }
  const timestampMs = ts > 1e12 ? ts : ts * 1000;
  const skewMs = Math.abs(Date.now() - timestampMs);
  if (skewMs > Math.max(1, maxSkewSeconds) * 1000) {
    return { ok: false, reason: "timestamp-skew-exceeded" };
  }

  const expectedHex = crypto.createHmac("sha256", normalizedSecret).update(payload).digest("hex");
  const provided = Buffer.from(providedHex, "hex");
  const expected = Buffer.from(expectedHex, "hex");
  if (provided.length !== expected.length) {
    return { ok: false, reason: "signature-length-mismatch" };
  }
  if (!crypto.timingSafeEqual(provided, expected)) {
    return { ok: false, reason: "signature-mismatch" };
  }
  return {
    ok: true,
    reason: "ok",
    nonceMaterial: `${req.path}|${timestamp}|${providedHex}`,
  };
}

interface IntakeHmacResult {
  ok: boolean;
  reason: string;
  nonceMaterial?: string;
}

function verifyIntakeHmac(req: Request, secret: string, maxSkewSeconds: number): IntakeHmacResult {
  const normalizedSecret = secret.trim();
  if (!normalizedSecret) {
    return { ok: true, reason: "hmac-disabled" };
  }
  const signatureRaw = (req.header("x-intake-signature") || "").trim();
  if (!signatureRaw) {
    return { ok: false, reason: "missing-signature" };
  }

  const providedHex = signatureRaw.replace(/^sha256=/i, "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(providedHex)) {
    return { ok: false, reason: "invalid-signature-format" };
  }

  const rawBody = (req as Request & { rawBody?: string }).rawBody || "";
  const timestamp = (req.header("x-intake-timestamp") || "").trim();
  if (!timestamp.length) {
    return { ok: false, reason: "missing-timestamp" };
  }
  const payload = `${timestamp}.${rawBody}`;

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return { ok: false, reason: "invalid-timestamp" };
  }
  const timestampMs = ts > 1e12 ? ts : ts * 1000;
  const skewMs = Math.abs(Date.now() - timestampMs);
  if (skewMs > Math.max(1, maxSkewSeconds) * 1000) {
    return { ok: false, reason: "timestamp-skew-exceeded" };
  }

  const expectedHex = crypto.createHmac("sha256", normalizedSecret).update(payload).digest("hex");
  const provided = Buffer.from(providedHex, "hex");
  const expected = Buffer.from(expectedHex, "hex");
  if (provided.length !== expected.length) {
    return { ok: false, reason: "signature-length-mismatch" };
  }
  if (!crypto.timingSafeEqual(provided, expected)) {
    return { ok: false, reason: "signature-mismatch" };
  }
  return {
    ok: true,
    reason: "ok",
    nonceMaterial: `${req.path}|${timestamp}|${providedHex}`,
  };
}

function verifyOpenclawHmac(req: Request, secret: string, maxSkewSeconds: number): IntakeHmacResult {
  const normalizedSecret = secret.trim();
  if (!normalizedSecret) {
    return { ok: true, reason: "hmac-disabled" };
  }
  const signatureRaw = (req.header("x-openclaw-signature") || "").trim();
  if (!signatureRaw) {
    return { ok: false, reason: "missing-signature" };
  }

  const providedHex = signatureRaw.replace(/^sha256=/i, "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(providedHex)) {
    return { ok: false, reason: "invalid-signature-format" };
  }

  const rawBody = (req as Request & { rawBody?: string }).rawBody || "";
  const timestamp = (req.header("x-openclaw-timestamp") || "").trim();
  if (!timestamp.length) {
    return { ok: false, reason: "missing-timestamp" };
  }
  const payload = `${timestamp}.${rawBody}`;

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return { ok: false, reason: "invalid-timestamp" };
  }
  const timestampMs = ts > 1e12 ? ts : ts * 1000;
  const skewMs = Math.abs(Date.now() - timestampMs);
  if (skewMs > Math.max(1, maxSkewSeconds) * 1000) {
    return { ok: false, reason: "timestamp-skew-exceeded" };
  }

  const expectedHex = crypto.createHmac("sha256", normalizedSecret).update(payload).digest("hex");
  const provided = Buffer.from(providedHex, "hex");
  const expected = Buffer.from(expectedHex, "hex");
  if (provided.length !== expected.length) {
    return { ok: false, reason: "signature-length-mismatch" };
  }
  if (!crypto.timingSafeEqual(provided, expected)) {
    return { ok: false, reason: "signature-mismatch" };
  }
  return {
    ok: true,
    reason: "ok",
    nonceMaterial: `${req.path}|${timestamp}|${providedHex}`,
  };
}

function parseChannelKind(raw: string): ChannelKind | null {
  const value = raw.trim().toLowerCase();
  if (value === "slack" || value === "teams" || value === "discord" || value === "email" || value === "webhook") {
    return value;
  }
  return null;
}

function extractIngressEventKey(req: Request): string {
  const headerEventId =
    (req.header("x-channel-event-id") || req.header("x-event-id") || "").trim().toLowerCase();
  const channel = String(req.params.channel || "").trim().toLowerCase();
  if (headerEventId) {
    return `${channel}|${headerEventId}`;
  }
  if (req.body && typeof req.body === "object") {
    const record = req.body as Record<string, unknown>;
    const bodyEventId = String(record.event_id || record.id || "").trim().toLowerCase();
    if (bodyEventId) {
      return `${channel}|${bodyEventId}`;
    }
  }
  return "";
}

function extractInitiativeIntakeEventKey(req: Request, providerEventId: string): string {
  const headerEventId = (req.header("x-intake-event-id") || req.header("x-event-id") || "")
    .trim()
    .toLowerCase();
  const provider = String(req.params.provider || "").trim().toLowerCase();
  if (headerEventId) {
    return `${provider}|${headerEventId}`;
  }
  const normalizedProviderEventId = providerEventId.trim().toLowerCase();
  if (normalizedProviderEventId) {
    return `${provider}|${normalizedProviderEventId}`;
  }
  return "";
}

function extractOpenclawEventKey(req: Request, providerEventId: string): string {
  const headerEventId = (req.header("x-openclaw-event-id") || req.header("x-event-id") || "")
    .trim()
    .toLowerCase();
  if (headerEventId) {
    return `openclaw|${headerEventId}`;
  }
  const normalizedProviderEventId = providerEventId.trim().toLowerCase();
  if (normalizedProviderEventId) {
    return `openclaw|${normalizedProviderEventId}`;
  }
  if (req.body && typeof req.body === "object") {
    const record = req.body as Record<string, unknown>;
    const bodyEventId = String(record.event_id || record.id || "").trim().toLowerCase();
    if (bodyEventId) {
      return `openclaw|${bodyEventId}`;
    }
  }
  return "";
}

function requestFingerprint(req: Request): string {
  return sha256Hex(`${req.method}|${req.originalUrl}|${stableStringify(req.body)}`);
}

function approvalHeader(req: Request): string {
  return (req.header("x-clawee-approval-id") || "").trim();
}

function parseActualUsage(payload: unknown): { inputTokens: number; outputTokens: number; model: string } | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  const record = payload as Record<string, unknown>;
  const usage = (record.usage || {}) as Record<string, unknown>;
  const inputTokens =
    typeof usage.input_tokens === "number"
      ? usage.input_tokens
      : typeof usage.prompt_tokens === "number"
        ? usage.prompt_tokens
        : 0;
  const outputTokens =
    typeof usage.output_tokens === "number"
      ? usage.output_tokens
      : typeof usage.completion_tokens === "number"
        ? usage.completion_tokens
        : 0;

  if (inputTokens <= 0 && outputTokens <= 0) {
    return null;
  }

  return {
    inputTokens: Math.max(0, Math.floor(inputTokens)),
    outputTokens: Math.max(0, Math.floor(outputTokens)),
    model: typeof record.model === "string" && record.model ? record.model : "unknown-model",
  };
}

export async function startUncertaintyGate(
  options: UncertaintyGateOptions,
  ledger: AuditLedger,
  riskEvaluator: RiskEvaluator,
  budgetController: BudgetController,
  modelRegistry: ModelRegistry,
  runtimeEgressGuard: RuntimeEgressGuard,
  approvalPolicy: ApprovalPolicyEngine,
  capabilityPolicy: CapabilityPolicyEngine,
  policyEngine: PolicyEngine,
  approvalService: ApprovalService,
  alertNotifier: AlertNotifier,
  modalityHub: ModalityHub,
  channelHub: ChannelHub,
  interactionStore: InteractionStore,
  replayStore: ReplayStore,
  channelDeliveryService: ChannelDeliveryService,
  channelDestinationPolicy: ChannelDestinationPolicy,
  approvalAttestationService: ApprovalAttestationService,
  auditAttestationService: AuditAttestationService,
  invariantRegistry: SecurityInvariantRegistry,
  securityConformanceService: SecurityConformanceService,
  reloadHandlers?: {
    reloadPolicyCatalog?: () => { fingerprint: string };
    reloadModelRegistry?: () => { fingerprint: string };
    reloadApprovalPolicyCatalog?: () => { fingerprint: string };
    reloadCapabilityCatalog?: () => { fingerprint: string };
  },
  initiativeService?: InitiativeControlService,
  vdiService?: VdiService,
): Promise<UncertaintyGateService> {
  const app = express();
  const sendAlert = async (
    event: string,
    severity: "info" | "warning" | "critical",
    message: string,
    details?: Record<string, unknown>,
  ) => {
    try {
      await alertNotifier.send({
        event,
        severity,
        message,
        details,
      });
    } catch (error) {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "alert-notifier",
        event,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  };
  const persistInteraction = (
    stage: string,
    fn: () => void,
    context: Record<string, unknown>,
  ) => {
    try {
      fn();
    } catch (error) {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage,
        context,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  };
  const invariantCheck = (input: {
    id: string;
    passed: boolean;
    reason?: string;
    context?: Record<string, unknown>;
    securityDecisionId?: string;
  }): boolean => {
    invariantRegistry.check({
      id: input.id,
      passed: input.passed,
      reason: input.reason,
      context: input.context,
    });
    if (!input.passed) {
      ledger.logAndSignAction("SECURITY_INVARIANT_VIOLATION", {
        invariant_id: input.id,
        reason: input.reason || "invariant failed",
        context: input.context || null,
        security_decision_id: input.securityDecisionId || null,
      });
      return options.securityInvariantsEnforcement !== "block";
    }
    return true;
  };

  app.use(
    express.json({
      limit: "10mb",
      verify: (req, _res, buf) => {
        (req as Request & { rawBody?: string }).rawBody = buf.toString("utf8");
      },
    }),
  );
  app.use(express.urlencoded({ extended: true }));
  const controlLimiter = new FixedWindowRateLimiter(
    options.controlRateLimitWindowSeconds,
    options.controlRateLimitMaxRequests,
  );
  const channelLimiter = new FixedWindowRateLimiter(
    options.channelIngressRateLimitWindowSeconds,
    options.channelIngressRateLimitMaxRequests,
  );
  const modalityPayloadValidation: ModalityPayloadValidationOptions = {
    maxPayloadBytes: {
      text: Math.max(256, Math.floor(options.modalityTextMaxPayloadBytes)),
      vision: Math.max(1024, Math.floor(options.modalityVisionMaxPayloadBytes)),
      audio: Math.max(1024, Math.floor(options.modalityAudioMaxPayloadBytes)),
      action: Math.max(256, Math.floor(options.modalityActionMaxPayloadBytes)),
    },
    textMaxChars: Math.max(32, Math.floor(options.modalityTextMaxChars)),
  };
  const initiativeIntakeEnabled =
    options.initiativeIntakeEnabled === true &&
    Boolean(options.initiativeIntakeToken && options.initiativeIntakeToken.trim());
  const initiativeIntakeToken = String(options.initiativeIntakeToken || "").trim();
  const initiativeIntakeHmacSecret = String(options.initiativeIntakeHmacSecret || "").trim();
  const initiativeIntakeMaxSkewSeconds = Math.max(
    1,
    Math.floor(Number(options.initiativeIntakeMaxSkewSeconds || 300)),
  );
  const initiativeIntakeEventTtlSeconds = Math.max(
    60,
    Math.floor(Number(options.initiativeIntakeEventTtlSeconds || 86400)),
  );
  const openclawIntakeEnabled =
    options.openclawIntakeEnabled === true &&
    Boolean(options.openclawIntakeToken && options.openclawIntakeToken.trim());
  const openclawIntakeToken = String(options.openclawIntakeToken || "").trim();
  const openclawIntakeHmacSecret = String(options.openclawIntakeHmacSecret || "").trim();
  const openclawIntakeMaxSkewSeconds = Math.max(
    1,
    Math.floor(Number(options.openclawIntakeMaxSkewSeconds || 300)),
  );
  const openclawIntakeEventTtlSeconds = Math.max(
    60,
    Math.floor(Number(options.openclawIntakeEventTtlSeconds || 86400)),
  );
  let openclawWorkItemsIngestedTotal = 0;
  let openclawWorkItemsReplayedTotal = 0;
  let openclawWorkItemsDedupedTotal = 0;
  let openclawLastHeartbeatAt: string | null = null;

  const controlAuth =
    (permission: ControlPermission): RequestHandler =>
    (req, res, next) => {
      const rateKey = `control:${req.ip || "unknown"}`;
      const rateDecision = controlLimiter.check(rateKey);
      if (!rateDecision.allowed) {
        ledger.logAndSignAction("RATE_LIMIT_BLOCKED", {
          path: req.originalUrl,
          method: req.method,
          scope: "control",
          retry_after_seconds: rateDecision.retryAfterSeconds,
        });
        res.setHeader("retry-after", String(rateDecision.retryAfterSeconds));
        res.status(429).json({ error: "Control rate limit exceeded." });
        return;
      }
      const token = controlTokenFromRequest(req);
      const identity = options.controlAuthz.authenticate(token);
      if (!identity) {
        ledger.logAndSignAction("CONTROL_ACCESS_DENIED", {
          path: req.originalUrl,
          method: req.method,
          permission,
        });
        res.status(401).json({ error: "Unauthorized control request." });
        return;
      }
      if (!options.controlAuthz.can(identity, permission)) {
        ledger.logAndSignAction("CONTROL_SCOPE_DENIED", {
          path: req.originalUrl,
          method: req.method,
          principal: identity.principal,
          role: identity.role,
          permission,
        });
        res.status(403).json({ error: "Forbidden by control permission policy." });
        return;
      }
      (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity = identity;
      next();
    };
  const getInitiativeService = (res: express.Response): InitiativeControlService | null => {
    if (!initiativeService || !initiativeService.isEnabled()) {
      res.status(503).json({ error: "Initiative engine is not enabled." });
      return null;
    }
    return initiativeService;
  };
  const getVdiService = (res: express.Response): VdiService | null => {
    if (!vdiService || !vdiService.isEnabled()) {
      res.status(503).json({ error: "VDI runtime is not enabled." });
      return null;
    }
    return vdiService;
  };

  app.get("/_clawee/control/status", controlAuth("system.read"), (_req, res) => {
    const status = budgetController.getStatus();
    const controlAuthzState = options.controlAuthz.getState();
    const connectorState = channelDeliveryService.getConnectorState();
    const destinationPolicyState = channelDestinationPolicy.getState();
    const attestationSigning = approvalAttestationService.getSigningState();
    const auditAttestationSigning = auditAttestationService.getSigningState();
    const securityConformanceSigning = securityConformanceService.getSigningState();
    const securityInvariantsSummary = invariantRegistry.summary();
    const capabilityPolicyState = capabilityPolicy.getState();
    const approvalPolicyState = approvalPolicy.getState();
    const replayStoreState = replayStore.getState();
    const initiativeStats = initiativeService ? initiativeService.getStats() : { enabled: false };
    const vdiStats = vdiService ? vdiService.getStats() : { enabled: false };
    res.json({
      enforcement_mode: options.enforcementMode,
      node_id: options.nodeId,
      cluster_id: options.clusterId,
      warn_threshold: options.warnThreshold,
      risk_evaluator_fail_mode: options.riskEvaluatorFailMode,
      audit_startup_verify_mode: options.auditStartupVerifyMode,
      security_invariants_enforcement: options.securityInvariantsEnforcement,
      max_request_input_tokens: options.maxRequestInputTokens,
      max_request_output_tokens: options.maxRequestOutputTokens,
      channel_ingress_event_ttl_seconds: options.channelIngressEventTtlSeconds,
      channel_ingress_max_text_chars: options.channelIngressMaxTextChars,
      channel_max_outbound_chars: options.channelMaxOutboundChars,
      modality_text_max_chars: options.modalityTextMaxChars,
      modality_payload_max_bytes: {
        text: options.modalityTextMaxPayloadBytes,
        vision: options.modalityVisionMaxPayloadBytes,
        audio: options.modalityAudioMaxPayloadBytes,
        action: options.modalityActionMaxPayloadBytes,
      },
      approval_required_count: options.approvalRequiredCount,
      approval_max_uses: options.approvalMaxUses,
      model_registry_fingerprint: options.modelRegistryFingerprint,
      config_fingerprints: options.configFingerprints,
      budget: status,
      control_authz: controlAuthzState,
      channel_connectors: connectorState,
      channel_destination_policy: destinationPolicyState,
      approval_attestation_signing: attestationSigning,
      audit_attestation_signing: auditAttestationSigning,
      security_conformance_signing: securityConformanceSigning,
      security_invariants: {
        summary: securityInvariantsSummary,
        definition_hash: invariantRegistry.definitionHash(),
      },
      approval_policy: approvalPolicyState,
      capability_policy: capabilityPolicyState,
      replay_store: replayStoreState,
      initiatives: initiativeStats,
      vdi_runtime: vdiStats,
      initiative_intake: {
        enabled: initiativeIntakeEnabled,
        token_configured: Boolean(initiativeIntakeToken),
        hmac_enabled: Boolean(initiativeIntakeHmacSecret),
        max_skew_seconds: initiativeIntakeMaxSkewSeconds,
        event_ttl_seconds: initiativeIntakeEventTtlSeconds,
      },
      openclaw_adapter: {
        enabled: openclawIntakeEnabled,
        token_configured: Boolean(openclawIntakeToken),
        hmac_enabled: Boolean(openclawIntakeHmacSecret),
        max_skew_seconds: openclawIntakeMaxSkewSeconds,
        event_ttl_seconds: openclawIntakeEventTtlSeconds,
        work_items_ingested_total: openclawWorkItemsIngestedTotal,
        work_items_replayed_total: openclawWorkItemsReplayedTotal,
        work_items_deduped_total: openclawWorkItemsDedupedTotal,
        last_heartbeat_at: openclawLastHeartbeatAt,
      },
    });
  });

  app.post("/_clawee/control/resume", controlAuth("budget.control"), (req, res) => {
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const resumedBy = identity?.principal || "manual-operator";
    budgetController.resume(resumedBy);
    ledger.logAndSignAction("BUDGET_RESUMED", { resumed_by: resumedBy });
    res.json({ ok: true, status: budgetController.getStatus() });
  });

  app.post("/_clawee/control/suspend", controlAuth("budget.control"), (req, res) => {
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const reason = typeof req.body?.reason === "string" ? req.body.reason : "Manual suspension request.";
    budgetController.suspend(reason);
    ledger.logAndSignAction("BUDGET_SUSPENDED", {
      reason,
      source: "manual",
      principal: identity?.principal || "unknown",
    });
    res.json({ ok: true, status: budgetController.getStatus() });
  });

  app.get("/_clawee/control/approvals/pending", controlAuth("approvals.read"), (_req, res) => {
    const pending = approvalService.getPending();
    res.json({
      count: pending.length,
      approvals: pending,
    });
  });

  app.post("/_clawee/control/approvals/:id/approve", controlAuth("approvals.write"), (req, res) => {
    try {
      const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
      const actor = identity?.principal || "manual-operator";
      const existing = approvalService.getById(req.params.id);
      if (existing) {
        const metadata = parseApprovalMetadata(existing.metadata);
        const requestedBy = typeof metadata.requested_by === "string" ? metadata.requested_by : "";
        if (requestedBy && requestedBy === actor) {
          ledger.logAndSignAction("APPROVAL_CONFLICT_OF_INTEREST_DENIED", {
            approval_id: req.params.id,
            actor,
            requested_by: requestedBy,
          });
          res.status(409).json({
            error: "Approver cannot approve their own requested action.",
          });
          return;
        }
      }
      const row = approvalService.approve(req.params.id, actor, identity?.role || "unknown");
      const remaining = remainingApprovals(row);
      const missingRoles = missingRequiredRoles(row);
      if (row.status === "approved") {
        ledger.logAndSignAction("APPROVAL_GRANTED", {
          approval_id: row.id,
          actor,
          required_approvals: row.required_approvals,
          required_roles: parseRequiredRoles(row.required_roles),
          approval_actors: parseApprovalActors(row.approval_actors),
          approval_actor_roles: parseApprovalActorRoles(row.approval_actor_roles),
        });
        void sendAlert("approval_granted", "info", "High-risk approval was granted.", {
          approval_id: row.id,
          actor,
          required_approvals: row.required_approvals,
          required_roles: parseRequiredRoles(row.required_roles),
          approval_actors: parseApprovalActors(row.approval_actors),
          approval_actor_roles: parseApprovalActorRoles(row.approval_actor_roles),
        });
        res.json({
          ok: true,
          approval: row,
          remaining_approvals: remaining,
          missing_required_roles: missingRoles,
        });
        return;
      }
      ledger.logAndSignAction("APPROVAL_REQUIRED", {
        approval_id: row.id,
        actor,
        required_approvals: row.required_approvals,
        required_roles: parseRequiredRoles(row.required_roles),
        approval_actors: parseApprovalActors(row.approval_actors),
        approval_actor_roles: parseApprovalActorRoles(row.approval_actor_roles),
        remaining_approvals: remaining,
        missing_required_roles: missingRoles,
        stage: "partial-approval",
      });
      res.status(202).json({
        ok: false,
        pending: true,
        approval: row,
        remaining_approvals: remaining,
        missing_required_roles: missingRoles,
      });
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/approvals/:id/deny", controlAuth("approvals.write"), (req, res) => {
    try {
      const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
      const actor = identity?.principal || "manual-operator";
      const row = approvalService.deny(req.params.id, actor);
      ledger.logAndSignAction("APPROVAL_DENIED", {
        approval_id: row.id,
        actor,
      });
      void sendAlert("approval_denied", "warning", "High-risk approval was denied.", {
        approval_id: row.id,
        actor,
      });
      res.json({ ok: true, approval: row });
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/_clawee/control/audit/recent", controlAuth("audit.read"), (req, res) => {
    const rawLimit = Number(req.query.limit || 100);
    const limit = Number.isNaN(rawLimit) ? 100 : rawLimit;
    res.json({
      count: Math.min(Math.max(1, Math.floor(limit)), 1000),
      events: ledger.getRecent(limit),
    });
  });

  app.get("/_clawee/control/audit/verify", controlAuth("audit.read"), (_req, res) => {
    const report = ledger.verifyIntegrity();
    res.status(report.valid ? 200 : 409).json({
      ok: report.valid,
      report,
    });
  });

  app.get("/_clawee/control/security/invariants", controlAuth("system.read"), (_req, res) => {
    res.json({
      enforcement_mode: options.securityInvariantsEnforcement,
      definition_hash: invariantRegistry.definitionHash(),
      summary: invariantRegistry.summary(),
      invariants: invariantRegistry.list(),
    });
  });

  app.post("/_clawee/control/security/conformance/export", controlAuth("audit.read"), (req, res) => {
    try {
      const payload = securityConformanceService.generate({
        invariantCatalogHash: invariantRegistry.definitionHash(),
        summary: invariantRegistry.summary(),
        invariants: invariantRegistry.list(),
      });
      const reportPath = typeof req.body?.report_path === "string" ? req.body.report_path : "";
      const chainPath = typeof req.body?.chain_path === "string" ? req.body.chain_path : "";
      const exported = securityConformanceService.exportSealedSnapshot(payload, {
        reportPath,
        chainPath,
      });
      ledger.logAndSignAction("SECURITY_CONFORMANCE_EXPORTED", {
        report_path: exported.report_path,
        chain_path: exported.chain_path,
        report_hash: exported.report_hash,
        current_hash: exported.current_hash,
        previous_hash: exported.previous_hash,
      });
      res.json({
        ok: true,
        ...exported,
      });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/security/conformance/verify", controlAuth("audit.read"), (req, res) => {
    const reportPath = typeof req.body?.report_path === "string" ? req.body.report_path : "";
    const chainPath = typeof req.body?.chain_path === "string" ? req.body.chain_path : "";
    if (!reportPath) {
      res.status(400).json({ error: "report_path is required." });
      return;
    }
    try {
      const snapshot = securityConformanceService.verifySnapshotFile(reportPath);
      const chain = chainPath
        ? securityConformanceService.verifySealedChain(chainPath, { verifySnapshots: true })
        : null;
      const valid = snapshot.valid && (chain ? chain.valid : true);
      ledger.logAndSignAction("SECURITY_CONFORMANCE_VERIFIED", {
        report_path: reportPath,
        chain_path: chainPath || null,
        valid,
        snapshot_valid: snapshot.valid,
        chain_valid: chain?.valid ?? null,
      });
      res.status(valid ? 200 : 409).json({
        ok: valid,
        snapshot,
        chain,
      });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/_clawee/control/audit/attestation", controlAuth("audit.read"), (req, res) => {
    const rawLimit = Number(req.query.limit || 1000);
    const limit = Number.isNaN(rawLimit) ? 1000 : rawLimit;
    const since = typeof req.query.since === "string" ? req.query.since : "";
    const payload = auditAttestationService.generate(limit, since);
    ledger.logAndSignAction("AUDIT_ATTESTATION_GENERATED", {
      count: payload.count,
      final_hash: payload.final_hash,
      since: payload.since,
    });
    res.json(payload);
  });

  app.post("/_clawee/control/audit/attestation/export", controlAuth("audit.read"), (req, res) => {
    const rawLimit = Number(req.body?.limit || 1000);
    const limit = Number.isNaN(rawLimit) ? 1000 : rawLimit;
    const since = typeof req.body?.since === "string" ? req.body.since : "";
    const snapshotPath = typeof req.body?.snapshot_path === "string" ? req.body.snapshot_path : "";
    const chainPath = typeof req.body?.chain_path === "string" ? req.body.chain_path : "";
    const result = auditAttestationService.exportSealedSnapshot({
      snapshotPath,
      chainPath,
      limit,
      since,
    });
    ledger.logAndSignAction("AUDIT_ATTESTATION_EXPORTED", result);
    res.json({ ok: true, ...result });
  });

  app.post("/_clawee/control/audit/attestation/verify", controlAuth("audit.read"), (req, res) => {
    const snapshotPath = typeof req.body?.snapshot_path === "string" ? req.body.snapshot_path : "";
    const chainPath = typeof req.body?.chain_path === "string" ? req.body.chain_path : "";
    if (!snapshotPath) {
      res.status(400).json({ error: "snapshot_path is required." });
      return;
    }
    try {
      const snapshot = auditAttestationService.verifySnapshotFile(snapshotPath);
      const chain = chainPath
        ? auditAttestationService.verifySealedChain(chainPath, { verifySnapshots: true })
        : null;
      const valid = snapshot.valid && (chain ? chain.valid : true);
      ledger.logAndSignAction("AUDIT_ATTESTATION_VERIFIED", {
        snapshot_path: snapshotPath,
        chain_path: chainPath || null,
        valid,
        snapshot_valid: snapshot.valid,
        chain_valid: chain?.valid ?? null,
      });
      res.status(valid ? 200 : 409).json({
        ok: valid,
        snapshot,
        chain,
      });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/_clawee/control/channel/inbound", controlAuth("channel.read"), (req, res) => {
    const rawLimit = Number(req.query.limit || 100);
    const limit = Number.isNaN(rawLimit) ? 100 : rawLimit;
    res.json({
      events: channelHub.listInbound(limit),
    });
  });

  app.get("/_clawee/control/channel/outbound", controlAuth("channel.read"), (req, res) => {
    const rawLimit = Number(req.query.limit || 100);
    const limit = Number.isNaN(rawLimit) ? 100 : rawLimit;
    res.json({
      messages: channelHub.listOutbound(limit),
    });
  });

  app.get("/_clawee/control/channel/delivery", controlAuth("channel.read"), (req, res) => {
    const rawLimit = Number(req.query.limit || 100);
    const limit = Number.isNaN(rawLimit) ? 100 : rawLimit;
    res.json({
      deliveries: interactionStore.listDeliveries(limit),
    });
  });

  app.post("/_clawee/control/channel/delivery/:id/retry", controlAuth("channel.delivery.retry"), (req, res) => {
    const ok = interactionStore.forceRetry(req.params.id);
    if (!ok) {
      res.status(404).json({ error: "Delivery message not found." });
      return;
    }
    ledger.logAndSignAction("CHANNEL_DELIVERY_RETRY_FORCED", {
      message_id: req.params.id,
    });
    res.json({ ok: true });
  });

  app.post("/_clawee/control/channel/reload-connectors", controlAuth("channel.connector.reload"), (_req, res) => {
    try {
      channelDeliveryService.reloadConnectors();
      const state = channelDeliveryService.getConnectorState();
      ledger.logAndSignAction("CHANNEL_CONNECTOR_CATALOG_RELOADED", state);
      res.json({ ok: true, ...state });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/_clawee/control/initiatives", controlAuth("initiative.read"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const rawLimit = Number(req.query.limit || 100);
    const statusRaw = String(req.query.status || "").trim().toLowerCase();
    const sourceRaw = String(req.query.source || "").trim().toLowerCase();
    const priorityRaw = String(req.query.priority || "").trim().toLowerCase();
    const status =
      statusRaw && ["pending", "running", "paused", "completed", "cancelled", "failed"].includes(statusRaw)
        ? (statusRaw as "pending" | "running" | "paused" | "completed" | "cancelled" | "failed")
        : undefined;
    const priority =
      priorityRaw && ["low", "normal", "high", "urgent"].includes(priorityRaw)
        ? (priorityRaw as "low" | "normal" | "high" | "urgent")
        : undefined;
    const initiatives = svc.listInitiatives({
      status,
      source: sourceRaw || undefined,
      priority,
      limit: Number.isFinite(rawLimit) ? rawLimit : 100,
    });
    res.json({
      count: initiatives.length,
      initiatives,
    });
  });

  app.post("/_clawee/control/initiatives", controlAuth("initiative.write"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const source = String(req.body?.source || "manual").trim().toLowerCase();
    const title = String(req.body?.title || "").trim();
    if (!title) {
      res.status(400).json({ error: "Initiative title is required." });
      return;
    }
    const tasksRaw: unknown[] = Array.isArray(req.body?.tasks) ? (req.body.tasks as unknown[]) : [];
    const tasks = tasksRaw
      .filter(
        (task: unknown): task is Record<string, unknown> =>
          Boolean(task) && typeof task === "object" && !Array.isArray(task),
      )
      .map((row) => {
        return {
          task_type: String(row.task_type || "").trim().toLowerCase(),
          payload:
            row.payload && typeof row.payload === "object" && !Array.isArray(row.payload)
              ? (row.payload as Record<string, unknown>)
              : {},
          max_retries: Number(row.max_retries || 3),
        };
      })
      .filter((task: { task_type: string }) => task.task_type.length > 0);

    const priorityRaw = String(req.body?.priority || "").trim().toLowerCase();
    const riskClassRaw = String(req.body?.risk_class || "").trim().toLowerCase();
    const priority =
      priorityRaw && ["low", "normal", "high", "urgent"].includes(priorityRaw)
        ? (priorityRaw as "low" | "normal" | "high" | "urgent")
        : undefined;
    const riskClass =
      riskClassRaw && ["low", "medium", "high", "critical"].includes(riskClassRaw)
        ? (riskClassRaw as "low" | "medium" | "high" | "critical")
        : undefined;
    const created = svc.createInitiative({
      source,
      external_ref: String(req.body?.external_ref || "").trim() || undefined,
      title,
      description: String(req.body?.description || "").trim() || undefined,
      priority,
      risk_class: riskClass,
      metadata:
        req.body?.metadata && typeof req.body.metadata === "object" && !Array.isArray(req.body.metadata)
          ? (req.body.metadata as Record<string, unknown>)
          : {},
      requested_by: identity?.principal || "manual-operator",
      tasks,
    });
    res.status(created.created ? 201 : 200).json({
      ok: true,
      created: created.created,
      initiative: created.initiative,
      tasks: created.tasks,
    });
  });

  app.get("/_clawee/control/initiatives/:id/tasks", controlAuth("initiative.read"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const initiative = svc.getInitiative(req.params.id);
    if (!initiative) {
      res.status(404).json({ error: "Initiative not found." });
      return;
    }
    const tasks = svc.listInitiativeTasks(req.params.id);
    res.json({
      initiative,
      count: tasks.length,
      tasks,
    });
  });

  app.get("/_clawee/control/initiatives/:id/events", controlAuth("initiative.read"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const initiative = svc.getInitiative(req.params.id);
    if (!initiative) {
      res.status(404).json({ error: "Initiative not found." });
      return;
    }
    const rawLimit = Number(req.query.limit || 200);
    const events = svc.listInitiativeEvents(
      req.params.id,
      Number.isFinite(rawLimit) ? rawLimit : 200,
    );
    res.json({
      initiative,
      count: events.length,
      events,
    });
  });

  app.post("/_clawee/control/initiatives/:id/start", controlAuth("initiative.write"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    try {
      const initiative = svc.startInitiative(req.params.id, identity?.principal || "manual-operator");
      res.json({ ok: true, initiative });
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/initiatives/:id/pause", controlAuth("initiative.write"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const reason = String(req.body?.reason || "").trim();
    try {
      const initiative = svc.pauseInitiative(
        req.params.id,
        identity?.principal || "manual-operator",
        reason,
      );
      res.json({ ok: true, initiative });
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/initiatives/:id/cancel", controlAuth("initiative.write"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const reason = String(req.body?.reason || "").trim();
    try {
      const initiative = svc.cancelInitiative(
        req.params.id,
        identity?.principal || "manual-operator",
        reason,
      );
      res.json({ ok: true, initiative });
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/initiatives/:id/interrupt", controlAuth("initiative.write"), (req, res) => {
    const svc = getInitiativeService(res);
    if (!svc) {
      return;
    }
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const reason = String(req.body?.reason || "manual-interrupt").trim() || "manual-interrupt";
    try {
      const initiative = svc.interruptInitiative(
        req.params.id,
        identity?.principal || "manual-operator",
        reason,
      );
      res.json({ ok: true, initiative });
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/_clawee/control/metrics", controlAuth("system.read"), (_req, res) => {
    const uptimeSeconds = Math.floor(process.uptime());
    const controlAuthzState = options.controlAuthz.getState();
    const connectorState = channelDeliveryService.getConnectorState();
    const destinationPolicyState = channelDestinationPolicy.getState();
    const attestationSigning = approvalAttestationService.getSigningState();
    const auditAttestationSigning = auditAttestationService.getSigningState();
    const securityConformanceSigning = securityConformanceService.getSigningState();
    const securityInvariantsSummary = invariantRegistry.summary();
    const capabilityPolicyState = capabilityPolicy.getState();
    const approvalPolicyState = approvalPolicy.getState();
    const replayStoreState = replayStore.getState();
    const initiativeStats = initiativeService ? initiativeService.getStats() : { enabled: false };
    const vdiStats = vdiService ? vdiService.getStats() : { enabled: false };
    res.json({
      service: "claw-ee",
      node_id: options.nodeId,
      cluster_id: options.clusterId,
      uptime_seconds: uptimeSeconds,
      timestamp: new Date().toISOString(),
      risk_evaluator_fail_mode: options.riskEvaluatorFailMode,
      audit_startup_verify_mode: options.auditStartupVerifyMode,
      security_invariants_enforcement: options.securityInvariantsEnforcement,
      max_request_input_tokens: options.maxRequestInputTokens,
      max_request_output_tokens: options.maxRequestOutputTokens,
      channel_ingress_event_ttl_seconds: options.channelIngressEventTtlSeconds,
      channel_ingress_max_text_chars: options.channelIngressMaxTextChars,
      channel_max_outbound_chars: options.channelMaxOutboundChars,
      modality_text_max_chars: options.modalityTextMaxChars,
      modality_payload_max_bytes: {
        text: options.modalityTextMaxPayloadBytes,
        vision: options.modalityVisionMaxPayloadBytes,
        audio: options.modalityAudioMaxPayloadBytes,
        action: options.modalityActionMaxPayloadBytes,
      },
      approval_required_count: options.approvalRequiredCount,
      approval_max_uses: options.approvalMaxUses,
      config_fingerprints: options.configFingerprints,
      budget: budgetController.getStatus(),
      approvals: approvalService.getStats(),
      channels: channelHub.stats(),
      modalities: modalityHub.stats(),
      interactions: interactionStore.counts(),
      audit: {
        total_events: ledger.getCount(),
      },
      control_authz: controlAuthzState,
      channel_connectors: connectorState,
      channel_destination_policy: destinationPolicyState,
      approval_attestation_signing: attestationSigning,
      audit_attestation_signing: auditAttestationSigning,
      security_conformance_signing: securityConformanceSigning,
      security_invariants: {
        summary: securityInvariantsSummary,
        definition_hash: invariantRegistry.definitionHash(),
      },
      approval_policy: approvalPolicyState,
      capability_policy: capabilityPolicyState,
      replay_store: replayStoreState,
      initiatives: initiativeStats,
      vdi_runtime: vdiStats,
      initiative_intake: {
        enabled: initiativeIntakeEnabled,
        token_configured: Boolean(initiativeIntakeToken),
        hmac_enabled: Boolean(initiativeIntakeHmacSecret),
        max_skew_seconds: initiativeIntakeMaxSkewSeconds,
        event_ttl_seconds: initiativeIntakeEventTtlSeconds,
      },
      openclaw_adapter: {
        enabled: openclawIntakeEnabled,
        token_configured: Boolean(openclawIntakeToken),
        hmac_enabled: Boolean(openclawIntakeHmacSecret),
        max_skew_seconds: openclawIntakeMaxSkewSeconds,
        event_ttl_seconds: openclawIntakeEventTtlSeconds,
        work_items_ingested_total: openclawWorkItemsIngestedTotal,
        work_items_replayed_total: openclawWorkItemsReplayedTotal,
        work_items_deduped_total: openclawWorkItemsDedupedTotal,
        last_heartbeat_at: openclawLastHeartbeatAt,
      },
      process: {
        pid: process.pid,
        memory_rss: process.memoryUsage().rss,
        memory_heap_used: process.memoryUsage().heapUsed,
      },
    });
  });

  app.post("/_clawee/control/reload/policies", controlAuth("policy.reload"), (_req, res) => {
    if (!reloadHandlers?.reloadPolicyCatalog) {
      res.status(400).json({ error: "Policy reload handler is not configured." });
      return;
    }
    try {
      const result = reloadHandlers.reloadPolicyCatalog();
      ledger.logAndSignAction("POLICY_CATALOG_RELOADED", {
        fingerprint: result.fingerprint,
      });
      res.json({ ok: true, fingerprint: result.fingerprint });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/reload/approval-policy", controlAuth("policy.reload"), (_req, res) => {
    if (!reloadHandlers?.reloadApprovalPolicyCatalog) {
      res.status(400).json({ error: "Approval policy reload handler is not configured." });
      return;
    }
    try {
      const result = reloadHandlers.reloadApprovalPolicyCatalog();
      ledger.logAndSignAction("APPROVAL_POLICY_RELOADED", {
        fingerprint: result.fingerprint,
      });
      res.json({ ok: true, fingerprint: result.fingerprint });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/reload/capability-policy", controlAuth("policy.reload"), (_req, res) => {
    if (!reloadHandlers?.reloadCapabilityCatalog) {
      res.status(400).json({ error: "Capability policy reload handler is not configured." });
      return;
    }
    try {
      const result = reloadHandlers.reloadCapabilityCatalog();
      ledger.logAndSignAction("CAPABILITY_CATALOG_RELOADED", {
        fingerprint: result.fingerprint,
      });
      res.json({ ok: true, fingerprint: result.fingerprint });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/reload/model-registry", controlAuth("model.reload"), (_req, res) => {
    if (!reloadHandlers?.reloadModelRegistry) {
      res.status(400).json({ error: "Model registry reload handler is not configured." });
      return;
    }
    try {
      const result = reloadHandlers.reloadModelRegistry();
      ledger.logAndSignAction("MODEL_REGISTRY_RELOADED", {
        fingerprint: result.fingerprint,
      });
      res.json({ ok: true, fingerprint: result.fingerprint });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/reload/control-tokens", controlAuth("authz.reload"), (_req, res) => {
    try {
      const state = options.controlAuthz.reload();
      ledger.logAndSignAction("CONTROL_TOKEN_CATALOG_RELOADED", state);
      res.json({ ok: true, ...state });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post(
    "/_clawee/control/reload/channel-destination-policy",
    controlAuth("channel.destination.reload"),
    (_req, res) => {
      try {
        const state = channelDestinationPolicy.reload();
        ledger.logAndSignAction("CHANNEL_DESTINATION_POLICY_RELOADED", state);
        res.json({ ok: true, ...state });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
      }
    },
  );

  app.get("/_clawee/control/approvals/attestation", controlAuth("approvals.export"), (req, res) => {
    const rawLimit = Number(req.query.limit || 1000);
    const limit = Number.isNaN(rawLimit) ? 1000 : rawLimit;
    const since = typeof req.query.since === "string" ? req.query.since : "";
    const payload = approvalAttestationService.generate(limit, since);
    ledger.logAndSignAction("APPROVAL_ATTESTATION_GENERATED", {
      count: payload.count,
      final_hash: payload.final_hash,
      since: payload.since,
    });
    res.json(payload);
  });

  app.post("/_clawee/control/approvals/attestation/export", controlAuth("approvals.export"), (req, res) => {
    const rawLimit = Number(req.body?.limit || 1000);
    const limit = Number.isNaN(rawLimit) ? 1000 : rawLimit;
    const since = typeof req.body?.since === "string" ? req.body.since : "";
    const snapshotPath = typeof req.body?.snapshot_path === "string" ? req.body.snapshot_path : "";
    const chainPath = typeof req.body?.chain_path === "string" ? req.body.chain_path : "";
    const result = approvalAttestationService.exportSealedSnapshot({
      snapshotPath,
      chainPath,
      limit,
      since,
    });
    ledger.logAndSignAction("APPROVAL_ATTESTATION_EXPORTED", result);
    res.json({ ok: true, ...result });
  });

  app.post("/_clawee/control/approvals/attestation/verify", controlAuth("approvals.verify"), (req, res) => {
    const snapshotPath = typeof req.body?.snapshot_path === "string" ? req.body.snapshot_path : "";
    const chainPath = typeof req.body?.chain_path === "string" ? req.body.chain_path : "";
    if (!snapshotPath) {
      res.status(400).json({ error: "snapshot_path is required." });
      return;
    }
    try {
      const snapshot = approvalAttestationService.verifySnapshotFile(snapshotPath);
      const chain = chainPath
        ? approvalAttestationService.verifySealedChain(chainPath, { verifySnapshots: true })
        : null;
      const valid = snapshot.valid && (chain ? chain.valid : true);
      ledger.logAndSignAction("APPROVAL_ATTESTATION_VERIFIED", {
        snapshot_path: snapshotPath,
        chain_path: chainPath || null,
        valid,
        snapshot_valid: snapshot.valid,
        chain_valid: chain?.valid ?? null,
      });
      res.json({
        ok: valid,
        snapshot,
        chain,
      });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post(
    "/_clawee/control/reload/approval-attestation-signing",
    controlAuth("approvals.verify"),
    (_req, res) => {
      try {
        const state = approvalAttestationService.reloadSigningKeys();
        ledger.logAndSignAction("APPROVAL_ATTESTATION_SIGNING_RELOADED", state);
        res.json({ ok: true, ...state });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
      }
    },
  );

  app.post("/_clawee/control/reload/audit-attestation-signing", controlAuth("audit.read"), (_req, res) => {
    try {
      const state = auditAttestationService.reloadSigningKeys();
      ledger.logAndSignAction("AUDIT_ATTESTATION_SIGNING_RELOADED", state);
      res.json({ ok: true, ...state });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/reload/security-conformance-signing", controlAuth("audit.read"), (_req, res) => {
    try {
      const state = securityConformanceService.reloadSigningKeys();
      res.json({ ok: true, ...state });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/_clawee/control/channel/send", controlAuth("channel.send"), (req, res) => {
    const identity = (req as Request & { controlIdentity?: ControlIdentity }).controlIdentity;
    const securityDecisionId = sha256Hex(
      `${Date.now()}|control-channel-send|${requestFingerprint(req)}`,
    );
    const channel = parseChannelKind(String(req.body?.channel || ""));
    const destination = typeof req.body?.destination === "string" ? req.body.destination : "";
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    if (!channel || !destination || !text) {
      res.status(400).json({ error: "Invalid channel send payload." });
      return;
    }
    if (text.length > Math.max(1, Math.floor(options.channelMaxOutboundChars))) {
      ledger.logAndSignAction("CHANNEL_MESSAGE_SIZE_BLOCKED", {
        channel,
        destination,
        text_length: text.length,
        max_allowed_chars: options.channelMaxOutboundChars,
      });
      res.status(413).json({
        error: "Blocked by Claw-EE outbound message size policy.",
        text_length: text.length,
        max_allowed_chars: options.channelMaxOutboundChars,
      });
      return;
    }
    const channelActionDecision = capabilityPolicy.evaluateChannelAction("channel.send", channel);
    if (!channelActionDecision.allowed) {
      invariantCheck({
        id: "INV-002-CAPABILITY-GATE",
        passed: true,
        reason: "channel send blocked by capability policy",
        context: {
          path: req.originalUrl,
          method: req.method,
          channel,
          action: "channel.send",
        },
        securityDecisionId,
      });
      ledger.logAndSignAction("CAPABILITY_BLOCKED_ACTION", {
        path: req.originalUrl,
        method: req.method,
        channel,
        action: "channel.send",
        reason: channelActionDecision.reason,
        matched_signals: channelActionDecision.matchedSignals,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "capability_blocked_action",
        "critical",
        "Claw-EE blocked outbound channel action by capability policy.",
        {
          path: req.originalUrl,
          method: req.method,
          channel,
          action: "channel.send",
          reason: channelActionDecision.reason,
          matched_signals: channelActionDecision.matchedSignals,
        },
      );
      res.status(403).json({
        error: "Blocked by Claw-EE capability policy.",
        reason: channelActionDecision.reason,
        matched_signals: channelActionDecision.matchedSignals,
      });
      return;
    }
    invariantCheck({
      id: "INV-002-CAPABILITY-GATE",
      passed: true,
      context: {
        path: req.originalUrl,
        method: req.method,
        channel,
        action: "channel.send",
      },
      securityDecisionId,
    });
    const destinationDecision = channelDestinationPolicy.evaluate(channel, destination);
    if (!destinationDecision.allowed) {
      invariantCheck({
        id: "INV-007-CHANNEL-DESTINATION-GATE",
        passed: true,
        reason: "destination policy blocked outbound channel",
        context: {
          stage: "queue",
          channel,
          destination,
        },
        securityDecisionId,
      });
      ledger.logAndSignAction("CHANNEL_DESTINATION_BLOCKED", {
        stage: "queue",
        channel,
        destination,
        reason: destinationDecision.reason,
        matched_pattern: destinationDecision.matched_pattern,
        source: destinationDecision.source,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "channel_destination_blocked",
        "warning",
        "Claw-EE blocked outbound channel destination by destination policy.",
        {
          channel,
          destination,
          reason: destinationDecision.reason,
          matched_pattern: destinationDecision.matched_pattern,
          source: destinationDecision.source,
        },
      );
      res.status(403).json({
        error: "Blocked by Claw-EE channel destination policy.",
        reason: destinationDecision.reason,
        matched_pattern: destinationDecision.matched_pattern,
      });
      return;
    }
    invariantCheck({
      id: "INV-007-CHANNEL-DESTINATION-GATE",
      passed: true,
      context: {
        stage: "queue",
        channel,
        destination,
      },
      securityDecisionId,
    });
    const policyDecision = policyEngine.evaluate({
      path: req.originalUrl,
      method: req.method,
      body: {
        channel,
        destination,
        text,
        metadata: (req.body?.metadata || {}) as Record<string, unknown>,
      },
      model: "control-plane",
      modality: "text",
      intent: { hasToolIntent: false, toolNames: [] },
    });
    invariantCheck({
      id: "INV-003-POLICY-GATE",
      passed: true,
      context: {
        path: req.originalUrl,
        method: req.method,
        decision: policyDecision.decision,
      },
      securityDecisionId,
    });
    let approvedRequest: { id: string; fingerprint: string } | null = null;
    if (policyDecision.decision === "block") {
      ledger.logAndSignAction("POLICY_BLOCKED_ACTION", {
        path: req.originalUrl,
        method: req.method,
        model: "control-plane",
        modality: "text",
        reason: policyDecision.reason,
        matched_signals: policyDecision.matchedSignals,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "policy_blocked_action",
        "critical",
        "Claw-EE blocked outbound channel message by policy.",
        {
          path: req.originalUrl,
          reason: policyDecision.reason,
          matched_signals: policyDecision.matchedSignals,
        },
      );
      res.status(403).json({
        error: "Blocked by Claw-EE policy engine.",
        reason: policyDecision.reason,
        matched_signals: policyDecision.matchedSignals,
      });
      return;
    }
    if (policyDecision.decision === "require_approval") {
      const approvalRequirements = approvalPolicy.evaluate({
        policyDecision,
        channel,
        action: "channel.send",
        toolNames: [],
      });
      const fingerprint = requestFingerprint(req);
      const approvalId = approvalHeader(req);
      const isApproved =
        approvalId.length > 0 && approvalService.validateApproved(approvalId, fingerprint);
      if (!isApproved) {
        const created = approvalService.getOrCreatePending({
          requestFingerprint: fingerprint,
          reason: policyDecision.reason,
          metadata: {
            path: req.originalUrl,
            method: req.method,
            channel,
            destination,
            signals: policyDecision.matchedSignals,
            requested_by: identity?.principal || "unknown",
            required_approvals: approvalRequirements.requiredApprovals,
            required_roles: approvalRequirements.requiredRoles,
          },
          ttlSeconds: options.approvalTtlSeconds,
          requiredApprovals: approvalRequirements.requiredApprovals,
          requiredRoles: approvalRequirements.requiredRoles,
          maxUses: options.approvalMaxUses,
        });
        invariantCheck({
          id: "INV-004-APPROVAL-GATE",
          passed: true,
          reason: "approval required and request blocked pending quorum",
          context: {
            path: req.originalUrl,
            method: req.method,
            approval_id: created.record.id,
          },
          securityDecisionId,
        });
        if (created.created) {
          ledger.logAndSignAction("APPROVAL_CREATED", {
            approval_id: created.record.id,
            reason: created.record.reason,
            expires_at: created.record.expires_at,
            security_decision_id: securityDecisionId,
          });
        }
        ledger.logAndSignAction("APPROVAL_REQUIRED", {
          approval_id: created.record.id,
          path: req.originalUrl,
          method: req.method,
          reason: policyDecision.reason,
          signals: policyDecision.matchedSignals,
          required_approvals: created.record.required_approvals,
          required_roles: parseRequiredRoles(created.record.required_roles),
          security_decision_id: securityDecisionId,
        });
        void sendAlert(
          "approval_required",
          "warning",
          "Claw-EE requires human approval for outbound channel message.",
          {
            approval_id: created.record.id,
            path: req.originalUrl,
            reason: policyDecision.reason,
            required_approvals: created.record.required_approvals,
            required_roles: parseRequiredRoles(created.record.required_roles),
          },
        );
        res.status(428).json({
          error: "Approval required by Claw-EE policy engine.",
          approval_id: created.record.id,
          expires_at: created.record.expires_at,
          reason: policyDecision.reason,
          required_approvals: created.record.required_approvals,
          required_roles: parseRequiredRoles(created.record.required_roles),
          max_uses: created.record.max_uses,
          use_count: created.record.use_count,
          current_approvals: parseApprovalActors(created.record.approval_actors).length,
          remaining_approvals: remainingApprovals(created.record),
          missing_required_roles: missingRequiredRoles(created.record),
        });
        return;
      }
      approvedRequest = {
        id: approvalId,
        fingerprint,
      };
      invariantCheck({
        id: "INV-004-APPROVAL-GATE",
        passed: true,
        context: {
          path: req.originalUrl,
          method: req.method,
          approval_id: approvalId,
          stage: "approved-request",
        },
        securityDecisionId,
      });
    }
    if (approvedRequest) {
      const consumed = approvalService.consumeApproved(
        approvedRequest.id,
        approvedRequest.fingerprint,
      );
      if (!consumed) {
        ledger.logAndSignAction("APPROVAL_TOKEN_REPLAY_BLOCKED", {
          approval_id: approvedRequest.id,
          path: req.originalUrl,
          method: req.method,
          security_decision_id: securityDecisionId,
        });
        res.status(428).json({
          error: "Approval token is expired or already consumed.",
        });
        return;
      }
      ledger.logAndSignAction("APPROVAL_GRANTED", {
        approval_id: approvedRequest.id,
        path: req.originalUrl,
        method: req.method,
        source: "request-header",
        security_decision_id: securityDecisionId,
      });
    }
    const queued = channelHub.queueOutbound({
      channel,
      destination,
      text,
      metadata: (req.body?.metadata || {}) as Record<string, unknown>,
      timestamp: typeof req.body?.timestamp === "string" ? req.body.timestamp : undefined,
    });
    ledger.logAndSignAction("CHANNEL_MESSAGE_QUEUED", {
      channel,
      destination,
      message_id: queued.id,
      security_decision_id: securityDecisionId,
    });
    persistInteraction("interaction-store:channel-outbound", () => {
      interactionStore.recordChannelOutbound(queued);
    }, { message_id: queued.id, channel, destination });
    res.json({ ok: true, message: queued });
  });

  app.post("/_clawee/control/modality/ingest", controlAuth("modality.write"), (req, res) => {
    const sessionId = nonEmptyStringWithMax(req.body?.session_id, MAX_MODALITY_SESSION_ID_CHARS);
    const modality = typeof req.body?.modality === "string" ? req.body.modality : "";
    const source = nonEmptyStringWithMax(req.body?.source, MAX_MODALITY_SOURCE_CHARS);
    if (!sessionId || !source || !["text", "vision", "audio", "action"].includes(modality)) {
      res.status(400).json({
        error: "Invalid modality observation payload.",
      });
      return;
    }
    const validation = validateModalityPayload(
      modality as ModalityType,
      req.body?.payload,
      modalityPayloadValidation,
    );
    if (!validation.ok || !validation.normalizedPayload) {
      ledger.logAndSignAction("MODALITY_PAYLOAD_BLOCKED", {
        path: req.originalUrl,
        reason: validation.reason,
        status_code: validation.statusCode,
        modality,
        payload_bytes: validation.payloadBytes,
        max_payload_bytes: validation.maxPayloadBytes,
      });
      res.status(validation.statusCode).json({
        error:
          validation.statusCode === 413
            ? "Modality payload exceeds configured size limits."
            : "Invalid modality payload schema.",
        reason: validation.reason,
        modality,
        payload_bytes: validation.payloadBytes,
        max_payload_bytes: validation.maxPayloadBytes,
      });
      return;
    }
    const observation = modalityHub.ingest({
      session_id: sessionId,
      modality: modality as ModalityType,
      source,
      payload: validation.normalizedPayload,
      timestamp: typeof req.body?.timestamp === "string" ? req.body.timestamp : undefined,
    });
    ledger.logAndSignAction("MODALITY_OBSERVATION", {
      observation_id: observation.id,
      session_id: observation.session_id,
      modality: observation.modality,
      source: observation.source,
    });
    persistInteraction(
      "interaction-store:modality-control",
      () => {
        interactionStore.recordModality(observation);
      },
      { observation_id: observation.id, session_id: observation.session_id },
    );
    res.json({ ok: true, observation });
  });

  app.post("/_clawee/control/vdi/session/start", controlAuth("initiative.write"), (req, res) => {
    void (async () => {
      const service = getVdiService(res);
      if (!service) {
        return;
      }
      try {
        const session = await service.startSession(req.body);
        ledger.logAndSignAction("VDI_SESSION_STARTED", {
          session_id: session.id,
          label: session.label,
          current_url: session.current_url || null,
        });
        res.json({ ok: true, session });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.toLowerCase().includes("allowlist policy")) {
          service.countBlockedStep();
          ledger.logAndSignAction("VDI_STEP_BLOCKED", {
            action: "session.start",
            reason: message,
          });
          res.status(403).json({ error: message });
          return;
        }
        ledger.logAndSignAction("SYSTEM_ERROR", {
          module: "uncertainty-gate",
          stage: "vdi-session-start",
          message,
        });
        res.status(500).json({ error: message });
      }
    })();
  });

  app.post("/_clawee/control/vdi/session/:id/step", controlAuth("initiative.write"), (req, res) => {
    void (async () => {
      const service = getVdiService(res);
      if (!service) {
        return;
      }
      const sessionId = String(req.params.id || "").trim();
      if (!sessionId) {
        res.status(400).json({ error: "VDI session id is required." });
        return;
      }
      try {
        const result = await service.executeStep(sessionId, req.body);
        ledger.logAndSignAction("VDI_STEP_EXECUTED", {
          session_id: sessionId,
          action: result.action,
          screenshot_path: result.screenshot_path || null,
        });
        if (result.screenshot_path) {
          ledger.logAndSignAction("VDI_ARTIFACT_CAPTURED", {
            session_id: sessionId,
            action: result.action,
            screenshot_path: result.screenshot_path,
          });
        }
        res.json({ ok: true, result });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.toLowerCase().includes("allowlist policy")) {
          service.countBlockedStep();
          ledger.logAndSignAction("VDI_STEP_BLOCKED", {
            session_id: sessionId,
            reason: message,
          });
          res.status(403).json({ error: message });
          return;
        }
        ledger.logAndSignAction("SYSTEM_ERROR", {
          module: "uncertainty-gate",
          stage: "vdi-step",
          session_id: sessionId,
          message,
        });
        res.status(500).json({ error: message });
      }
    })();
  });

  app.post("/_clawee/control/vdi/session/:id/stop", controlAuth("initiative.write"), (req, res) => {
    void (async () => {
      const service = getVdiService(res);
      if (!service) {
        return;
      }
      const sessionId = String(req.params.id || "").trim();
      if (!sessionId) {
        res.status(400).json({ error: "VDI session id is required." });
        return;
      }
      try {
        const reason = typeof req.body?.reason === "string" ? req.body.reason : "";
        const session = await service.stopSession(sessionId, reason);
        ledger.logAndSignAction("VDI_SESSION_STOPPED", {
          session_id: session.id,
          status: session.status,
          stopped_at: session.stopped_at,
          reason: reason || null,
        });
        res.json({ ok: true, session });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        ledger.logAndSignAction("SYSTEM_ERROR", {
          module: "uncertainty-gate",
          stage: "vdi-session-stop",
          session_id: sessionId,
          message,
        });
        res.status(500).json({ error: message });
      }
    })();
  });

  app.get("/_clawee/control/vdi/session/:id", controlAuth("initiative.read"), (req, res) => {
    void (async () => {
      const service = getVdiService(res);
      if (!service) {
        return;
      }
      const sessionId = String(req.params.id || "").trim();
      if (!sessionId) {
        res.status(400).json({ error: "VDI session id is required." });
        return;
      }
      try {
        const session = await service.getSession(sessionId);
        res.json({ ok: true, session });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        res.status(500).json({ error: message });
      }
    })();
  });

  app.get("/_clawee/control/vdi/session/:id/artifacts", controlAuth("initiative.read"), (req, res) => {
    void (async () => {
      const service = getVdiService(res);
      if (!service) {
        return;
      }
      const sessionId = String(req.params.id || "").trim();
      if (!sessionId) {
        res.status(400).json({ error: "VDI session id is required." });
        return;
      }
      try {
        const artifacts = await service.listArtifacts(sessionId);
        res.json({ ok: true, artifacts });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        res.status(500).json({ error: message });
      }
    })();
  });

  const openclawIntakeAuth: RequestHandler = (req, res, next) => {
    void (async () => {
      if (!openclawIntakeEnabled) {
        res.status(404).json({ error: "OpenClaw intake adapter is not enabled." });
        return;
      }
      const routeType = req.path.includes("/heartbeat") ? "heartbeat" : "work-item";
      const rateKey = `openclaw-intake:${req.ip || "unknown"}:${routeType}`;
      const rateDecision = channelLimiter.check(rateKey);
      if (!rateDecision.allowed) {
        ledger.logAndSignAction("RATE_LIMIT_BLOCKED", {
          path: req.originalUrl,
          method: req.method,
          scope: "openclaw-intake",
          route_type: routeType,
          retry_after_seconds: rateDecision.retryAfterSeconds,
        });
        res.setHeader("retry-after", String(rateDecision.retryAfterSeconds));
        res.status(429).json({ error: "OpenClaw intake rate limit exceeded." });
        return;
      }
      if (!openclawAuthorized(req, openclawIntakeToken)) {
        invariantCheck({
          id: "INV-008-INGRESS-AUTH-GATE",
          passed: true,
          reason: "openclaw intake unauthorized",
          context: {
            path: req.originalUrl,
            method: req.method,
            route_type: routeType,
            stage: "auth",
          },
        });
        ledger.logAndSignAction("CONTROL_ACCESS_DENIED", {
          path: req.originalUrl,
          method: req.method,
          route_type: routeType,
          openclaw_intake: true,
        });
        res.status(401).json({ error: "Unauthorized OpenClaw intake request." });
        return;
      }
      const signatureCheck = verifyOpenclawHmac(
        req,
        openclawIntakeHmacSecret,
        openclawIntakeMaxSkewSeconds,
      );
      if (!signatureCheck.ok) {
        invariantCheck({
          id: "INV-008-INGRESS-AUTH-GATE",
          passed: true,
          reason: signatureCheck.reason,
          context: {
            path: req.originalUrl,
            method: req.method,
            route_type: routeType,
            stage: "signature",
          },
        });
        ledger.logAndSignAction("OPENCLAW_INTAKE_SIGNATURE_DENIED", {
          path: req.originalUrl,
          method: req.method,
          route_type: routeType,
          reason: signatureCheck.reason,
        });
        res.status(401).json({ error: "Invalid OpenClaw intake signature." });
        return;
      }
      if (signatureCheck.nonceMaterial) {
        const nonceHash = sha256Hex(signatureCheck.nonceMaterial);
        const accepted = await replayStore.registerNonce(nonceHash, openclawIntakeMaxSkewSeconds);
        if (!accepted) {
          invariantCheck({
            id: "INV-008-INGRESS-AUTH-GATE",
            passed: true,
            reason: "openclaw intake nonce replay blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              route_type: routeType,
              stage: "nonce-replay",
            },
          });
          if (routeType === "work-item") {
            openclawWorkItemsReplayedTotal += 1;
          }
          ledger.logAndSignAction("OPENCLAW_INTAKE_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
            route_type: routeType,
            stage: "nonce",
          });
          res.status(409).json({ error: "Replay detected for OpenClaw intake request." });
          return;
        }
      }
      next();
    })().catch((error) => {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "openclaw-intake-auth",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: "OpenClaw intake auth failed." });
    });
  };

  app.post("/_clawee/intake/openclaw/work-item", openclawIntakeAuth, (req, res) => {
    void (async () => {
      const svc = getInitiativeService(res);
      if (!svc) {
        return;
      }
      const parsed = parseOpenClawWorkItem(req.body);
      if (!parsed.ok || !parsed.intake || !parsed.template) {
        ledger.logAndSignAction("OPENCLAW_INTAKE_SKIPPED", {
          reason: parsed.reason || "invalid payload",
          path: req.originalUrl,
        });
        res.status(400).json({
          error: "Invalid OpenClaw work-item payload.",
          reason: parsed.reason || "unknown",
        });
        return;
      }
      const eventKey = extractOpenclawEventKey(req, parsed.eventId);
      if (eventKey) {
        const eventKeyHash = sha256Hex(eventKey);
        const accepted = await replayStore.registerEventKey(eventKeyHash, openclawIntakeEventTtlSeconds);
        if (!accepted) {
          openclawWorkItemsReplayedTotal += 1;
          ledger.logAndSignAction("OPENCLAW_INTAKE_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
            stage: "event-id",
            event_key: eventKey,
          });
          res.status(409).json({ error: "Replay detected for OpenClaw intake event id." });
          return;
        }
      }
      ledger.logAndSignAction("OPENCLAW_INTAKE_RECEIVED", {
        event_id: parsed.eventId || null,
        source: parsed.intake.source,
        external_ref: parsed.intake.external_ref || null,
        dedupe_key: parsed.dedupeKey,
        template_id: parsed.template.template_id,
      });
      const created = svc.createInitiative(parsed.intake);
      let started = false;
      if (created.created) {
        try {
          svc.startInitiative(created.initiative.id, "intake:openclaw");
          started = true;
        } catch (error) {
          ledger.logAndSignAction("SYSTEM_ERROR", {
            module: "uncertainty-gate",
            stage: "openclaw-intake-start",
            initiative_id: created.initiative.id,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      } else {
        openclawWorkItemsDedupedTotal += 1;
      }
      openclawWorkItemsIngestedTotal += 1;
      ledger.logAndSignAction("OPENCLAW_INTAKE_CREATED", {
        created: created.created,
        started,
        initiative_id: created.initiative.id,
        external_ref: created.initiative.external_ref,
        event_id: parsed.eventId || null,
        dedupe_key: parsed.dedupeKey,
        template_id: parsed.template.template_id,
        template_version: parsed.template.template_version,
      });
      res.status(created.created ? 201 : 200).json({
        ok: true,
        provider: "openclaw",
        event_id: parsed.eventId || null,
        created: created.created,
        started,
        adapter: {
          provider: "openclaw",
          version: "1.0.0",
          mode: "http-gateway",
        },
        normalization: {
          template_id: parsed.template.template_id,
          template_version: parsed.template.template_version,
          dedupe_key: parsed.dedupeKey,
          created: created.created,
          started,
        },
        template: parsed.template,
        initiative: created.initiative,
        tasks: created.tasks,
      });
    })().catch((error) => {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "openclaw-intake-work-item",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: "OpenClaw work-item intake failed." });
    });
  });

  app.post("/_clawee/intake/openclaw/heartbeat", openclawIntakeAuth, (req, res) => {
    void (async () => {
      const parsed = parseOpenClawHeartbeat(req.body);
      if (!parsed.ok || !parsed.heartbeat) {
        ledger.logAndSignAction("OPENCLAW_INTAKE_SKIPPED", {
          reason: parsed.reason || "invalid heartbeat payload",
          path: req.originalUrl,
          stage: "heartbeat-parse",
        });
        res.status(400).json({
          error: "Invalid OpenClaw heartbeat payload.",
          reason: parsed.reason || "unknown",
        });
        return;
      }
      const eventKey = extractOpenclawEventKey(req, parsed.eventId);
      if (eventKey) {
        const eventKeyHash = sha256Hex(eventKey);
        const accepted = await replayStore.registerEventKey(eventKeyHash, openclawIntakeEventTtlSeconds);
        if (!accepted) {
          ledger.logAndSignAction("OPENCLAW_INTAKE_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
            stage: "heartbeat-event-id",
            event_key: eventKey,
          });
          res.status(409).json({ error: "Replay detected for OpenClaw heartbeat event id." });
          return;
        }
      }
      openclawLastHeartbeatAt = parsed.heartbeat.timestamp || new Date().toISOString();
      ledger.logAndSignAction("OPENCLAW_HEARTBEAT_RECEIVED", {
        event_id: parsed.eventId || null,
        agent_id: parsed.heartbeat.agent_id,
        status: parsed.heartbeat.status,
        active_task_id: parsed.heartbeat.active_task_id,
        queue_depth: parsed.heartbeat.queue_depth,
        timestamp: parsed.heartbeat.timestamp,
      });
      res.json({
        ok: true,
        provider: "openclaw",
        event_id: parsed.eventId || null,
        adapter: {
          provider: "openclaw",
          version: "1.0.0",
          mode: "http-gateway",
        },
        heartbeat: parsed.heartbeat,
      });
    })().catch((error) => {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "openclaw-intake-heartbeat",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: "OpenClaw heartbeat intake failed." });
    });
  });

  const initiativeIntakeAuth: RequestHandler = (req, res, next) => {
    void (async () => {
      if (!initiativeIntakeEnabled) {
        res.status(404).json({ error: "Initiative intake is not enabled." });
        return;
      }
      const provider = parseInitiativeProvider(String(req.params.provider || ""));
      if (!provider) {
        res.status(400).json({ error: "Unsupported intake provider." });
        return;
      }
      const rateKey = `initiative-intake:${req.ip || "unknown"}:${provider}`;
      const rateDecision = channelLimiter.check(rateKey);
      if (!rateDecision.allowed) {
        ledger.logAndSignAction("RATE_LIMIT_BLOCKED", {
          path: req.originalUrl,
          method: req.method,
          scope: "initiative-intake",
          provider,
          retry_after_seconds: rateDecision.retryAfterSeconds,
        });
        res.setHeader("retry-after", String(rateDecision.retryAfterSeconds));
        res.status(429).json({ error: "Initiative intake rate limit exceeded." });
        return;
      }
      if (!intakeAuthorized(req, initiativeIntakeToken)) {
        invariantCheck({
          id: "INV-008-INGRESS-AUTH-GATE",
          passed: true,
          reason: "initiative intake unauthorized",
          context: {
            path: req.originalUrl,
            method: req.method,
            provider,
            stage: "auth",
          },
        });
        ledger.logAndSignAction("CONTROL_ACCESS_DENIED", {
          path: req.originalUrl,
          method: req.method,
          provider,
          initiative_intake: true,
        });
        res.status(401).json({ error: "Unauthorized initiative intake request." });
        return;
      }
      const signatureCheck = verifyIntakeHmac(req, initiativeIntakeHmacSecret, initiativeIntakeMaxSkewSeconds);
      if (!signatureCheck.ok) {
        invariantCheck({
          id: "INV-008-INGRESS-AUTH-GATE",
          passed: true,
          reason: signatureCheck.reason,
          context: {
            path: req.originalUrl,
            method: req.method,
            provider,
            stage: "signature",
          },
        });
        ledger.logAndSignAction("INITIATIVE_INTAKE_SIGNATURE_DENIED", {
          path: req.originalUrl,
          method: req.method,
          provider,
          reason: signatureCheck.reason,
        });
        res.status(401).json({ error: "Invalid initiative intake signature." });
        return;
      }
      if (signatureCheck.nonceMaterial) {
        const nonceHash = sha256Hex(signatureCheck.nonceMaterial);
        const accepted = await replayStore.registerNonce(nonceHash, initiativeIntakeMaxSkewSeconds);
        if (!accepted) {
          invariantCheck({
            id: "INV-008-INGRESS-AUTH-GATE",
            passed: true,
            reason: "initiative intake nonce replay blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              provider,
              stage: "nonce-replay",
            },
          });
          ledger.logAndSignAction("INITIATIVE_INTAKE_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
            provider,
            stage: "nonce",
          });
          res.status(409).json({ error: "Replay detected for initiative intake request." });
          return;
        }
      }
      next();
    })().catch((error) => {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "initiative-intake-auth",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: "Initiative intake auth failed." });
    });
  };

  app.post("/_clawee/intake/:provider/webhook", initiativeIntakeAuth, (req, res) => {
    void (async () => {
      const provider = parseInitiativeProvider(String(req.params.provider || ""));
      if (!provider) {
        res.status(400).json({ error: "Unsupported intake provider." });
        return;
      }
      const svc = getInitiativeService(res);
      if (!svc) {
        return;
      }
      const parsed = parseInitiativeIntake(provider, req.body);
      if (!parsed.ok || !parsed.intake) {
        ledger.logAndSignAction("INITIATIVE_INTAKE_SKIPPED", {
          provider,
          reason: parsed.reason || "invalid payload",
          path: req.originalUrl,
        });
        res.status(400).json({
          error: "Invalid initiative intake payload.",
          reason: parsed.reason || "unknown",
        });
        return;
      }
      const eventKey = extractInitiativeIntakeEventKey(req, parsed.eventId);
      if (eventKey) {
        const eventKeyHash = sha256Hex(eventKey);
        const accepted = await replayStore.registerEventKey(eventKeyHash, initiativeIntakeEventTtlSeconds);
        if (!accepted) {
          ledger.logAndSignAction("INITIATIVE_INTAKE_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
            provider,
            stage: "event-id",
            event_key: eventKey,
          });
          res.status(409).json({ error: "Replay detected for initiative intake event id." });
          return;
        }
      }
      ledger.logAndSignAction("INITIATIVE_INTAKE_RECEIVED", {
        provider,
        event_id: parsed.eventId || null,
        source: parsed.intake.source,
        external_ref: parsed.intake.external_ref || null,
        template_id: parsed.template?.template_id || null,
      });
      const created = svc.createInitiative(parsed.intake);
      let started = false;
      if (created.created) {
        try {
          svc.startInitiative(created.initiative.id, `intake:${provider}`);
          started = true;
        } catch (error) {
          ledger.logAndSignAction("SYSTEM_ERROR", {
            module: "uncertainty-gate",
            stage: "initiative-intake-start",
            provider,
            initiative_id: created.initiative.id,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
      ledger.logAndSignAction("INITIATIVE_INTAKE_CREATED", {
        provider,
        created: created.created,
        started,
        initiative_id: created.initiative.id,
        external_ref: created.initiative.external_ref,
        event_id: parsed.eventId || null,
        template_id: parsed.template?.template_id || null,
        template_version: parsed.template?.template_version || null,
      });
      res.status(created.created ? 201 : 200).json({
        ok: true,
        provider,
        event_id: parsed.eventId || null,
        created: created.created,
        started,
        template: parsed.template,
        initiative: created.initiative,
        tasks: created.tasks,
      });
    })().catch((error) => {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "initiative-intake",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: "Initiative intake failed." });
    });
  });

  const channelIngestAuth: RequestHandler = (req, res, next) => {
    void (async () => {
      const rateKey = `channel:${req.ip || "unknown"}:${req.params.channel || "unknown"}`;
      const rateDecision = channelLimiter.check(rateKey);
      if (!rateDecision.allowed) {
        ledger.logAndSignAction("RATE_LIMIT_BLOCKED", {
          path: req.originalUrl,
          method: req.method,
          scope: "channel-ingress",
          retry_after_seconds: rateDecision.retryAfterSeconds,
        });
        res.setHeader("retry-after", String(rateDecision.retryAfterSeconds));
        res.status(429).json({ error: "Channel ingress rate limit exceeded." });
        return;
      }
      if (!channelAuthorized(req, options.channelIngestToken)) {
        ledger.logAndSignAction("CONTROL_ACCESS_DENIED", {
          path: req.originalUrl,
          method: req.method,
          channel_ingest: true,
        });
        res.status(401).json({ error: "Unauthorized channel ingest request." });
        return;
      }
      const signatureCheck = verifyChannelHmac(
        req,
        options.channelIngressHmacSecret,
        options.channelIngressMaxSkewSeconds,
      );
      if (!signatureCheck.ok) {
        invariantCheck({
          id: "INV-008-INGRESS-AUTH-GATE",
          passed: true,
          reason: signatureCheck.reason,
          context: {
            path: req.originalUrl,
            method: req.method,
            stage: "signature",
          },
        });
        ledger.logAndSignAction("CHANNEL_INGRESS_SIGNATURE_DENIED", {
          path: req.originalUrl,
          method: req.method,
          reason: signatureCheck.reason,
        });
        res.status(401).json({ error: "Invalid channel ingress signature." });
        return;
      }
      if (signatureCheck.nonceMaterial) {
        const nonceHash = sha256Hex(signatureCheck.nonceMaterial);
        const accepted = await replayStore.registerNonce(
          nonceHash,
          options.channelIngressMaxSkewSeconds,
        );
        if (!accepted) {
          invariantCheck({
            id: "INV-008-INGRESS-AUTH-GATE",
            passed: true,
            reason: "nonce replay blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              stage: "nonce-replay",
            },
          });
          ledger.logAndSignAction("CHANNEL_INGRESS_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
          });
          res.status(409).json({ error: "Replay detected for channel ingress request." });
          return;
        }
      }
      const eventKey = extractIngressEventKey(req);
      if (eventKey) {
        const eventKeyHash = sha256Hex(eventKey);
        const accepted = await replayStore.registerEventKey(
          eventKeyHash,
          options.channelIngressEventTtlSeconds,
        );
        if (!accepted) {
          invariantCheck({
            id: "INV-008-INGRESS-AUTH-GATE",
            passed: true,
            reason: "event replay blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              stage: "event-replay",
            },
          });
          ledger.logAndSignAction("CHANNEL_INGRESS_EVENT_REPLAY_BLOCKED", {
            path: req.originalUrl,
            method: req.method,
            channel: req.params.channel || "unknown",
          });
          res.status(409).json({ error: "Replay detected for channel event id." });
          return;
        }
      }
      const channel = parseChannelKind(req.params.channel || "");
      if (channel) {
        const channelActionDecision = capabilityPolicy.evaluateChannelAction("channel.ingest", channel);
        if (!channelActionDecision.allowed) {
          invariantCheck({
            id: "INV-002-CAPABILITY-GATE",
            passed: true,
            reason: "channel ingest capability blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              channel,
            },
          });
          ledger.logAndSignAction("CAPABILITY_BLOCKED_ACTION", {
            path: req.originalUrl,
            method: req.method,
            channel,
            action: "channel.ingest",
            reason: channelActionDecision.reason,
            matched_signals: channelActionDecision.matchedSignals,
          });
          res.status(403).json({
            error: "Blocked by Claw-EE capability policy.",
            reason: channelActionDecision.reason,
            matched_signals: channelActionDecision.matchedSignals,
          });
          return;
        }
        invariantCheck({
          id: "INV-002-CAPABILITY-GATE",
          passed: true,
          context: {
            path: req.originalUrl,
            method: req.method,
            channel,
            action: "channel.ingest",
          },
        });
      }
      invariantCheck({
        id: "INV-008-INGRESS-AUTH-GATE",
        passed: true,
        context: {
          path: req.originalUrl,
          method: req.method,
          stage: "accepted",
        },
      });
      next();
    })().catch((error) => {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "channel-ingest-auth",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: "Channel ingest auth failed." });
    });
  };

  app.post("/_clawee/channel/:channel/inbound", channelIngestAuth, (req, res) => {
    const channel = parseChannelKind(req.params.channel || "");
    const source = nonEmptyStringWithMax(req.body?.source, MAX_CHANNEL_SOURCE_CHARS);
    const sender = nonEmptyStringWithMax(req.body?.sender, MAX_CHANNEL_SENDER_CHARS);
    const textLimit = Math.max(1, options.channelIngressMaxTextChars);
    const rawText = typeof req.body?.text === "string" ? req.body.text : "";
    if (rawText.length > textLimit) {
      ledger.logAndSignAction("CHANNEL_INGRESS_PAYLOAD_BLOCKED", {
        path: req.originalUrl,
        channel: req.params.channel || "unknown",
        reason: "text length exceeds limit",
        status_code: 413,
        text_chars: rawText.length,
        max_text_chars: textLimit,
      });
      res.status(413).json({
        error: "Inbound channel payload exceeds configured size limits.",
        reason: `Field "text" exceeds ${textLimit} characters.`,
      });
      return;
    }
    const text = nonEmptyStringWithMax(rawText, textLimit);
    if (!channel || !source || !sender || !text) {
      res.status(400).json({ error: "Invalid inbound channel payload." });
      return;
    }
    const metadata = req.body?.metadata ?? {};
    if (!isPlainObject(metadata)) {
      res.status(400).json({ error: "Invalid inbound channel payload metadata." });
      return;
    }
    const textPayloadValidation = validateModalityPayload(
      "text",
      {
        sender,
        text,
        metadata,
      },
      modalityPayloadValidation,
    );
    if (!textPayloadValidation.ok || !textPayloadValidation.normalizedPayload) {
      ledger.logAndSignAction("CHANNEL_INGRESS_PAYLOAD_BLOCKED", {
        path: req.originalUrl,
        channel,
        source,
        reason: textPayloadValidation.reason,
        status_code: textPayloadValidation.statusCode,
        payload_bytes: textPayloadValidation.payloadBytes,
        max_payload_bytes: textPayloadValidation.maxPayloadBytes,
      });
      res.status(textPayloadValidation.statusCode).json({
        error:
          textPayloadValidation.statusCode === 413
            ? "Inbound channel payload exceeds configured size limits."
            : "Invalid inbound channel payload schema.",
        reason: textPayloadValidation.reason,
      });
      return;
    }
    const inbound = channelHub.ingestInbound({
      channel,
      source,
      sender,
      text,
      metadata,
      timestamp: typeof req.body?.timestamp === "string" ? req.body.timestamp : undefined,
    });
    const inboundSessionId =
      nonEmptyStringWithMax(req.body?.session_id, MAX_MODALITY_SESSION_ID_CHARS) ||
      `channel:${channel}:${source}`;
    const observation = modalityHub.ingest({
      session_id: inboundSessionId,
      modality: "text",
      source: `${channel}:${source}`,
      payload: textPayloadValidation.normalizedPayload,
      timestamp: inbound.timestamp,
    });
    ledger.logAndSignAction("CHANNEL_EVENT_INGESTED", {
      channel,
      source,
      sender,
      event_id: inbound.id,
      observation_id: observation.id,
    });
    persistInteraction(
      "interaction-store:channel-inbound",
      () => {
        interactionStore.recordChannelInbound(inbound);
        interactionStore.recordModality(observation);
      },
      { event_id: inbound.id, observation_id: observation.id, channel, source },
    );
    res.json({ ok: true, event: inbound, observation });
  });

  app.get("/_clawee/control/modality/recent", controlAuth("modality.read"), (req, res) => {
    const rawLimit = Number(req.query.limit || 100);
    const limit = Number.isNaN(rawLimit) ? 100 : rawLimit;
    res.json({
      observations: modalityHub.listRecent(limit),
    });
  });

  const guardMiddleware: RequestHandler = async (req, res, next) => {
    if (isControlPath(req.path) || isChannelIngressPath(req.path) || req.method === "GET" || req.method === "HEAD") {
      return next();
    }
    const securityDecisionId = sha256Hex(`${Date.now()}|${req.method}|${requestFingerprint(req)}`);
    (req as Request & { __claweeSecurityDecisionId?: string }).__claweeSecurityDecisionId =
      securityDecisionId;

    try {
      await runtimeEgressGuard.assertAllowed("upstream_base_url");
      invariantCheck({
        id: "INV-001-RUNTIME-EGRESS-GATE",
        passed: true,
        context: {
          path: req.originalUrl,
          method: req.method,
        },
        securityDecisionId,
      });
    } catch (error) {
      const details =
        error instanceof RuntimeEgressPolicyError ? error.result : { reason: String(error) };
      invariantCheck({
        id: "INV-001-RUNTIME-EGRESS-GATE",
        passed: true,
        reason: "request blocked by runtime egress policy",
        context: {
          path: req.originalUrl,
          method: req.method,
          details,
        },
        securityDecisionId,
      });
      ledger.logAndSignAction("RUNTIME_EGRESS_BLOCKED", {
        path: req.originalUrl,
        method: req.method,
        target: "upstream_base_url",
        details,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "runtime_egress_blocked",
        "critical",
        "Claw-EE blocked request due to runtime egress policy.",
        {
          path: req.originalUrl,
          method: req.method,
          details,
        },
      );
      res.status(503).json({
        error: "Blocked by Claw-EE runtime egress policy.",
        details,
      });
      return;
    }

    const model = extractModel(req.body);
    const modality = inferModality(req.originalUrl, req.body);
    const intent = extractToolIntent(req.body);
    const channelHint = extractChannelHint(req.body);
    const capabilityToolDecision = capabilityPolicy.evaluateToolExecution(intent.toolNames, channelHint);
    if (!capabilityToolDecision.allowed) {
      invariantCheck({
        id: "INV-002-CAPABILITY-GATE",
        passed: true,
        reason: "capability policy blocked tool execution",
        context: {
          path: req.originalUrl,
          method: req.method,
          tools: intent.toolNames,
          channel_hint: channelHint || null,
        },
        securityDecisionId,
      });
      ledger.logAndSignAction("CAPABILITY_BLOCKED_ACTION", {
        path: req.originalUrl,
        method: req.method,
        model,
        modality,
        tools: intent.toolNames,
        channel_hint: channelHint || null,
        reason: capabilityToolDecision.reason,
        matched_signals: capabilityToolDecision.matchedSignals,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "capability_blocked_action",
        "critical",
        "Claw-EE blocked tool execution by capability policy.",
        {
          path: req.originalUrl,
          method: req.method,
          model,
          modality,
          tools: intent.toolNames,
          channel_hint: channelHint || null,
          reason: capabilityToolDecision.reason,
          matched_signals: capabilityToolDecision.matchedSignals,
        },
      );
      res.status(403).json({
        error: "Blocked by Claw-EE capability policy.",
        reason: capabilityToolDecision.reason,
        matched_signals: capabilityToolDecision.matchedSignals,
      });
      return;
    }
    invariantCheck({
      id: "INV-002-CAPABILITY-GATE",
      passed: true,
      context: {
        path: req.originalUrl,
        method: req.method,
        tools: intent.toolNames,
        channel_hint: channelHint || null,
      },
      securityDecisionId,
    });
    const inputTokens = estimateInputTokens(req.body);
    const outputTokens = extractOutputTokens(req.body);
    if (inputTokens > Math.max(1, Math.floor(options.maxRequestInputTokens))) {
      ledger.logAndSignAction("TOKEN_BUDGET_BLOCKED", {
        path: req.originalUrl,
        method: req.method,
        token_type: "input",
        estimated_tokens: inputTokens,
        max_allowed_tokens: options.maxRequestInputTokens,
      });
      res.status(413).json({
        error: "Blocked by Claw-EE request token policy.",
        token_type: "input",
        estimated_tokens: inputTokens,
        max_allowed_tokens: options.maxRequestInputTokens,
      });
      return;
    }
    if (outputTokens > Math.max(1, Math.floor(options.maxRequestOutputTokens))) {
      ledger.logAndSignAction("TOKEN_BUDGET_BLOCKED", {
        path: req.originalUrl,
        method: req.method,
        token_type: "output",
        estimated_tokens: outputTokens,
        max_allowed_tokens: options.maxRequestOutputTokens,
      });
      res.status(413).json({
        error: "Blocked by Claw-EE request token policy.",
        token_type: "output",
        estimated_tokens: outputTokens,
        max_allowed_tokens: options.maxRequestOutputTokens,
      });
      return;
    }
    const modelPolicy = modelRegistry.evaluate(model, modality);
    if (!modelPolicy.allowed) {
      invariantCheck({
        id: "INV-006-MODEL-REGISTRY-GATE",
        passed: true,
        reason: "model registry denied model/modality",
        context: {
          path: req.originalUrl,
          method: req.method,
          model,
          modality,
        },
        securityDecisionId,
      });
      ledger.logAndSignAction("MODEL_POLICY_BLOCKED", {
        path: req.originalUrl,
        method: req.method,
        model,
        modality,
        reason: modelPolicy.reason,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "model_policy_blocked",
        "critical",
        "Claw-EE blocked request due to model registry policy.",
        {
          path: req.originalUrl,
          model,
          modality,
          reason: modelPolicy.reason,
        },
      );
      res.status(403).json({
        error: "Blocked by Claw-EE model registry policy.",
        reason: modelPolicy.reason,
      });
      return;
    }
    invariantCheck({
      id: "INV-006-MODEL-REGISTRY-GATE",
      passed: true,
      context: {
        path: req.originalUrl,
        method: req.method,
        model,
        modality,
      },
      securityDecisionId,
    });

    const policyDecision = policyEngine.evaluate({
      path: req.originalUrl,
      method: req.method,
      body: req.body,
      model,
      modality,
      intent,
    });
    invariantCheck({
      id: "INV-003-POLICY-GATE",
      passed: true,
      context: {
        path: req.originalUrl,
        method: req.method,
        decision: policyDecision.decision,
      },
      securityDecisionId,
    });
    let approvedRequest: { id: string; fingerprint: string } | null = null;
    if (policyDecision.decision === "block") {
      ledger.logAndSignAction("POLICY_BLOCKED_ACTION", {
        path: req.originalUrl,
        method: req.method,
        model,
        modality,
        reason: policyDecision.reason,
        matched_signals: policyDecision.matchedSignals,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "policy_blocked_action",
        "critical",
        "Claw-EE blocked a critical action by policy.",
        {
          path: req.originalUrl,
          method: req.method,
          reason: policyDecision.reason,
          matched_signals: policyDecision.matchedSignals,
        },
      );
      res.status(403).json({
        error: "Blocked by Claw-EE policy engine.",
        reason: policyDecision.reason,
        matched_signals: policyDecision.matchedSignals,
      });
      return;
    }

    if (policyDecision.decision === "require_approval") {
      const approvalRequirements = approvalPolicy.evaluate({
        policyDecision,
        channel: channelHint,
        action: "tool.execute",
        toolNames: intent.toolNames,
      });
      const fingerprint = requestFingerprint(req);
      const approvalId = approvalHeader(req);
      const isApproved =
        approvalId.length > 0 && approvalService.validateApproved(approvalId, fingerprint);
      if (!isApproved) {
        const created = approvalService.getOrCreatePending({
          requestFingerprint: fingerprint,
          reason: policyDecision.reason,
          metadata: {
            path: req.originalUrl,
            method: req.method,
            model,
            modality,
            signals: policyDecision.matchedSignals,
            required_approvals: approvalRequirements.requiredApprovals,
            required_roles: approvalRequirements.requiredRoles,
          },
          ttlSeconds: options.approvalTtlSeconds,
          requiredApprovals: approvalRequirements.requiredApprovals,
          requiredRoles: approvalRequirements.requiredRoles,
          maxUses: options.approvalMaxUses,
        });
        invariantCheck({
          id: "INV-004-APPROVAL-GATE",
          passed: true,
          reason: "approval required and action blocked pending human approval",
          context: {
            path: req.originalUrl,
            method: req.method,
            approval_id: created.record.id,
          },
          securityDecisionId,
        });
        if (created.created) {
          ledger.logAndSignAction("APPROVAL_CREATED", {
            approval_id: created.record.id,
            reason: created.record.reason,
            expires_at: created.record.expires_at,
            security_decision_id: securityDecisionId,
          });
        }
        ledger.logAndSignAction("APPROVAL_REQUIRED", {
          approval_id: created.record.id,
          path: req.originalUrl,
          method: req.method,
          reason: policyDecision.reason,
          signals: policyDecision.matchedSignals,
          required_approvals: created.record.required_approvals,
          required_roles: parseRequiredRoles(created.record.required_roles),
          security_decision_id: securityDecisionId,
        });
        void sendAlert(
          "approval_required",
          "warning",
          "Claw-EE requires human approval for a high-risk action.",
          {
            approval_id: created.record.id,
            path: req.originalUrl,
            reason: policyDecision.reason,
            required_approvals: created.record.required_approvals,
            required_roles: parseRequiredRoles(created.record.required_roles),
          },
        );
        res.status(428).json({
          error: "Approval required by Claw-EE policy engine.",
          approval_id: created.record.id,
          expires_at: created.record.expires_at,
          reason: policyDecision.reason,
          required_approvals: created.record.required_approvals,
          required_roles: parseRequiredRoles(created.record.required_roles),
          max_uses: created.record.max_uses,
          use_count: created.record.use_count,
          current_approvals: parseApprovalActors(created.record.approval_actors).length,
          remaining_approvals: remainingApprovals(created.record),
          missing_required_roles: missingRequiredRoles(created.record),
        });
        return;
      }
      approvedRequest = {
        id: approvalId,
        fingerprint,
      };
      invariantCheck({
        id: "INV-004-APPROVAL-GATE",
        passed: true,
        context: {
          path: req.originalUrl,
          method: req.method,
          approval_id: approvalId,
          stage: "approval-token-present",
        },
        securityDecisionId,
      });
    }

    let estimate: CostEstimate;
    try {
      estimate = budgetController.estimateCost(model, inputTokens, outputTokens);
    } catch (error) {
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "budget-estimate",
        path: req.originalUrl,
        message: error instanceof Error ? error.message : String(error),
      });
      return next();
    }

    const budgetDecision = budgetController.evaluateProjected(estimate);
    if (budgetDecision.decision === "suspend") {
      invariantCheck({
        id: "INV-005-BUDGET-GATE",
        passed: true,
        reason: "budget gate blocked forwarding",
        context: {
          path: req.originalUrl,
          method: req.method,
          model,
          estimated_usd: estimate.estimatedUsd,
        },
        securityDecisionId,
      });
      ledger.logAndSignAction("BUDGET_SUSPENDED", {
        reason: budgetDecision.reason || "Budget cap exceeded.",
        path: req.originalUrl,
        model,
        estimated_usd: estimate.estimatedUsd,
        security_decision_id: securityDecisionId,
      });
      void sendAlert(
        "budget_suspended",
        "critical",
        "Claw-EE suspended traffic because budget cap was exceeded.",
        {
          path: req.originalUrl,
          model,
          reason: budgetDecision.reason || "Budget cap exceeded.",
          estimated_usd: estimate.estimatedUsd,
        },
      );
      res.status(429).json({
        error: "Claw-EE suspended: compute budget exceeded.",
        reason: budgetDecision.reason,
      });
      return;
    }
    invariantCheck({
      id: "INV-005-BUDGET-GATE",
      passed: true,
      context: {
        path: req.originalUrl,
        method: req.method,
        model,
      },
      securityDecisionId,
    });

    (req as Request & { __claweeCostEstimate?: CostEstimate }).__claweeCostEstimate = estimate;

    if (!intent.hasToolIntent) {
      if (approvedRequest) {
        const consumed = approvalService.consumeApproved(
          approvedRequest.id,
          approvedRequest.fingerprint,
        );
        if (!consumed) {
          invariantCheck({
            id: "INV-004-APPROVAL-GATE",
            passed: true,
            reason: "approval token replay blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              approval_id: approvedRequest.id,
            },
            securityDecisionId,
          });
          ledger.logAndSignAction("APPROVAL_TOKEN_REPLAY_BLOCKED", {
            approval_id: approvedRequest.id,
            path: req.originalUrl,
            method: req.method,
            security_decision_id: securityDecisionId,
          });
          res.status(428).json({
            error: "Approval token is expired or already consumed.",
          });
          return;
        }
        ledger.logAndSignAction("APPROVAL_GRANTED", {
          approval_id: approvedRequest.id,
          path: req.originalUrl,
          method: req.method,
          source: "request-header",
          consumed: true,
          security_decision_id: securityDecisionId,
        });
      }
      return next();
    }

    try {
      const risk = await riskEvaluator.evaluateRisk(
        options.evaluatorModel,
        req.originalUrl,
        req.method,
        req.body,
        intent,
      );

      (req as Request & { __claweeRisk?: unknown }).__claweeRisk = risk;
      ledger.logAndSignAction("RISK_SCORED", {
        path: req.originalUrl,
        method: req.method,
        risk,
        tools: intent.toolNames,
        security_decision_id: securityDecisionId,
      });

      if (risk.confidence_score < options.warnThreshold) {
        if (options.enforcementMode === "block") {
          ledger.logAndSignAction("RISK_BLOCKED_ACTION", {
            path: req.originalUrl,
            method: req.method,
            threshold: options.warnThreshold,
            risk,
            mode: options.enforcementMode,
            security_decision_id: securityDecisionId,
          });
          void sendAlert(
            "risk_blocked_action",
            "critical",
            "Claw-EE blocked action due to low confidence risk evaluation.",
            {
              path: req.originalUrl,
              method: req.method,
              confidence_score: risk.confidence_score,
              reason: risk.reason,
            },
          );
          res.status(403).json({
            error: "Blocked by Claw-EE uncertainty gate.",
            reason: risk.reason,
            confidence_score: risk.confidence_score,
          });
          return;
        }
        res.setHeader("x-clawee-risk-warning", "true");
        ledger.logAndSignAction("RISK_HIGH_WARNING", {
          path: req.originalUrl,
          method: req.method,
          threshold: options.warnThreshold,
          risk,
          mode: options.enforcementMode,
          security_decision_id: securityDecisionId,
        });
      }

      if (approvedRequest) {
        const consumed = approvalService.consumeApproved(
          approvedRequest.id,
          approvedRequest.fingerprint,
        );
        if (!consumed) {
          invariantCheck({
            id: "INV-004-APPROVAL-GATE",
            passed: true,
            reason: "approval token replay blocked",
            context: {
              path: req.originalUrl,
              method: req.method,
              approval_id: approvedRequest.id,
            },
            securityDecisionId,
          });
          ledger.logAndSignAction("APPROVAL_TOKEN_REPLAY_BLOCKED", {
            approval_id: approvedRequest.id,
            path: req.originalUrl,
            method: req.method,
            security_decision_id: securityDecisionId,
          });
          res.status(428).json({
            error: "Approval token is expired or already consumed.",
          });
          return;
        }
        ledger.logAndSignAction("APPROVAL_GRANTED", {
          approval_id: approvedRequest.id,
          path: req.originalUrl,
          method: req.method,
          source: "request-header",
          consumed: true,
          security_decision_id: securityDecisionId,
        });
        invariantCheck({
          id: "INV-004-APPROVAL-GATE",
          passed: true,
          context: {
            path: req.originalUrl,
            method: req.method,
            approval_id: approvedRequest.id,
            stage: "consumed",
          },
          securityDecisionId,
        });
      }

      next();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "uncertainty-gate",
        stage: "evaluate",
        path: req.originalUrl,
        message,
        risk_evaluator_fail_mode: options.riskEvaluatorFailMode,
        security_decision_id: securityDecisionId,
      });
      if (options.riskEvaluatorFailMode === "block") {
        void sendAlert(
          "risk_evaluator_error",
          "critical",
          "Claw-EE blocked action because risk evaluator failed.",
          {
            path: req.originalUrl,
            method: req.method,
            message,
          },
        );
        res.status(503).json({
          error: "Blocked by Claw-EE risk evaluator failure policy.",
          reason: "Risk evaluator unavailable or failed.",
        });
        return;
      }
      ledger.logAndSignAction("RISK_HIGH_WARNING", {
        path: req.originalUrl,
        method: req.method,
        warning: "risk-evaluator-failed-open",
        message,
        security_decision_id: securityDecisionId,
      });
      next();
    }
  };

  app.use(guardMiddleware);

  app.use((req, res, next) => {
    if (isControlPath(req.path) || isChannelIngressPath(req.path) || req.method === "GET" || req.method === "HEAD") {
      next();
      return;
    }
    const securityDecisionId = (
      req as Request & { __claweeSecurityDecisionId?: string }
    ).__claweeSecurityDecisionId;
    if (securityDecisionId && securityDecisionId.length > 0) {
      next();
      return;
    }
    const allow = invariantCheck({
      id: "INV-003-POLICY-GATE",
      passed: false,
      reason: "request reached forwarding stage without guard decision id",
      context: {
        path: req.originalUrl,
        method: req.method,
      },
    });
    if (!allow) {
      res.status(500).json({
        error: "Blocked by Claw-EE security invariant enforcement.",
        reason: "guard coverage invariant failed",
      });
      return;
    }
    next();
  });

  const proxy = createProxyMiddleware({
    target: options.upstreamBaseUrl,
    changeOrigin: true,
    ws: true,
    selfHandleResponse: true,
    agent: options.upstreamAgent,
    on: {
      proxyReq: (proxyReq, req) => {
        fixRequestBody(proxyReq, req);
      },
      proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        try {
          const reqWithState = req as Request & {
            __claweeCostEstimate?: CostEstimate;
            __claweeRisk?: unknown;
            __claweeSecurityDecisionId?: string;
          };
          const securityDecisionId = reqWithState.__claweeSecurityDecisionId || null;
          const estimate = reqWithState.__claweeCostEstimate || null;
          const contentType = String(proxyRes.headers["content-type"] || "");

          let actual = estimate;
          if (contentType.includes("application/json")) {
            const payload = JSON.parse(responseBuffer.toString("utf8")) as unknown;
            const usage = parseActualUsage(payload);
            if (usage) {
              actual = budgetController.estimateCost(usage.model, usage.inputTokens, usage.outputTokens);
            }
          }

          if (actual) {
            budgetController.recordActual({
              ...actual,
              requestPath: req.url || "/",
            });
            ledger.logAndSignAction("BUDGET_COST_RECORDED", {
              path: req.url || "/",
              model: actual.model,
              input_tokens: actual.inputTokens,
              output_tokens: actual.outputTokens,
              usd_cost: actual.estimatedUsd,
              security_decision_id: securityDecisionId,
            });
          }
        } catch (error) {
          ledger.logAndSignAction("SYSTEM_ERROR", {
            module: "uncertainty-gate",
            stage: "proxy-res",
            path: req.url,
            message: error instanceof Error ? error.message : String(error),
            security_decision_id: (
              req as Request & { __claweeSecurityDecisionId?: string }
            ).__claweeSecurityDecisionId || null,
          });
        }

        const statusCode = proxyRes.statusCode ?? 0;
        ledger.logAndSignAction("ACTION_FORWARDED", {
          path: req.url,
          method: req.method,
          status_code: statusCode,
          risk: (req as Request & { __claweeRisk?: unknown }).__claweeRisk ?? null,
          security_decision_id: (
            req as Request & { __claweeSecurityDecisionId?: string }
          ).__claweeSecurityDecisionId || null,
        });

        return responseBuffer;
      }),
      error: (error, req) => {
        ledger.logAndSignAction("SYSTEM_ERROR", {
          module: "uncertainty-gate",
          stage: "proxy",
          path: req.url,
          message: error.message,
        });
      },
    },
  }) as ProxyRequestHandler;

  app.use("/", proxy);

  const server = await new Promise<http.Server>((resolve) => {
    const started = app.listen(options.port, () => resolve(started));
  });

  return {
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      }),
  };
}
