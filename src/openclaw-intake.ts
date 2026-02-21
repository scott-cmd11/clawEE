import type {
  CreateInitiativeInput,
  CreateInitiativeTaskInput,
  InitiativePriority,
  InitiativeRiskClass,
} from "./initiative-types";
import type { InitiativeTemplate } from "./initiative-template";
import { sha256Hex, stableStringify } from "./utils";

export type OpenClawWorkType =
  | "task_assigned"
  | "incident_interrupt"
  | "message_request"
  | "manual_order";

type TemplateChannel = "slack" | "teams" | "discord" | "email" | "webhook";

const TEMPLATE_VERSION = "1.0.0";
const OPENCLAW_ALLOWED_CHANNELS = new Set<TemplateChannel>([
  "slack",
  "teams",
  "discord",
  "email",
  "webhook",
]);

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function str(value: unknown): string {
  return String(value || "").trim();
}

function toSlug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function normalizeChannel(value: unknown): TemplateChannel {
  const normalized = str(value).toLowerCase();
  if (OPENCLAW_ALLOWED_CHANNELS.has(normalized as TemplateChannel)) {
    return normalized as TemplateChannel;
  }
  return "slack";
}

function normalizeDestination(value: string, fallback: string): string {
  const normalized = toSlug(value);
  if (normalized) {
    return normalized;
  }
  const fallbackNormalized = toSlug(fallback);
  if (fallbackNormalized) {
    return fallbackNormalized;
  }
  return "openclaw-ops";
}

function priorityFromText(raw: unknown, workType: OpenClawWorkType): InitiativePriority {
  const normalized = str(raw).toLowerCase();
  if (!normalized) {
    return workType === "incident_interrupt" ? "urgent" : "normal";
  }
  if (
    normalized.includes("critical") ||
    normalized.includes("urgent") ||
    normalized.includes("p0") ||
    normalized.includes("sev0") ||
    normalized.includes("sev1")
  ) {
    return "urgent";
  }
  if (normalized.includes("high") || normalized.includes("p1") || normalized.includes("sev2")) {
    return "high";
  }
  if (normalized.includes("low") || normalized.includes("p3") || normalized.includes("p4")) {
    return "low";
  }
  return "normal";
}

function riskFromPriority(priority: InitiativePriority): InitiativeRiskClass {
  if (priority === "urgent") {
    return "critical";
  }
  if (priority === "high") {
    return "high";
  }
  if (priority === "low") {
    return "low";
  }
  return "medium";
}

function riskFromText(raw: unknown, priority: InitiativePriority): InitiativeRiskClass {
  const normalized = str(raw).toLowerCase();
  if (!normalized) {
    return riskFromPriority(priority);
  }
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return riskFromPriority(priority);
}

function normalizeWorkType(raw: unknown): OpenClawWorkType | null {
  const value = str(raw).toLowerCase();
  if (
    value === "task_assigned" ||
    value === "incident_interrupt" ||
    value === "message_request" ||
    value === "manual_order"
  ) {
    return value;
  }
  return null;
}

function templateForWorkType(workType: OpenClawWorkType): InitiativeTemplate {
  switch (workType) {
    case "task_assigned":
      return {
        template_id: "openclaw.task.notify-execute.v1",
        template_version: TEMPLATE_VERSION,
        strategy: "notify+execute",
        task_count: 2,
        stages: ["notify", "execute"],
      };
    case "incident_interrupt":
      return {
        template_id: "openclaw.incident.interrupt-triage.v1",
        template_version: TEMPLATE_VERSION,
        strategy: "interrupt+triage",
        task_count: 2,
        stages: ["interrupt", "triage"],
      };
    case "message_request":
      return {
        template_id: "openclaw.message.respond.v1",
        template_version: TEMPLATE_VERSION,
        strategy: "notify+respond",
        task_count: 2,
        stages: ["notify", "respond"],
      };
    case "manual_order":
      return {
        template_id: "openclaw.order.execute.v1",
        template_version: TEMPLATE_VERSION,
        strategy: "notify+execute",
        task_count: 2,
        stages: ["notify", "execute"],
      };
    default:
      return {
        template_id: "openclaw.task.notify-execute.v1",
        template_version: TEMPLATE_VERSION,
        strategy: "notify+execute",
        task_count: 2,
        stages: ["notify", "execute"],
      };
  }
}

function defaultDestination(workType: OpenClawWorkType): string {
  if (workType === "incident_interrupt") {
    return "openclaw-incident-response";
  }
  if (workType === "message_request") {
    return "openclaw-messages";
  }
  return "openclaw-ops";
}

function createChannelTask(
  channel: TemplateChannel,
  destination: string,
  text: string,
  metadata: Record<string, unknown>,
): CreateInitiativeTaskInput {
  return {
    task_type: "channel.send",
    max_retries: 2,
    payload: {
      channel,
      destination,
      text,
      metadata,
    },
  };
}

function createExecuteMarkerTask(templateId: string, workType: OpenClawWorkType): CreateInitiativeTaskInput {
  return {
    task_type: "noop",
    max_retries: 1,
    payload: {
      action: "openclaw.execute.marker",
      template_id: templateId,
      work_type: workType,
    },
  };
}

function followupMessage(workType: OpenClawWorkType, eventId: string): string {
  if (workType === "incident_interrupt") {
    return `[OpenClaw ${eventId}] Incident interrupt accepted. Begin triage, identify blast radius, and post ETA.`;
  }
  if (workType === "message_request") {
    return `[OpenClaw ${eventId}] Draft a response and post for manager approval.`;
  }
  if (workType === "manual_order") {
    return `[OpenClaw ${eventId}] Manual order queued for execution checkpoint.`;
  }
  return `[OpenClaw ${eventId}] Task assignment accepted and queued for execution.`;
}

export interface OpenClawWorkItemIntakeResult {
  ok: boolean;
  eventId: string;
  dedupeKey: string;
  intake: CreateInitiativeInput | null;
  template: InitiativeTemplate | null;
  reason?: string;
}

export interface OpenClawHeartbeatRecord {
  agent_id: string;
  status: string;
  active_task_id: string | null;
  queue_depth: number | null;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface OpenClawHeartbeatResult {
  ok: boolean;
  eventId: string;
  heartbeat: OpenClawHeartbeatRecord | null;
  reason?: string;
}

export function parseOpenClawWorkItem(body: unknown): OpenClawWorkItemIntakeResult {
  const payload = asRecord(body);
  const eventId = str(payload.event_id) || str(payload.id);
  const agentId = str(payload.agent_id);
  const workType = normalizeWorkType(payload.work_type);
  const title = str(payload.title);
  if (!eventId || !agentId || !workType || !title) {
    return {
      ok: false,
      eventId,
      dedupeKey: "",
      intake: null,
      template: null,
      reason: "OpenClaw work-item payload requires event_id, agent_id, work_type, and title.",
    };
  }

  const payloadMetadata = asRecord(payload.metadata);
  const channel = normalizeChannel(payload.channel || payloadMetadata.channel);
  const destination = normalizeDestination(str(payload.destination), defaultDestination(workType));
  const sourceRef = str(payload.source_ref || payload.external_ref);
  const externalRef = sourceRef || eventId;
  const priority = priorityFromText(payload.priority, workType);
  const riskClass = riskFromText(payload.risk_class, priority);
  const template = templateForWorkType(workType);
  const eventType = str(payload.event_type) || workType;
  const customText = str(payload.text);
  const notifyText =
    customText ||
    `[OpenClaw ${eventId}] ${title}\nPriority: ${priority}\nWork type: ${workType}\nAgent: ${agentId}`;
  const followupText = followupMessage(workType, eventId);
  const followupDestination =
    workType === "incident_interrupt"
      ? `${destination}-triage`
      : workType === "message_request"
        ? `${destination}-responses`
        : destination;
  const commonMetadata = {
    provider: "openclaw",
    event_id: eventId,
    event_type: eventType,
    work_type: workType,
    external_ref: externalRef,
    agent_id: agentId,
    template_id: template.template_id,
    template_version: template.template_version,
  };
  const tasks: CreateInitiativeTaskInput[] = [
    createChannelTask(channel, destination, notifyText, {
      ...commonMetadata,
      stage: "notify",
    }),
    workType === "task_assigned" || workType === "manual_order"
      ? createExecuteMarkerTask(template.template_id, workType)
      : createChannelTask(channel, followupDestination, followupText, {
          ...commonMetadata,
          stage: template.stages[1] || "followup",
        }),
  ];
  const dedupeKey = `openclaw|${externalRef.toLowerCase()}`;

  return {
    ok: true,
    eventId,
    dedupeKey,
    template,
    intake: {
      source: "openclaw",
      external_ref: externalRef,
      title: `[OpenClaw ${eventId}] ${title}`,
      description: str(payload.description),
      priority,
      risk_class: riskClass,
      requested_by: `intake:openclaw:${agentId}`,
      metadata: {
        provider: "openclaw",
        agent_id: agentId,
        event_id: eventId,
        event_type: eventType,
        work_type: workType,
        source_ref: sourceRef || null,
        dedupe_key: dedupeKey,
        payload_digest: sha256Hex(stableStringify(payload)),
        template_id: template.template_id,
        template_version: template.template_version,
        template_strategy: template.strategy,
        notify_channel: channel,
        notify_destination: destination,
        followup_destination:
          workType === "task_assigned" || workType === "manual_order"
            ? null
            : followupDestination,
      },
      tasks,
    },
  };
}

export function parseOpenClawHeartbeat(body: unknown): OpenClawHeartbeatResult {
  const payload = asRecord(body);
  const eventId = str(payload.event_id) || str(payload.id);
  const agentId = str(payload.agent_id);
  if (!agentId) {
    return {
      ok: false,
      eventId,
      heartbeat: null,
      reason: "OpenClaw heartbeat payload requires agent_id.",
    };
  }
  const queueDepthRaw = Number(payload.queue_depth);
  const queueDepth =
    Number.isFinite(queueDepthRaw) && queueDepthRaw >= 0 ? Math.floor(queueDepthRaw) : null;
  const heartbeat: OpenClawHeartbeatRecord = {
    agent_id: agentId,
    status: str(payload.status) || "online",
    active_task_id: str(payload.active_task_id) || null,
    queue_depth: queueDepth,
    timestamp: str(payload.timestamp) || new Date().toISOString(),
    metadata: asRecord(payload.metadata),
  };
  return {
    ok: true,
    eventId,
    heartbeat,
  };
}
