import type {
  CreateInitiativeInput,
  InitiativePriority,
  InitiativeRiskClass,
} from "./initiative-types";
import { sha256Hex, stableStringify } from "./utils";

export type InitiativeIntakeProvider = "jira" | "linear" | "pagerduty";

export interface InitiativeIntakeResult {
  ok: boolean;
  provider: InitiativeIntakeProvider;
  eventId: string;
  intake: CreateInitiativeInput | null;
  reason?: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function str(value: unknown): string {
  return String(value || "").trim();
}

function maybeJsonText(value: unknown): string {
  if (typeof value === "string") {
    return value.trim();
  }
  if (!value || typeof value !== "object") {
    return "";
  }
  const record = asRecord(value);
  const directText = str(record.text);
  if (directText) {
    return directText;
  }
  const content = Array.isArray(record.content) ? record.content : [];
  const extracted: string[] = [];
  for (const node of content) {
    const nodeRecord = asRecord(node);
    const nodeText = str(nodeRecord.text);
    if (nodeText) {
      extracted.push(nodeText);
    }
    const nested = Array.isArray(nodeRecord.content) ? nodeRecord.content : [];
    for (const child of nested) {
      const childText = str(asRecord(child).text);
      if (childText) {
        extracted.push(childText);
      }
    }
  }
  return extracted.join("\n").trim();
}

function priorityFromText(value: string): InitiativePriority {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return "normal";
  }
  if (
    normalized.includes("critical") ||
    normalized.includes("p0") ||
    normalized.includes("sev0") ||
    normalized.includes("sev1") ||
    normalized.includes("blocker") ||
    normalized.includes("urgent")
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

function linearPriorityFromNumeric(value: unknown): InitiativePriority {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "normal";
  }
  // Linear commonly maps 1=urgent, 2=high, 3=normal, 4=low, 0=none.
  if (numeric <= 1) {
    return "urgent";
  }
  if (numeric === 2) {
    return "high";
  }
  if (numeric >= 4) {
    return "low";
  }
  return "normal";
}

function parseJira(payload: Record<string, unknown>): InitiativeIntakeResult {
  const issue = asRecord(payload.issue);
  const fields = asRecord(issue.fields);
  const issueKey = str(issue.key) || str(issue.id);
  const summary = str(fields.summary);
  if (!issueKey || !summary) {
    return {
      ok: false,
      provider: "jira",
      eventId: "",
      intake: null,
      reason: "Jira payload is missing issue key or summary.",
    };
  }
  const webhookEvent = str(payload.webhookEvent);
  const description = maybeJsonText(fields.description);
  const priorityName = str(asRecord(fields.priority).name);
  const priority = priorityFromText(priorityName);
  const eventId =
    str(payload.timestamp) ||
    str(payload.issue_event_type_name) ||
    str(asRecord(payload.changelog).id) ||
    `${webhookEvent || "jira.event"}:${issueKey}`;
  const actor = asRecord(payload.user);
  const requestedBy =
    str(actor.emailAddress) ||
    str(actor.displayName) ||
    `intake:jira`;
  return {
    ok: true,
    provider: "jira",
    eventId,
    intake: {
      source: "jira",
      external_ref: issueKey,
      title: `[Jira ${issueKey}] ${summary}`,
      description,
      priority,
      risk_class: riskFromPriority(priority),
      requested_by: requestedBy,
      metadata: {
        provider: "jira",
        issue_key: issueKey,
        webhook_event: webhookEvent || null,
        issue_type: str(asRecord(fields.issuetype).name) || null,
        project_key: str(asRecord(fields.project).key) || null,
        status: str(asRecord(fields.status).name) || null,
        payload_digest: sha256Hex(stableStringify(payload)),
      },
      tasks: [{ task_type: "noop", payload: { provider: "jira", issue_key: issueKey } }],
    },
  };
}

function parseLinear(payload: Record<string, unknown>): InitiativeIntakeResult {
  const data = asRecord(payload.data);
  const issueId = str(data.identifier) || str(data.id);
  const title = str(data.title);
  if (!issueId || !title) {
    return {
      ok: false,
      provider: "linear",
      eventId: "",
      intake: null,
      reason: "Linear payload is missing issue identifier or title.",
    };
  }
  const action = str(payload.action) || str(payload.type) || "linear.event";
  const priority = linearPriorityFromNumeric(data.priority);
  const actor = asRecord(payload.actor);
  const requestedBy = str(actor.email) || str(actor.name) || "intake:linear";
  return {
    ok: true,
    provider: "linear",
    eventId: str(payload.id) || `${action}:${issueId}`,
    intake: {
      source: "linear",
      external_ref: issueId,
      title: `[Linear ${issueId}] ${title}`,
      description: str(data.description),
      priority,
      risk_class: riskFromPriority(priority),
      requested_by: requestedBy,
      metadata: {
        provider: "linear",
        issue_id: issueId,
        action,
        team_key: str(asRecord(data.team).key) || null,
        state: str(asRecord(data.state).name) || null,
        payload_digest: sha256Hex(stableStringify(payload)),
      },
      tasks: [{ task_type: "noop", payload: { provider: "linear", issue_id: issueId } }],
    },
  };
}

function parsePagerDuty(payload: Record<string, unknown>): InitiativeIntakeResult {
  const event = asRecord(payload.event);
  const data = asRecord(event.data);
  const incident = asRecord(data.incident);
  const incidentNumber = str(incident.incident_number) || str(incident.number) || str(incident.id);
  const incidentTitle = str(incident.title);
  if (!incidentNumber || !incidentTitle) {
    return {
      ok: false,
      provider: "pagerduty",
      eventId: "",
      intake: null,
      reason: "PagerDuty payload is missing incident id/number or title.",
    };
  }
  const urgency = str(incident.urgency);
  const priority = urgency.toLowerCase() === "high" ? "urgent" : "high";
  const eventType = str(event.event_type) || str(payload.event_type) || "pagerduty.event";
  return {
    ok: true,
    provider: "pagerduty",
    eventId: str(event.id) || `${eventType}:${incidentNumber}`,
    intake: {
      source: "pagerduty",
      external_ref: incidentNumber,
      title: `[PagerDuty ${incidentNumber}] ${incidentTitle}`,
      description: str(incident.description),
      priority,
      risk_class: riskFromPriority(priority),
      requested_by: "intake:pagerduty",
      metadata: {
        provider: "pagerduty",
        incident_number: incidentNumber,
        event_type: eventType,
        urgency: urgency || null,
        status: str(incident.status) || null,
        service: str(asRecord(incident.service).summary) || null,
        payload_digest: sha256Hex(stableStringify(payload)),
      },
      tasks: [
        { task_type: "noop", payload: { provider: "pagerduty", incident_number: incidentNumber } },
      ],
    },
  };
}

export function parseInitiativeProvider(value: string): InitiativeIntakeProvider | null {
  const normalized = value.trim().toLowerCase();
  if (normalized === "jira" || normalized === "linear" || normalized === "pagerduty") {
    return normalized;
  }
  return null;
}

export function parseInitiativeIntake(
  provider: InitiativeIntakeProvider,
  body: unknown,
): InitiativeIntakeResult {
  const payload = asRecord(body);
  if (provider === "jira") {
    return parseJira(payload);
  }
  if (provider === "linear") {
    return parseLinear(payload);
  }
  return parsePagerDuty(payload);
}
