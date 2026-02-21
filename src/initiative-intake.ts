import type {
  CreateInitiativeInput,
  InitiativePriority,
  InitiativeRiskClass,
} from "./initiative-types";
import { compileInitiativeTemplate, type InitiativeTemplate } from "./initiative-template";
import { sha256Hex, stableStringify } from "./utils";

export type InitiativeIntakeProvider = "jira" | "linear" | "pagerduty";

export interface InitiativeIntakeResult {
  ok: boolean;
  provider: InitiativeIntakeProvider;
  eventId: string;
  intake: CreateInitiativeInput | null;
  template: InitiativeTemplate | null;
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
      template: null,
      reason: "Jira payload is missing issue key or summary.",
    };
  }
  const webhookEvent = str(payload.webhookEvent);
  const description = maybeJsonText(fields.description);
  const priorityName = str(asRecord(fields.priority).name);
  const priority = priorityFromText(priorityName);
  const projectKey = str(asRecord(fields.project).key);
  const status = str(asRecord(fields.status).name);
  const issueLink = str(issue.self);
  const template = compileInitiativeTemplate({
    provider: "jira",
    sourcePayload: payload,
    externalRef: issueKey,
    title: summary,
    priority,
    eventType: webhookEvent || "jira.event",
    status,
    projectKey,
    link: issueLink,
  });
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
    template: template.template,
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
        project_key: projectKey || null,
        status: status || null,
        payload_digest: sha256Hex(stableStringify(payload)),
        ...template.metadata,
      },
      tasks: template.tasks,
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
      template: null,
      reason: "Linear payload is missing issue identifier or title.",
    };
  }
  const action = str(payload.action) || str(payload.type) || "linear.event";
  const priority = linearPriorityFromNumeric(data.priority);
  const actor = asRecord(payload.actor);
  const requestedBy = str(actor.email) || str(actor.name) || "intake:linear";
  const teamKey = str(asRecord(data.team).key);
  const state = str(asRecord(data.state).name);
  const issueLink = str(data.url);
  const template = compileInitiativeTemplate({
    provider: "linear",
    sourcePayload: payload,
    externalRef: issueId,
    title,
    priority,
    eventType: action,
    status: state,
    teamKey,
    link: issueLink,
  });
  return {
    ok: true,
    provider: "linear",
    eventId: str(payload.id) || `${action}:${issueId}`,
    template: template.template,
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
        team_key: teamKey || null,
        state: state || null,
        payload_digest: sha256Hex(stableStringify(payload)),
        ...template.metadata,
      },
      tasks: template.tasks,
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
      template: null,
      reason: "PagerDuty payload is missing incident id/number or title.",
    };
  }
  const urgency = str(incident.urgency);
  const priority = urgency.toLowerCase() === "high" ? "urgent" : "high";
  const eventType = str(event.event_type) || str(payload.event_type) || "pagerduty.event";
  const status = str(incident.status);
  const service = str(asRecord(incident.service).summary);
  const incidentLink = str(incident.html_url);
  const template = compileInitiativeTemplate({
    provider: "pagerduty",
    sourcePayload: payload,
    externalRef: incidentNumber,
    title: incidentTitle,
    priority,
    eventType,
    status,
    service,
    link: incidentLink,
  });
  return {
    ok: true,
    provider: "pagerduty",
    eventId: str(event.id) || `${eventType}:${incidentNumber}`,
    template: template.template,
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
        status: status || null,
        service: service || null,
        payload_digest: sha256Hex(stableStringify(payload)),
        ...template.metadata,
      },
      tasks: template.tasks,
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
