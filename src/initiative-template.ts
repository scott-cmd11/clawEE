import type { CreateInitiativeTaskInput, InitiativePriority } from "./initiative-types";

type TemplateChannel = "slack" | "teams" | "discord" | "email" | "webhook";
type InitiativeTemplateProvider = "jira" | "linear" | "pagerduty";

const ALLOWED_CHANNELS = new Set<TemplateChannel>(["slack", "teams", "discord", "email", "webhook"]);
const TEMPLATE_STRATEGY = "notify+triage";

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

function normalizeDestination(value: string, fallback: string): string {
  const slug = toSlug(value);
  if (slug) {
    return slug;
  }
  return toSlug(fallback) || "intake-triage";
}

function normalizeChannel(value: unknown): TemplateChannel {
  const raw = str(value).toLowerCase();
  if (ALLOWED_CHANNELS.has(raw as TemplateChannel)) {
    return raw as TemplateChannel;
  }
  return "slack";
}

function compactLines(lines: Array<string | null | undefined>): string {
  const cleaned = lines.map((line) => str(line)).filter(Boolean);
  return cleaned.join("\n");
}

function createChannelSendTask(input: {
  provider: InitiativeTemplateProvider;
  stage: "notify" | "triage";
  channel: TemplateChannel;
  destination: string;
  text: string;
  externalRef: string;
  priority: InitiativePriority;
  eventType: string;
}): CreateInitiativeTaskInput {
  return {
    task_type: "channel.send",
    max_retries: 2,
    payload: {
      channel: input.channel,
      destination: input.destination,
      text: input.text,
      metadata: {
        provider: input.provider,
        stage: input.stage,
        external_ref: input.externalRef,
        priority: input.priority,
        event_type: input.eventType,
      },
    },
  };
}

function dedupeDestinations(primary: string, secondary: string): [string, string] {
  if (primary === secondary) {
    return [primary, `${primary}-triage`];
  }
  return [primary, secondary];
}

function parseOverrides(raw: unknown): {
  channel: TemplateChannel;
  notifyDestination: string;
  triageDestination: string;
} {
  const root = asRecord(raw);
  const clawee = asRecord(root.clawee);
  const channel = normalizeChannel(clawee.channel ?? clawee.delivery_channel);
  const notifyDestination = str(clawee.notify_destination || clawee.destination);
  const triageDestination = str(clawee.triage_destination);
  return {
    channel,
    notifyDestination,
    triageDestination,
  };
}

export interface InitiativeTemplate {
  template_id: string;
  template_version: string;
  strategy: string;
  task_count: number;
  stages: string[];
}

export interface InitiativeTemplateCompileInput {
  provider: InitiativeTemplateProvider;
  externalRef: string;
  title: string;
  priority: InitiativePriority;
  eventType: string;
  status?: string;
  projectKey?: string;
  teamKey?: string;
  service?: string;
  link?: string;
  sourcePayload: unknown;
}

export interface InitiativeTemplateCompilation {
  template: InitiativeTemplate;
  tasks: CreateInitiativeTaskInput[];
  metadata: Record<string, unknown>;
}

function compileJiraTemplate(input: InitiativeTemplateCompileInput): InitiativeTemplateCompilation {
  const overrides = parseOverrides(input.sourcePayload);
  const templateId = "jira.issue.notify-triage.v1";
  const baseDestination = normalizeDestination(
    overrides.notifyDestination,
    `jira-${str(input.projectKey) || "triage"}`,
  );
  const triageDestination = normalizeDestination(
    overrides.triageDestination,
    `${baseDestination}-triage`,
  );
  const [notifyDestination, triageDestinationFinal] = dedupeDestinations(
    baseDestination,
    triageDestination,
  );
  const notifyText = compactLines([
    `[Jira ${input.externalRef}] ${input.title}`,
    `Priority: ${input.priority}. Status: ${str(input.status) || "unknown"}.`,
    `Event: ${input.eventType || "jira.event"}.`,
    input.link ? `Link: ${input.link}` : null,
  ]);
  const triageText = compactLines([
    `[Jira ${input.externalRef}] Triage requested`,
    "Checklist:",
    "1) Confirm impact and affected environments.",
    "2) Assign an owner and ETA.",
    "3) Post mitigation update in the incident channel.",
  ]);
  const tasks = [
    createChannelSendTask({
      provider: "jira",
      stage: "notify",
      channel: overrides.channel,
      destination: notifyDestination,
      text: notifyText,
      externalRef: input.externalRef,
      priority: input.priority,
      eventType: input.eventType,
    }),
    createChannelSendTask({
      provider: "jira",
      stage: "triage",
      channel: overrides.channel,
      destination: triageDestinationFinal,
      text: triageText,
      externalRef: input.externalRef,
      priority: input.priority,
      eventType: input.eventType,
    }),
  ];
  return {
    template: {
      template_id: templateId,
      template_version: "1.0.0",
      strategy: TEMPLATE_STRATEGY,
      task_count: tasks.length,
      stages: ["notify", "triage"],
    },
    tasks,
    metadata: {
      template_id: templateId,
      template_version: "1.0.0",
      template_strategy: TEMPLATE_STRATEGY,
      notify_channel: overrides.channel,
      notify_destination: notifyDestination,
      triage_destination: triageDestinationFinal,
    },
  };
}

function compileLinearTemplate(input: InitiativeTemplateCompileInput): InitiativeTemplateCompilation {
  const overrides = parseOverrides(input.sourcePayload);
  const templateId = "linear.issue.notify-triage.v1";
  const baseDestination = normalizeDestination(
    overrides.notifyDestination,
    `linear-${str(input.teamKey) || "triage"}`,
  );
  const triageDestination = normalizeDestination(
    overrides.triageDestination,
    `${baseDestination}-triage`,
  );
  const [notifyDestination, triageDestinationFinal] = dedupeDestinations(
    baseDestination,
    triageDestination,
  );
  const notifyText = compactLines([
    `[Linear ${input.externalRef}] ${input.title}`,
    `Priority: ${input.priority}. Status: ${str(input.status) || "unknown"}.`,
    `Event: ${input.eventType || "linear.event"}.`,
    input.link ? `Link: ${input.link}` : null,
  ]);
  const triageText = compactLines([
    `[Linear ${input.externalRef}] Triage requested`,
    "Checklist:",
    "1) Verify issue scope and customer impact.",
    "2) Confirm assignee and delivery window.",
    "3) Publish next update in project channel.",
  ]);
  const tasks = [
    createChannelSendTask({
      provider: "linear",
      stage: "notify",
      channel: overrides.channel,
      destination: notifyDestination,
      text: notifyText,
      externalRef: input.externalRef,
      priority: input.priority,
      eventType: input.eventType,
    }),
    createChannelSendTask({
      provider: "linear",
      stage: "triage",
      channel: overrides.channel,
      destination: triageDestinationFinal,
      text: triageText,
      externalRef: input.externalRef,
      priority: input.priority,
      eventType: input.eventType,
    }),
  ];
  return {
    template: {
      template_id: templateId,
      template_version: "1.0.0",
      strategy: TEMPLATE_STRATEGY,
      task_count: tasks.length,
      stages: ["notify", "triage"],
    },
    tasks,
    metadata: {
      template_id: templateId,
      template_version: "1.0.0",
      template_strategy: TEMPLATE_STRATEGY,
      notify_channel: overrides.channel,
      notify_destination: notifyDestination,
      triage_destination: triageDestinationFinal,
    },
  };
}

function compilePagerDutyTemplate(input: InitiativeTemplateCompileInput): InitiativeTemplateCompilation {
  const overrides = parseOverrides(input.sourcePayload);
  const templateId = "pagerduty.incident.notify-triage.v1";
  const baseDestination = normalizeDestination(
    overrides.notifyDestination,
    `incident-${str(input.service) || "response"}`,
  );
  const triageDestination = normalizeDestination(
    overrides.triageDestination,
    `${baseDestination}-command`,
  );
  const [notifyDestination, triageDestinationFinal] = dedupeDestinations(
    baseDestination,
    triageDestination,
  );
  const notifyText = compactLines([
    `[PagerDuty ${input.externalRef}] ${input.title}`,
    `Priority: ${input.priority}. Status: ${str(input.status) || "unknown"}.`,
    `Event: ${input.eventType || "pagerduty.event"}.`,
    input.link ? `Link: ${input.link}` : null,
  ]);
  const triageText = compactLines([
    `[PagerDuty ${input.externalRef}] Incident triage requested`,
    "Checklist:",
    "1) Acknowledge incident and confirm comms owner.",
    "2) Pull logs, metrics, and latest deployment delta.",
    "3) Share mitigation plan and next checkpoint.",
  ]);
  const tasks = [
    createChannelSendTask({
      provider: "pagerduty",
      stage: "notify",
      channel: overrides.channel,
      destination: notifyDestination,
      text: notifyText,
      externalRef: input.externalRef,
      priority: input.priority,
      eventType: input.eventType,
    }),
    createChannelSendTask({
      provider: "pagerduty",
      stage: "triage",
      channel: overrides.channel,
      destination: triageDestinationFinal,
      text: triageText,
      externalRef: input.externalRef,
      priority: input.priority,
      eventType: input.eventType,
    }),
  ];
  return {
    template: {
      template_id: templateId,
      template_version: "1.0.0",
      strategy: TEMPLATE_STRATEGY,
      task_count: tasks.length,
      stages: ["notify", "triage"],
    },
    tasks,
    metadata: {
      template_id: templateId,
      template_version: "1.0.0",
      template_strategy: TEMPLATE_STRATEGY,
      notify_channel: overrides.channel,
      notify_destination: notifyDestination,
      triage_destination: triageDestinationFinal,
    },
  };
}

export function compileInitiativeTemplate(input: InitiativeTemplateCompileInput): InitiativeTemplateCompilation {
  if (input.provider === "jira") {
    return compileJiraTemplate(input);
  }
  if (input.provider === "linear") {
    return compileLinearTemplate(input);
  }
  return compilePagerDutyTemplate(input);
}
