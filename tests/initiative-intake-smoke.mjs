import assert from "node:assert/strict";

import { parseInitiativeIntake } from "../dist/initiative-intake.js";

function assertTemplateResult(result, provider, templateId) {
  assert.equal(result.ok, true);
  assert.equal(result.provider, provider);
  assert.ok(result.intake);
  assert.ok(result.template);
  assert.equal(result.template.template_id, templateId);
  assert.equal(result.template.strategy, "notify+triage");
  assert.equal(Array.isArray(result.intake.tasks), true);
  assert.equal(result.intake.tasks.length, 2);
  assert.equal(result.template.task_count, result.intake.tasks.length);
  for (const task of result.intake.tasks) {
    assert.equal(task.task_type, "channel.send");
    assert.equal(typeof task.payload?.channel, "string");
    assert.equal(typeof task.payload?.destination, "string");
    assert.equal(typeof task.payload?.text, "string");
    assert.equal(String(task.payload.destination).length > 0, true);
    assert.equal(String(task.payload.text).length > 0, true);
  }
}

async function main() {
  const jiraPayload = {
    webhookEvent: "jira:issue_created",
    issue: {
      key: "ENG-120",
      self: "https://jira.example.local/browse/ENG-120",
      fields: {
        summary: "Fix auth redirect loop",
        description: "Users are bounced after SSO callback.",
        priority: { name: "High" },
        status: { name: "To Do" },
        project: { key: "ENG" },
      },
    },
    user: { displayName: "Ops Bot" },
    clawee: {
      channel: "teams",
      destination: "eng-war-room",
      triage_destination: "eng-war-room-triage",
    },
  };
  const jiraResult = parseInitiativeIntake("jira", jiraPayload);
  assertTemplateResult(jiraResult, "jira", "jira.issue.notify-triage.v1");
  assert.equal(jiraResult.intake.tasks[0].payload.channel, "teams");
  assert.equal(jiraResult.intake.tasks[0].payload.destination, "eng-war-room");
  assert.equal(jiraResult.intake.tasks[1].payload.destination, "eng-war-room-triage");
  assert.equal(jiraResult.intake.metadata.template_id, "jira.issue.notify-triage.v1");

  const linearPayload = {
    action: "Issue",
    type: "Issue",
    id: "linear-event-1",
    data: {
      id: "lin-001",
      identifier: "PLAT-88",
      title: "Repair nightly build artifact retention",
      description: "Artifacts are expiring too early.",
      priority: 2,
      team: { key: "PLAT" },
      state: { name: "Backlog" },
      url: "https://linear.example.local/issue/PLAT-88",
    },
    actor: { name: "Integration Bot" },
  };
  const linearResult = parseInitiativeIntake("linear", linearPayload);
  assertTemplateResult(linearResult, "linear", "linear.issue.notify-triage.v1");
  assert.equal(String(linearResult.intake.tasks[0].payload.destination).startsWith("linear-"), true);

  const pagerDutyPayload = {
    event: {
      id: "pd-event-1",
      event_type: "incident.triggered",
      data: {
        incident: {
          incident_number: "5123",
          title: "Production API latency spike",
          description: "p95 exceeded threshold for 10m",
          urgency: "high",
          status: "triggered",
          html_url: "https://pagerduty.example.local/incidents/5123",
          service: { summary: "api-service" },
        },
      },
    },
  };
  const pagerDutyResult = parseInitiativeIntake("pagerduty", pagerDutyPayload);
  assertTemplateResult(pagerDutyResult, "pagerduty", "pagerduty.incident.notify-triage.v1");
  assert.equal(
    String(pagerDutyResult.intake.tasks[0].payload.destination).startsWith("incident-"),
    true,
  );

  console.log("initiative-intake-smoke: ok");
}

main().catch((error) => {
  console.error("initiative-intake-smoke: failed", error);
  process.exit(1);
});
