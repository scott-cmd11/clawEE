import assert from "node:assert/strict";

import { parseOpenClawHeartbeat, parseOpenClawWorkItem } from "../dist/openclaw-intake.js";

function assertWorkItem(result, templateId) {
  assert.equal(result.ok, true);
  assert.ok(result.intake);
  assert.ok(result.template);
  assert.equal(result.template.template_id, templateId);
  assert.equal(typeof result.dedupeKey, "string");
  assert.equal(result.dedupeKey.length > 0, true);
  assert.equal(Array.isArray(result.intake.tasks), true);
  assert.equal(result.intake.tasks.length, 2);
}

async function main() {
  const assigned = parseOpenClawWorkItem({
    event_id: "oc-evt-101",
    agent_id: "agent-alpha",
    work_type: "task_assigned",
    source_ref: "OC-101",
    title: "Prepare sprint summary",
    description: "Collect completed items and risks.",
    channel: "slack",
    destination: "engineering-ops",
    metadata: { source: "openclaw-daemon" },
  });
  assertWorkItem(assigned, "openclaw.task.notify-execute.v1");
  assert.equal(assigned.intake.source, "openclaw");
  assert.equal(assigned.intake.external_ref, "OC-101");
  assert.equal(assigned.intake.tasks[0].task_type, "channel.send");
  assert.equal(assigned.intake.tasks[1].task_type, "noop");

  const incident = parseOpenClawWorkItem({
    event_id: "oc-evt-200",
    agent_id: "agent-alpha",
    work_type: "incident_interrupt",
    title: "API error rate increase",
  });
  assertWorkItem(incident, "openclaw.incident.interrupt-triage.v1");
  assert.equal(incident.intake.priority, "urgent");
  assert.equal(incident.intake.tasks[0].task_type, "channel.send");
  assert.equal(incident.intake.tasks[1].task_type, "channel.send");

  const heartbeat = parseOpenClawHeartbeat({
    event_id: "och-1",
    agent_id: "agent-alpha",
    status: "online",
    queue_depth: 2,
    active_task_id: "task-22",
    metadata: { host: "node-a" },
  });
  assert.equal(heartbeat.ok, true);
  assert.equal(heartbeat.eventId, "och-1");
  assert.equal(heartbeat.heartbeat.agent_id, "agent-alpha");
  assert.equal(heartbeat.heartbeat.queue_depth, 2);
  assert.equal(heartbeat.heartbeat.status, "online");

  const invalid = parseOpenClawWorkItem({
    event_id: "oc-missing",
    work_type: "task_assigned",
    title: "Missing agent id",
  });
  assert.equal(invalid.ok, false);

  console.log("openclaw-intake-smoke: ok");
}

main().catch((error) => {
  console.error("openclaw-intake-smoke: failed", error);
  process.exit(1);
});
