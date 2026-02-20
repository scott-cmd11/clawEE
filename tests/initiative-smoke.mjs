import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { SqliteAuditLedger } from "../dist/audit-ledger.js";
import { ChannelHub } from "../dist/channel-hub.js";
import { InitiativeEngine } from "../dist/initiative-engine.js";
import { InitiativeStore } from "../dist/initiative-store.js";
import { InteractionStore } from "../dist/interaction-store.js";

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claw-ee-initiative-smoke-"));
  const auditPath = path.join(tmpDir, "audit.db");
  const interactionPath = path.join(tmpDir, "interactions.db");
  const initiativePath = path.join(tmpDir, "initiatives.db");

  const ledger = new SqliteAuditLedger(auditPath);
  ledger.init();
  const interactionStore = new InteractionStore(interactionPath);
  interactionStore.init();
  const initiativeStore = new InitiativeStore(initiativePath);
  initiativeStore.init();
  const channelHub = new ChannelHub(100);

  const engine = new InitiativeEngine(
    {
      enabled: true,
      pollSeconds: 30,
      maxTaskRetries: 2,
      nodeId: "initiative-smoke-node",
    },
    initiativeStore,
    channelHub,
    interactionStore,
    ledger,
  );

  try {
    const created = engine.createInitiative({
      source: "manual",
      title: "Send daily standup summary",
      description: "Validate initiative engine task flow.",
      priority: "normal",
      risk_class: "low",
      requested_by: "smoke-test",
      tasks: [
        {
          task_type: "channel.send",
          payload: {
            channel: "slack",
            destination: "engineering-standup",
            text: "Synthetic worker standup update.",
            metadata: {
              source: "initiative-smoke",
            },
          },
        },
      ],
    });

    assert.equal(created.created, true);
    assert.equal(created.tasks.length, 1);

    const running = engine.startInitiative(created.initiative.id, "smoke-test");
    assert.equal(running.status, "running");

    await engine.runNow();

    const updated = engine.getInitiative(created.initiative.id);
    assert.ok(updated);
    assert.equal(updated.status, "completed");
    const tasks = engine.listInitiativeTasks(created.initiative.id);
    assert.equal(tasks.length, 1);
    assert.equal(tasks[0].status, "completed");

    const outbound = channelHub.listOutbound(10);
    assert.equal(outbound.length, 1);
    assert.equal(outbound[0].channel, "slack");
    assert.equal(outbound[0].destination, "engineering-standup");

    const counts = interactionStore.counts();
    assert.equal(counts.channel_outbound_total, 1);

    const interrupted = engine.createInitiative({
      source: "manual",
      title: "Interrupt test",
      requested_by: "smoke-test",
      tasks: [{ task_type: "noop" }],
    });
    engine.startInitiative(interrupted.initiative.id, "smoke-test");
    const paused = engine.interruptInitiative(interrupted.initiative.id, "smoke-test", "incident");
    assert.equal(paused.status, "paused");

    console.log("initiative-smoke: ok", {
      initiative_id: created.initiative.id,
      outbound_id: outbound[0].id,
      audit_events: ledger.getCount(),
    });
  } finally {
    await engine.stop();
    initiativeStore.close();
    interactionStore.close();
    ledger.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error("initiative-smoke: failed", error);
  process.exit(1);
});
