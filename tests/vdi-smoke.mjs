import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import { SqliteAuditLedger } from "../dist/audit-ledger.js";
import { ChannelHub } from "../dist/channel-hub.js";
import { InitiativeEngine } from "../dist/initiative-engine.js";
import { InitiativeStore } from "../dist/initiative-store.js";
import { InteractionStore } from "../dist/interaction-store.js";
import { VdiService } from "../dist/vdi-service.js";

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(undefined));
  });
}

async function closeServer(server) {
  await new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claw-ee-vdi-smoke-"));
  const sessions = new Map();
  const artifacts = new Map();
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const bodyText = Buffer.concat(chunks).toString("utf8");
    const body = bodyText.trim() ? JSON.parse(bodyText) : {};
    const url = req.url || "/";
    let response = json(404, { error: "not found" });

    if (req.method === "POST" && url === "/session/start") {
      const id = `sess-${sessions.size + 1}`;
      const session = {
        id,
        label: String(body.label || "test"),
        status: "active",
        started_at: new Date().toISOString(),
        stopped_at: null,
        current_url: String(body.start_url || "about:blank"),
        metadata: body.metadata && typeof body.metadata === "object" ? body.metadata : {},
      };
      sessions.set(id, session);
      artifacts.set(id, []);
      response = json(200, { ok: true, session });
    } else if (req.method === "POST" && /^\/session\/[^/]+\/step$/.test(url)) {
      const sessionId = url.split("/")[2];
      const session = sessions.get(sessionId);
      if (!session) {
        response = json(404, { error: "session not found" });
      } else {
        const action = String(body.action || "").trim().toLowerCase();
        if (action === "navigate" && body.url) {
          session.current_url = String(body.url);
        }
        const result = {
          action: action || "screenshot",
          ok: true,
          timestamp: new Date().toISOString(),
          current_url: session.current_url || null,
          screenshot_path:
            action === "screenshot" ? path.join(tmpDir, `${sessionId}-shot.png`) : undefined,
          text: action === "extract_text" ? "ok" : undefined,
        };
        if (result.screenshot_path) {
          artifacts.get(sessionId).push(result.screenshot_path);
        }
        response = json(200, { ok: true, result });
      }
    } else if (req.method === "POST" && /^\/session\/[^/]+\/stop$/.test(url)) {
      const sessionId = url.split("/")[2];
      const session = sessions.get(sessionId);
      if (!session) {
        response = json(404, { error: "session not found" });
      } else {
        session.status = "closed";
        session.stopped_at = new Date().toISOString();
        response = json(200, { ok: true, session });
      }
    } else if (req.method === "GET" && /^\/session\/[^/]+$/.test(url)) {
      const sessionId = url.split("/")[2];
      const session = sessions.get(sessionId);
      if (!session) {
        response = json(404, { error: "session not found" });
      } else {
        response = json(200, { ok: true, session });
      }
    } else if (req.method === "GET" && /^\/session\/[^/]+\/artifacts$/.test(url)) {
      const sessionId = url.split("/")[2];
      response = json(200, { ok: true, artifacts: artifacts.get(sessionId) || [] });
    }

    res.writeHead(response.statusCode, response.headers);
    res.end(response.body);
  });

  await listen(server);
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("Failed to bind VDI mock server.");
  }
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  const vdiService = new VdiService({
    enabled: true,
    workerBaseUrl: baseUrl,
    authToken: "",
    stepTimeoutMs: 5000,
    screenshotMaxBytes: 1048576,
    allowedHosts: ["example.com"],
    artifactPath: tmpDir,
  });

  const ledger = new SqliteAuditLedger(path.join(tmpDir, "audit.db"));
  const interactionStore = new InteractionStore(path.join(tmpDir, "interactions.db"));
  const initiativeStore = new InitiativeStore(path.join(tmpDir, "initiatives.db"));
  const channelHub = new ChannelHub(100);
  ledger.init();
  interactionStore.init();
  initiativeStore.init();
  const engine = new InitiativeEngine(
    {
      enabled: true,
      pollSeconds: 30,
      maxTaskRetries: 1,
      nodeId: "vdi-smoke-node",
    },
    initiativeStore,
    channelHub,
    interactionStore,
    ledger,
    vdiService,
  );

  try {
    const started = await vdiService.startSession({
      label: "smoke",
      start_url: "https://example.com",
    });
    assert.ok(started.id);
    const step = await vdiService.executeStep(started.id, { action: "screenshot" });
    assert.equal(step.action, "screenshot");
    const session = await vdiService.getSession(started.id);
    assert.equal(session.id, started.id);
    const artifactList = await vdiService.listArtifacts(started.id);
    assert.equal(Array.isArray(artifactList), true);
    const stopped = await vdiService.stopSession(started.id, "done");
    assert.equal(stopped.status, "closed");

    let blocked = false;
    try {
      await vdiService.startSession({ start_url: "https://blocked.example" });
    } catch (error) {
      blocked = String(error).toLowerCase().includes("allowlist policy");
    }
    assert.equal(blocked, true);

    const created = engine.createInitiative({
      source: "vdi-smoke",
      title: "Run VDI task trio",
      requested_by: "smoke-test",
      tasks: [
        {
          task_type: "vdi.session.start",
          payload: {
            session_alias: "main",
            start_url: "https://example.com",
          },
        },
        {
          task_type: "vdi.browser.step",
          payload: {
            session_alias: "main",
            step: { action: "screenshot" },
          },
        },
        {
          task_type: "vdi.session.stop",
          payload: {
            session_alias: "main",
            reason: "smoke done",
          },
        },
      ],
    });
    engine.startInitiative(created.initiative.id, "smoke-test");
    await engine.runNow();
    await engine.runNow();
    await engine.runNow();
    const updated = engine.getInitiative(created.initiative.id);
    assert.equal(updated.status, "completed");
    const stats = vdiService.getStats();
    assert.equal(stats.sessions_started_total >= 2, true);
    assert.equal(stats.steps_executed_total >= 2, true);

    console.log("vdi-smoke: ok", {
      vdi_sessions_started: stats.sessions_started_total,
      vdi_steps_executed: stats.steps_executed_total,
      initiative_id: created.initiative.id,
    });
  } finally {
    await engine.stop();
    initiativeStore.close();
    interactionStore.close();
    ledger.close();
    await closeServer(server);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error("vdi-smoke: failed", error);
  process.exit(1);
});

