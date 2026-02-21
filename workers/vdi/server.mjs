import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import { chromium } from "playwright";

const PORT = Number(process.env.PORT || 8091);
const AUTH_TOKEN = String(process.env.VDI_WORKER_AUTH_TOKEN || "").trim();
const STEP_TIMEOUT_MS = Math.max(500, Number(process.env.VDI_STEP_TIMEOUT_MS || 15000));
const SCREENSHOT_MAX_BYTES = Math.max(
  32768,
  Number(process.env.VDI_SCREENSHOT_MAX_BYTES || 1048576),
);
const ARTIFACT_DIR =
  String(process.env.VDI_CONTAINER_ARTIFACT_PATH || "").trim() ||
  path.join(process.cwd(), "artifacts");
const ALLOWED_HOSTS = String(process.env.VDI_ALLOWED_HOSTS || "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

fs.mkdirSync(ARTIFACT_DIR, { recursive: true });

const app = express();
app.use(express.json({ limit: "2mb" }));

const sessions = new Map();
const closedSessions = new Map();

function normalizeHost(value) {
  return String(value || "").trim().toLowerCase();
}

function parseToken(req) {
  const authHeader = String(req.header("authorization") || "");
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice("Bearer ".length).trim();
  }
  return String(req.header("x-vdi-token") || "").trim();
}

function auth(req, res, next) {
  if (!AUTH_TOKEN) {
    next();
    return;
  }
  if (parseToken(req) !== AUTH_TOKEN) {
    res.status(401).json({ error: "Unauthorized VDI worker request." });
    return;
  }
  next();
}

function assertAllowedUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  const host = normalizeHost(parsed.hostname);
  if (!host) {
    throw new Error("VDI URL host is missing.");
  }
  if (ALLOWED_HOSTS.length === 0) {
    throw new Error("VDI navigation blocked: no allowlisted hosts configured.");
  }
  const allowed = ALLOWED_HOSTS.some((allowedHost) => {
    return host === allowedHost || host.endsWith(`.${allowedHost}`);
  });
  if (!allowed) {
    throw new Error(`VDI navigation blocked for host: ${host}`);
  }
}

function ensureSession(id) {
  const session = sessions.get(id);
  if (!session) {
    const closed = closedSessions.get(id);
    if (closed) {
      return { closed };
    }
    const error = new Error("VDI session not found.");
    error.statusCode = 404;
    throw error;
  }
  return { active: session };
}

function summarizeSession(session) {
  return {
    id: session.id,
    label: session.label,
    status: session.status,
    started_at: session.startedAt,
    stopped_at: session.stoppedAt || null,
    current_url: session.currentUrl || null,
    metadata: session.metadata || {},
  };
}

function artifactName(sessionId) {
  return `${sessionId}_${Date.now()}_${crypto.randomUUID()}.png`;
}

app.post("/session/start", auth, async (req, res) => {
  try {
    const label = String(req.body?.label || "claw-ee-vdi").trim() || "claw-ee-vdi";
    const startUrl = String(req.body?.start_url || "").trim();
    const widthRaw = Number(req.body?.viewport?.width);
    const heightRaw = Number(req.body?.viewport?.height);
    const viewport = {
      width: Number.isFinite(widthRaw) ? Math.min(Math.max(Math.floor(widthRaw), 320), 3840) : 1366,
      height: Number.isFinite(heightRaw) ? Math.min(Math.max(Math.floor(heightRaw), 240), 2160) : 768,
    };
    const metadata =
      req.body?.metadata && typeof req.body.metadata === "object" && !Array.isArray(req.body.metadata)
        ? req.body.metadata
        : {};

    if (startUrl) {
      assertAllowedUrl(startUrl);
    }
    const browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();
    page.setDefaultTimeout(STEP_TIMEOUT_MS);
    if (startUrl) {
      await page.goto(startUrl, { waitUntil: "domcontentloaded", timeout: STEP_TIMEOUT_MS });
    }
    const id = crypto.randomUUID();
    const session = {
      id,
      label,
      browser,
      context,
      page,
      metadata,
      status: "active",
      startedAt: new Date().toISOString(),
      stoppedAt: null,
      currentUrl: page.url() || null,
    };
    sessions.set(id, session);
    res.json({ ok: true, session: summarizeSession(session) });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/session/:id/step", auth, async (req, res) => {
  try {
    const sessionState = ensureSession(String(req.params.id || "").trim());
    if (!sessionState.active) {
      res.status(409).json({ error: "Session is already closed." });
      return;
    }
    const session = sessionState.active;
    const page = session.page;
    const action = String(req.body?.action || "").trim().toLowerCase();
    const timeoutRaw = Number(req.body?.timeout_ms);
    const timeoutMs = Number.isFinite(timeoutRaw)
      ? Math.min(Math.max(Math.floor(timeoutRaw), 100), 120000)
      : STEP_TIMEOUT_MS;
    const now = new Date().toISOString();

    const response = {
      action,
      ok: true,
      timestamp: now,
      current_url: page.url() || null,
      metadata:
        req.body?.metadata && typeof req.body.metadata === "object" && !Array.isArray(req.body.metadata)
          ? req.body.metadata
          : {},
    };

    switch (action) {
      case "navigate": {
        const url = String(req.body?.url || "").trim();
        if (!url) {
          throw new Error("navigate step requires url.");
        }
        assertAllowedUrl(url);
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs });
        response.current_url = page.url() || null;
        break;
      }
      case "click": {
        const selector = String(req.body?.selector || "").trim();
        if (!selector) {
          throw new Error("click step requires selector.");
        }
        await page.click(selector, { timeout: timeoutMs });
        response.current_url = page.url() || null;
        break;
      }
      case "type": {
        const selector = String(req.body?.selector || "").trim();
        const text = String(req.body?.text || "");
        if (!selector) {
          throw new Error("type step requires selector.");
        }
        await page.fill(selector, text, { timeout: timeoutMs });
        response.current_url = page.url() || null;
        break;
      }
      case "select": {
        const selector = String(req.body?.selector || "").trim();
        const value = req.body?.value;
        if (!selector) {
          throw new Error("select step requires selector.");
        }
        if (Array.isArray(value)) {
          await page.selectOption(
            selector,
            value.map((item) => String(item || "")),
            { timeout: timeoutMs },
          );
        } else {
          await page.selectOption(selector, String(value || ""), { timeout: timeoutMs });
        }
        response.current_url = page.url() || null;
        break;
      }
      case "wait_for": {
        const selector = String(req.body?.selector || "").trim();
        if (!selector) {
          throw new Error("wait_for step requires selector.");
        }
        await page.waitForSelector(selector, { timeout: timeoutMs, state: "visible" });
        response.current_url = page.url() || null;
        break;
      }
      case "screenshot": {
        const fullPage = req.body?.full_page === true;
        const fileName = artifactName(session.id);
        const filePath = path.join(ARTIFACT_DIR, fileName);
        const shot = await page.screenshot({ fullPage, timeout: timeoutMs });
        if (shot.byteLength > SCREENSHOT_MAX_BYTES) {
          throw new Error("VDI screenshot exceeds configured max bytes.");
        }
        fs.writeFileSync(filePath, shot);
        response.screenshot_path = filePath;
        response.current_url = page.url() || null;
        break;
      }
      case "extract_text": {
        const selector = String(req.body?.selector || "body").trim() || "body";
        const text = await page.textContent(selector, { timeout: timeoutMs });
        response.text = String(text || "");
        response.current_url = page.url() || null;
        break;
      }
      default:
        throw new Error(`Unsupported VDI step action: ${action}`);
    }

    session.currentUrl = response.current_url;
    res.json({ ok: true, result: response });
  } catch (error) {
    const statusCode = Number(error?.statusCode || 500);
    res.status(statusCode).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/session/:id/stop", auth, async (req, res) => {
  try {
    const sessionState = ensureSession(String(req.params.id || "").trim());
    if (!sessionState.active) {
      res.json({ ok: true, session: sessionState.closed });
      return;
    }
    const session = sessionState.active;
    await session.context.close();
    await session.browser.close();
    session.status = "closed";
    session.stoppedAt = new Date().toISOString();
    session.currentUrl = session.page.url() || null;
    sessions.delete(session.id);
    const summary = summarizeSession(session);
    closedSessions.set(session.id, summary);
    res.json({ ok: true, session: summary });
  } catch (error) {
    const statusCode = Number(error?.statusCode || 500);
    res.status(statusCode).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

app.get("/session/:id", auth, async (req, res) => {
  try {
    const sessionState = ensureSession(String(req.params.id || "").trim());
    if (sessionState.closed) {
      res.json({ ok: true, session: sessionState.closed });
      return;
    }
    res.json({ ok: true, session: summarizeSession(sessionState.active) });
  } catch (error) {
    const statusCode = Number(error?.statusCode || 500);
    res.status(statusCode).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

app.get("/session/:id/artifacts", auth, async (req, res) => {
  try {
    const sessionId = String(req.params.id || "").trim();
    if (!sessionId) {
      res.status(400).json({ error: "Session id is required." });
      return;
    }
    const files = fs
      .readdirSync(ARTIFACT_DIR, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.startsWith(`${sessionId}_`))
      .map((entry) => path.join(ARTIFACT_DIR, entry.name))
      .sort();
    res.json({ ok: true, artifacts: files });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`claw-ee-vdi-worker listening on :${PORT}`);
});

async function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`Received ${signal}, shutting down VDI worker...`);
  for (const session of sessions.values()) {
    try {
      await session.context.close();
      await session.browser.close();
    } catch {
      // no-op
    }
  }
  sessions.clear();
  await new Promise((resolve) => server.close(() => resolve(undefined)));
  process.exit(0);
}

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});
process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

