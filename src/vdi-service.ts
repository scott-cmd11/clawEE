import {
  normalizeVdiSessionStartInput,
  normalizeVdiStepInput,
  type VdiRuntimeStats,
  type VdiSessionStartInput,
  type VdiSessionSummary,
  type VdiStepInput,
  type VdiStepResult,
} from "./vdi-types";

export interface VdiServiceOptions {
  enabled: boolean;
  workerBaseUrl: string;
  authToken: string;
  stepTimeoutMs: number;
  screenshotMaxBytes: number;
  allowedHosts: string[];
  artifactPath: string;
}

interface StartSessionResponse {
  ok: boolean;
  session: VdiSessionSummary;
}

interface StepResponse {
  ok: boolean;
  result: VdiStepResult;
}

interface StopSessionResponse {
  ok: boolean;
  session: VdiSessionSummary;
}

interface SessionResponse {
  ok: boolean;
  session: VdiSessionSummary;
}

interface ArtifactListResponse {
  ok: boolean;
  artifacts: string[];
}

function normalizeHost(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeWorkerBaseUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) {
    return "http://127.0.0.1:8091";
  }
  return trimmed;
}

function parseErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class VdiService {
  private options: VdiServiceOptions;
  private activeSessions = new Set<string>();
  private sessionsStartedTotal = 0;
  private sessionsStoppedTotal = 0;
  private stepsExecutedTotal = 0;
  private stepsBlockedTotal = 0;
  private lastError: string | null = null;

  constructor(options: VdiServiceOptions) {
    const allowedHosts = Array.from(
      new Set((options.allowedHosts || []).map((value) => normalizeHost(value)).filter(Boolean)),
    );
    this.options = {
      enabled: options.enabled === true,
      workerBaseUrl: normalizeWorkerBaseUrl(options.workerBaseUrl),
      authToken: String(options.authToken || "").trim(),
      stepTimeoutMs: Math.max(500, Math.floor(Number(options.stepTimeoutMs || 15000))),
      screenshotMaxBytes: Math.max(32_768, Math.floor(Number(options.screenshotMaxBytes || 1_048_576))),
      allowedHosts,
      artifactPath: String(options.artifactPath || "").trim(),
    };
  }

  isEnabled(): boolean {
    return this.options.enabled;
  }

  getStats(): VdiRuntimeStats {
    return {
      enabled: this.options.enabled,
      worker_base_url: this.options.workerBaseUrl,
      allowed_hosts: this.options.allowedHosts,
      active_sessions: this.activeSessions.size,
      sessions_started_total: this.sessionsStartedTotal,
      sessions_stopped_total: this.sessionsStoppedTotal,
      steps_executed_total: this.stepsExecutedTotal,
      steps_blocked_total: this.stepsBlockedTotal,
      last_error: this.lastError,
    };
  }

  async startSession(input: unknown): Promise<VdiSessionSummary> {
    this.assertEnabled();
    const normalized = normalizeVdiSessionStartInput(input);
    if (normalized.start_url) {
      this.assertHostAllowed(normalized.start_url);
    }
    try {
      const payload = await this.request<StartSessionResponse>(
        "POST",
        "/session/start",
        normalized,
      );
      if (!payload?.ok || !payload.session?.id) {
        throw new Error("Invalid VDI worker start-session response.");
      }
      this.activeSessions.add(payload.session.id);
      this.sessionsStartedTotal += 1;
      this.lastError = null;
      return payload.session;
    } catch (error) {
      this.lastError = parseErrorMessage(error);
      throw error;
    }
  }

  async executeStep(sessionId: string, input: unknown): Promise<VdiStepResult> {
    this.assertEnabled();
    const normalizedSessionId = String(sessionId || "").trim();
    if (!normalizedSessionId) {
      throw new Error("VDI session id is required.");
    }
    const normalized = normalizeVdiStepInput(input);
    if (normalized.action === "navigate" && normalized.url) {
      this.assertHostAllowed(normalized.url);
    }
    try {
      const payload = await this.request<StepResponse>(
        "POST",
        `/session/${encodeURIComponent(normalizedSessionId)}/step`,
        normalized,
      );
      if (!payload?.ok || !payload.result?.action) {
        throw new Error("Invalid VDI worker step response.");
      }
      this.stepsExecutedTotal += 1;
      this.lastError = null;
      return payload.result;
    } catch (error) {
      this.lastError = parseErrorMessage(error);
      throw error;
    }
  }

  async stopSession(sessionId: string, reason = ""): Promise<VdiSessionSummary> {
    this.assertEnabled();
    const normalizedSessionId = String(sessionId || "").trim();
    if (!normalizedSessionId) {
      throw new Error("VDI session id is required.");
    }
    try {
      const payload = await this.request<StopSessionResponse>(
        "POST",
        `/session/${encodeURIComponent(normalizedSessionId)}/stop`,
        { reason: String(reason || "").trim() || undefined },
      );
      if (!payload?.ok || !payload.session?.id) {
        throw new Error("Invalid VDI worker stop-session response.");
      }
      this.activeSessions.delete(payload.session.id);
      this.sessionsStoppedTotal += 1;
      this.lastError = null;
      return payload.session;
    } catch (error) {
      this.lastError = parseErrorMessage(error);
      throw error;
    }
  }

  async getSession(sessionId: string): Promise<VdiSessionSummary> {
    this.assertEnabled();
    const normalizedSessionId = String(sessionId || "").trim();
    if (!normalizedSessionId) {
      throw new Error("VDI session id is required.");
    }
    const payload = await this.request<SessionResponse>(
      "GET",
      `/session/${encodeURIComponent(normalizedSessionId)}`,
      null,
    );
    if (!payload?.ok || !payload.session?.id) {
      throw new Error("Invalid VDI worker get-session response.");
    }
    return payload.session;
  }

  async listArtifacts(sessionId: string): Promise<string[]> {
    this.assertEnabled();
    const normalizedSessionId = String(sessionId || "").trim();
    if (!normalizedSessionId) {
      throw new Error("VDI session id is required.");
    }
    const payload = await this.request<ArtifactListResponse>(
      "GET",
      `/session/${encodeURIComponent(normalizedSessionId)}/artifacts`,
      null,
    );
    if (!payload?.ok || !Array.isArray(payload.artifacts)) {
      throw new Error("Invalid VDI worker artifacts response.");
    }
    return payload.artifacts.map((value) => String(value || "")).filter(Boolean);
  }

  countBlockedStep(): void {
    this.stepsBlockedTotal += 1;
  }

  private assertEnabled(): void {
    if (!this.options.enabled) {
      throw new Error("VDI runtime is not enabled.");
    }
  }

  private assertHostAllowed(rawUrl: string): void {
    const url = new URL(rawUrl);
    const host = normalizeHost(url.hostname);
    if (!host) {
      this.stepsBlockedTotal += 1;
      throw new Error("VDI navigation blocked: invalid URL host.");
    }
    if (this.options.allowedHosts.length === 0) {
      this.stepsBlockedTotal += 1;
      throw new Error("VDI navigation blocked by allowlist policy (no allowed hosts configured).");
    }
    const allowed = this.options.allowedHosts.some((allowedHost) => {
      return host === allowedHost || host.endsWith(`.${allowedHost}`);
    });
    if (!allowed) {
      this.stepsBlockedTotal += 1;
      throw new Error(`VDI navigation blocked by allowlist policy for host: ${host}`);
    }
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body: unknown,
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.stepTimeoutMs);
    const headers: Record<string, string> = {};
    if (this.options.authToken) {
      headers["x-vdi-token"] = this.options.authToken;
    }
    if (method === "POST") {
      headers["content-type"] = "application/json";
    }
    try {
      const response = await fetch(`${this.options.workerBaseUrl}${path}`, {
        method,
        headers,
        signal: controller.signal,
        body: method === "POST" ? JSON.stringify(body || {}) : undefined,
      });
      const text = await response.text();
      let parsed: unknown = {};
      if (text.trim()) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = { error: text.slice(0, 400) };
        }
      }
      if (!response.ok) {
        const message =
          typeof (parsed as { error?: unknown }).error === "string"
            ? (parsed as { error: string }).error
            : `VDI worker request failed with status ${response.status}.`;
        throw new Error(message);
      }
      return parsed as T;
    } finally {
      clearTimeout(timeout);
    }
  }
}

