export type VdiStepAction =
  | "navigate"
  | "click"
  | "type"
  | "select"
  | "wait_for"
  | "screenshot"
  | "extract_text";

export interface VdiSessionStartInput {
  label?: string;
  start_url?: string;
  viewport?: {
    width?: number;
    height?: number;
  };
  metadata?: Record<string, unknown>;
}

export interface VdiSessionSummary {
  id: string;
  label: string;
  status: "active" | "closed";
  started_at: string;
  stopped_at: string | null;
  current_url: string | null;
  metadata: Record<string, unknown>;
}

export interface VdiStepInput {
  action: VdiStepAction;
  url?: string;
  selector?: string;
  text?: string;
  value?: string | string[];
  timeout_ms?: number;
  full_page?: boolean;
  metadata?: Record<string, unknown>;
}

export interface VdiStepResult {
  action: VdiStepAction;
  ok: boolean;
  timestamp: string;
  current_url?: string | null;
  text?: string;
  screenshot_path?: string;
  metadata?: Record<string, unknown>;
}

export interface VdiRuntimeStats {
  enabled: boolean;
  worker_base_url: string;
  allowed_hosts: string[];
  active_sessions: number;
  sessions_started_total: number;
  sessions_stopped_total: number;
  steps_executed_total: number;
  steps_blocked_total: number;
  last_error: string | null;
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

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function normalizeMetadata(value: unknown): Record<string, unknown> {
  return asRecord(value);
}

export function normalizeVdiSessionStartInput(value: unknown): VdiSessionStartInput {
  const record = asRecord(value);
  const viewportRaw = asRecord(record.viewport);
  const viewport: { width?: number; height?: number } = {};
  const width = Number(viewportRaw.width);
  const height = Number(viewportRaw.height);
  if (Number.isFinite(width) && width > 0) {
    viewport.width = clamp(width, 320, 3840);
  }
  if (Number.isFinite(height) && height > 0) {
    viewport.height = clamp(height, 240, 2160);
  }
  return {
    label: str(record.label) || undefined,
    start_url: str(record.start_url) || undefined,
    viewport: Object.keys(viewport).length > 0 ? viewport : undefined,
    metadata: normalizeMetadata(record.metadata),
  };
}

export function normalizeVdiStepInput(value: unknown): VdiStepInput {
  const record = asRecord(value);
  const actionRaw = str(record.action).toLowerCase();
  const action = (
    ["navigate", "click", "type", "select", "wait_for", "screenshot", "extract_text"].includes(
      actionRaw,
    )
      ? actionRaw
      : "screenshot"
  ) as VdiStepAction;
  const timeoutRaw = Number(record.timeout_ms);
  return {
    action,
    url: str(record.url) || undefined,
    selector: str(record.selector) || undefined,
    text: str(record.text) || undefined,
    value: Array.isArray(record.value)
      ? record.value.map((item) => str(item)).filter(Boolean)
      : str(record.value) || undefined,
    timeout_ms: Number.isFinite(timeoutRaw) ? clamp(timeoutRaw, 100, 120000) : undefined,
    full_page: record.full_page === true,
    metadata: normalizeMetadata(record.metadata),
  };
}

