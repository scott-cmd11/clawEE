import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { sha256Hex, stableStringify } from "./utils";
import type {
  CreateInitiativeInput,
  CreateInitiativeTaskInput,
  InitiativeEventRecord,
  InitiativePriority,
  InitiativeRecord,
  InitiativeRiskClass,
  InitiativeStats,
  InitiativeStatus,
  InitiativeTaskRecord,
  InitiativeTaskStatus,
  ListInitiativeFilters,
} from "./initiative-types";

const INITIATIVE_STATUS_VALUES = new Set<InitiativeStatus>([
  "pending",
  "running",
  "paused",
  "completed",
  "cancelled",
  "failed",
]);
const INITIATIVE_PRIORITY_VALUES = new Set<InitiativePriority>(["low", "normal", "high", "urgent"]);
const INITIATIVE_RISK_VALUES = new Set<InitiativeRiskClass>(["low", "medium", "high", "critical"]);
const TASK_STATUS_VALUES = new Set<InitiativeTaskStatus>([
  "queued",
  "running",
  "retry",
  "completed",
  "failed",
  "cancelled",
]);

export interface InitiativeTaskClaim {
  initiative: InitiativeRecord;
  task: InitiativeTaskRecord;
}

function normalizePriority(raw: unknown): InitiativePriority {
  const value = String(raw || "normal").trim().toLowerCase() as InitiativePriority;
  return INITIATIVE_PRIORITY_VALUES.has(value) ? value : "normal";
}

function normalizeRiskClass(raw: unknown): InitiativeRiskClass {
  const value = String(raw || "medium").trim().toLowerCase() as InitiativeRiskClass;
  return INITIATIVE_RISK_VALUES.has(value) ? value : "medium";
}

function normalizeStatus(raw: unknown): InitiativeStatus {
  const value = String(raw || "pending").trim().toLowerCase() as InitiativeStatus;
  return INITIATIVE_STATUS_VALUES.has(value) ? value : "pending";
}

function normalizeTaskStatus(raw: unknown): InitiativeTaskStatus {
  const value = String(raw || "queued").trim().toLowerCase() as InitiativeTaskStatus;
  return TASK_STATUS_VALUES.has(value) ? value : "queued";
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (typeof raw !== "string" || !raw.trim()) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    return parsed as Record<string, unknown>;
  } catch {
    return {};
  }
}

function initiativeFromRow(row: Record<string, unknown>): InitiativeRecord {
  return {
    id: String(row.id || ""),
    source: String(row.source || ""),
    external_ref: row.external_ref ? String(row.external_ref) : null,
    title: String(row.title || ""),
    description: String(row.description || ""),
    priority: normalizePriority(row.priority),
    risk_class: normalizeRiskClass(row.risk_class),
    status: normalizeStatus(row.status),
    requested_by: String(row.requested_by || ""),
    metadata: parseJsonObject(row.metadata),
    created_at: String(row.created_at || ""),
    updated_at: String(row.updated_at || ""),
    started_at: row.started_at ? String(row.started_at) : null,
    finished_at: row.finished_at ? String(row.finished_at) : null,
    last_error: row.last_error ? String(row.last_error) : null,
  };
}

function taskFromRow(row: Record<string, unknown>): InitiativeTaskRecord {
  return {
    id: String(row.id || ""),
    initiative_id: String(row.initiative_id || ""),
    sequence: Number(row.sequence || 0),
    task_type: String(row.task_type || ""),
    payload: parseJsonObject(row.payload),
    status: normalizeTaskStatus(row.status),
    retry_count: Number(row.retry_count || 0),
    max_retries: Number(row.max_retries || 0),
    next_run_at: String(row.next_run_at || ""),
    created_at: String(row.created_at || ""),
    updated_at: String(row.updated_at || ""),
    started_at: row.started_at ? String(row.started_at) : null,
    finished_at: row.finished_at ? String(row.finished_at) : null,
    last_error: row.last_error ? String(row.last_error) : null,
  };
}

function eventFromRow(row: Record<string, unknown>): InitiativeEventRecord {
  return {
    id: Number(row.id || 0),
    initiative_id: String(row.initiative_id || ""),
    task_id: row.task_id ? String(row.task_id) : null,
    event_type: String(row.event_type || ""),
    actor: String(row.actor || ""),
    payload: parseJsonObject(row.payload),
    timestamp: String(row.timestamp || ""),
    previous_hash: String(row.previous_hash || ""),
    current_hash: String(row.current_hash || ""),
  };
}

function nowIso(): string {
  return new Date().toISOString();
}

export class InitiativeStore {
  private dbPath: string;
  private db: Database.Database | null = null;

  constructor(dbPath = path.join(os.homedir(), ".openclaw", "enterprise_initiatives.db")) {
    this.dbPath = dbPath;
  }

  init(): void {
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS initiatives (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        external_ref TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        priority TEXT NOT NULL,
        risk_class TEXT NOT NULL,
        status TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        metadata TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        last_error TEXT
      );

      CREATE UNIQUE INDEX IF NOT EXISTS initiatives_source_external_ref_uniq
      ON initiatives (source, external_ref)
      WHERE external_ref IS NOT NULL AND TRIM(external_ref) <> '';

      CREATE TABLE IF NOT EXISTS initiative_tasks (
        id TEXT PRIMARY KEY,
        initiative_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        task_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL,
        retry_count INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER NOT NULL DEFAULT 3,
        next_run_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        last_error TEXT,
        FOREIGN KEY (initiative_id) REFERENCES initiatives(id)
      );

      CREATE INDEX IF NOT EXISTS initiative_tasks_due_idx
      ON initiative_tasks (status, next_run_at, sequence);

      CREATE INDEX IF NOT EXISTS initiative_tasks_initiative_idx
      ON initiative_tasks (initiative_id, sequence);

      CREATE TABLE IF NOT EXISTS initiative_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        initiative_id TEXT NOT NULL,
        task_id TEXT,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        payload TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL,
        FOREIGN KEY (initiative_id) REFERENCES initiatives(id)
      );

      CREATE INDEX IF NOT EXISTS initiative_events_lookup_idx
      ON initiative_events (initiative_id, id DESC);
    `);
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  createInitiative(input: CreateInitiativeInput): {
    created: boolean;
    initiative: InitiativeRecord;
    tasks: InitiativeTaskRecord[];
  } {
    const db = this.assertDb();
    const source = String(input.source || "").trim().toLowerCase();
    const title = String(input.title || "").trim();
    if (!source) {
      throw new Error("Initiative source is required.");
    }
    if (!title) {
      throw new Error("Initiative title is required.");
    }

    const externalRef = String(input.external_ref || "").trim();
    if (externalRef) {
      const existing = db
        .prepare(
          `
            SELECT *
            FROM initiatives
            WHERE source = ? AND external_ref = ?
            LIMIT 1
          `,
        )
        .get(source, externalRef) as Record<string, unknown> | undefined;
      if (existing) {
        const existingInitiative = initiativeFromRow(existing);
        return {
          created: false,
          initiative: existingInitiative,
          tasks: this.listInitiativeTasks(existingInitiative.id),
        };
      }
    }

    const createdAt = nowIso();
    const initiativeId = crypto.randomUUID();
    const priority = normalizePriority(input.priority);
    const riskClass = normalizeRiskClass(input.risk_class);
    const requestedBy = String(input.requested_by || "manual-operator").trim() || "manual-operator";
    const description = String(input.description || "").trim();
    const metadata = input.metadata && typeof input.metadata === "object" ? input.metadata : {};
    const tasksInput = Array.isArray(input.tasks) ? input.tasks : [];

    const tx = db.transaction(() => {
      db.prepare(
        `
          INSERT INTO initiatives (
            id, source, external_ref, title, description, priority, risk_class, status, requested_by, metadata,
            created_at, updated_at, started_at, finished_at, last_error
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, NULL, NULL, NULL)
        `,
      ).run(
        initiativeId,
        source,
        externalRef || null,
        title,
        description,
        priority,
        riskClass,
        requestedBy,
        stableStringify(metadata),
        createdAt,
        createdAt,
      );

      tasksInput.forEach((taskInput, index) => {
        this.insertTask(db, initiativeId, index + 1, taskInput, createdAt);
      });
    });
    tx();

    const initiative = this.getInitiativeById(initiativeId);
    if (!initiative) {
      throw new Error("Failed to create initiative.");
    }
    const tasks = this.listInitiativeTasks(initiativeId);
    return {
      created: true,
      initiative,
      tasks,
    };
  }

  listInitiatives(filters: ListInitiativeFilters = {}): InitiativeRecord[] {
    const db = this.assertDb();
    const where: string[] = [];
    const params: Array<string | number> = [];

    if (filters.status) {
      where.push("status = ?");
      params.push(filters.status);
    }
    if (filters.source) {
      where.push("source = ?");
      params.push(filters.source.trim().toLowerCase());
    }
    if (filters.priority) {
      where.push("priority = ?");
      params.push(filters.priority);
    }
    const limit = Math.min(Math.max(1, Math.floor(Number(filters.limit || 100))), 1000);
    params.push(limit);
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    return db
      .prepare(
        `
          SELECT *
          FROM initiatives
          ${whereSql}
          ORDER BY updated_at DESC
          LIMIT ?
        `,
      )
      .all(...params)
      .map((row) => initiativeFromRow(row as Record<string, unknown>));
  }

  getInitiativeById(id: string): InitiativeRecord | null {
    const db = this.assertDb();
    const row = db
      .prepare(
        `
          SELECT *
          FROM initiatives
          WHERE id = ?
          LIMIT 1
        `,
      )
      .get(id) as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    return initiativeFromRow(row);
  }

  listInitiativeTasks(initiativeId: string): InitiativeTaskRecord[] {
    const db = this.assertDb();
    return db
      .prepare(
        `
          SELECT *
          FROM initiative_tasks
          WHERE initiative_id = ?
          ORDER BY sequence ASC
        `,
      )
      .all(initiativeId)
      .map((row) => taskFromRow(row as Record<string, unknown>));
  }

  listInitiativeEvents(initiativeId: string, limit = 200): InitiativeEventRecord[] {
    const db = this.assertDb();
    const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 5000);
    return db
      .prepare(
        `
          SELECT *
          FROM initiative_events
          WHERE initiative_id = ?
          ORDER BY id DESC
          LIMIT ?
        `,
      )
      .all(initiativeId, safeLimit)
      .map((row) => eventFromRow(row as Record<string, unknown>));
  }

  setInitiativeStatus(
    initiativeId: string,
    status: InitiativeStatus,
    actor: string,
    reason = "",
  ): InitiativeRecord {
    const db = this.assertDb();
    const existing = this.getInitiativeById(initiativeId);
    if (!existing) {
      throw new Error("Initiative not found.");
    }

    const now = nowIso();
    const startedAt =
      status === "running" && !existing.started_at ? now : existing.started_at;
    const finishedAt =
      status === "completed" || status === "cancelled" || status === "failed" ? now : existing.finished_at;

    db.prepare(
      `
        UPDATE initiatives
        SET status = ?, updated_at = ?, started_at = ?, finished_at = ?, last_error = ?
        WHERE id = ?
      `,
    ).run(status, now, startedAt, finishedAt, reason || null, initiativeId);

    this.appendEvent(initiativeId, null, `initiative.${status}`, actor, {
      reason: reason || null,
      previous_status: existing.status,
      new_status: status,
    });

    if (status === "cancelled") {
      db.prepare(
        `
          UPDATE initiative_tasks
          SET status = 'cancelled', updated_at = ?
          WHERE initiative_id = ?
            AND status IN ('queued', 'running', 'retry')
        `,
      ).run(now, initiativeId);
    }

    const updated = this.getInitiativeById(initiativeId);
    if (!updated) {
      throw new Error("Initiative status update failed.");
    }
    return updated;
  }

  appendEvent(
    initiativeId: string,
    taskId: string | null,
    eventType: string,
    actor: string,
    payload: Record<string, unknown>,
    timestamp = nowIso(),
  ): InitiativeEventRecord {
    const db = this.assertDb();
    const serializedPayload = stableStringify(payload || {});
    const previousHash =
      (db
        .prepare(
          `
            SELECT current_hash
            FROM initiative_events
            WHERE initiative_id = ?
            ORDER BY id DESC
            LIMIT 1
          `,
        )
        .get(initiativeId) as { current_hash: string } | undefined)?.current_hash || "0".repeat(64);
    const currentHash = sha256Hex(
      `${initiativeId}|${taskId || ""}|${eventType}|${actor}|${timestamp}|${serializedPayload}|${previousHash}`,
    );
    const result = db
      .prepare(
        `
          INSERT INTO initiative_events (
            initiative_id, task_id, event_type, actor, payload, timestamp, previous_hash, current_hash
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
      )
      .run(
        initiativeId,
        taskId,
        eventType,
        actor || "system",
        serializedPayload,
        timestamp,
        previousHash,
        currentHash,
      );

    const row = db
      .prepare("SELECT * FROM initiative_events WHERE id = ?")
      .get(Number(result.lastInsertRowid)) as Record<string, unknown>;
    return eventFromRow(row);
  }

  claimNextDueTask(nodeId: string): InitiativeTaskClaim | null {
    const db = this.assertDb();
    const now = nowIso();

    let claim: InitiativeTaskClaim | null = null;
    const tx = db.transaction(() => {
      const row = db
        .prepare(
          `
            SELECT
              t.id AS task_id,
              t.initiative_id AS task_initiative_id
            FROM initiative_tasks t
            JOIN initiatives i ON i.id = t.initiative_id
            WHERE i.status = 'running'
              AND t.status IN ('queued', 'retry')
              AND t.next_run_at <= ?
            ORDER BY
              CASE i.priority
                WHEN 'urgent' THEN 4
                WHEN 'high' THEN 3
                WHEN 'normal' THEN 2
                ELSE 1
              END DESC,
              t.sequence ASC
            LIMIT 1
          `,
        )
        .get(now) as { task_id: string; task_initiative_id: string } | undefined;

      if (!row) {
        return;
      }

      const update = db
        .prepare(
          `
            UPDATE initiative_tasks
            SET status = 'running',
                started_at = ?,
                updated_at = ?
            WHERE id = ?
              AND status IN ('queued', 'retry')
          `,
        )
        .run(now, now, row.task_id);
      if (update.changes === 0) {
        return;
      }

      const initiative = this.getInitiativeById(row.task_initiative_id);
      const taskRow = db
        .prepare("SELECT * FROM initiative_tasks WHERE id = ? LIMIT 1")
        .get(row.task_id) as Record<string, unknown> | undefined;
      if (!initiative || !taskRow) {
        return;
      }
      claim = {
        initiative,
        task: taskFromRow(taskRow),
      };

      this.appendEvent(row.task_initiative_id, row.task_id, "task.started", `node:${nodeId}`, {
        started_at: now,
      });
    });
    tx();

    return claim;
  }

  completeTask(initiativeId: string, taskId: string, actor: string, payload: Record<string, unknown>): void {
    const db = this.assertDb();
    const now = nowIso();
    db.prepare(
      `
        UPDATE initiative_tasks
        SET status = 'completed',
            updated_at = ?,
            finished_at = ?,
            last_error = NULL
        WHERE id = ?
      `,
    ).run(now, now, taskId);
    this.appendEvent(initiativeId, taskId, "task.completed", actor, payload, now);
    this.reconcileInitiativeStatus(initiativeId, actor);
  }

  failTaskWithRetry(input: {
    initiativeId: string;
    taskId: string;
    actor: string;
    retryCount: number;
    maxRetries: number;
    errorMessage: string;
    nextRunAt: string;
  }): void {
    const db = this.assertDb();
    const now = nowIso();
    const exhausted = input.retryCount > input.maxRetries;
    const status: InitiativeTaskStatus = exhausted ? "failed" : "retry";
    db.prepare(
      `
        UPDATE initiative_tasks
        SET status = ?,
            retry_count = ?,
            updated_at = ?,
            next_run_at = ?,
            finished_at = ?,
            last_error = ?
        WHERE id = ?
      `,
    ).run(
      status,
      input.retryCount,
      now,
      input.nextRunAt,
      exhausted ? now : null,
      input.errorMessage,
      input.taskId,
    );
    this.appendEvent(input.initiativeId, input.taskId, "task.failed", input.actor, {
      retry_count: input.retryCount,
      max_retries: input.maxRetries,
      exhausted,
      error: input.errorMessage,
      next_run_at: input.nextRunAt,
    });
    this.reconcileInitiativeStatus(input.initiativeId, input.actor);
  }

  reconcileInitiativeStatus(initiativeId: string, actor: string): InitiativeRecord {
    const db = this.assertDb();
    const initiative = this.getInitiativeById(initiativeId);
    if (!initiative) {
      throw new Error("Initiative not found.");
    }
    const counts = db
      .prepare(
        `
          SELECT
            SUM(CASE WHEN status IN ('queued', 'running', 'retry') THEN 1 ELSE 0 END) AS active_count,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_count
          FROM initiative_tasks
          WHERE initiative_id = ?
        `,
      )
      .get(initiativeId) as {
      active_count: number | null;
      failed_count: number | null;
      completed_count: number | null;
    };

    const activeCount = Number(counts.active_count || 0);
    const failedCount = Number(counts.failed_count || 0);
    const completedCount = Number(counts.completed_count || 0);
    if (activeCount > 0) {
      return initiative;
    }

    let nextStatus: InitiativeStatus = initiative.status;
    if (failedCount > 0) {
      nextStatus = "failed";
    } else if (completedCount > 0 && initiative.status !== "cancelled") {
      nextStatus = "completed";
    }

    if (nextStatus === initiative.status) {
      return initiative;
    }

    return this.setInitiativeStatus(
      initiativeId,
      nextStatus,
      actor,
      nextStatus === "failed" ? "One or more tasks exhausted retries." : "",
    );
  }

  getStats(): InitiativeStats {
    const db = this.assertDb();
    const initiativeCounts = db
      .prepare(
        `
          SELECT status, COUNT(*) AS count
          FROM initiatives
          GROUP BY status
        `,
      )
      .all() as Array<{ status: InitiativeStatus; count: number }>;

    const taskCounts = db
      .prepare(
        `
          SELECT status, COUNT(*) AS count
          FROM initiative_tasks
          GROUP BY status
        `,
      )
      .all() as Array<{ status: InitiativeTaskStatus; count: number }>;

    const statusMap: Record<string, number> = {};
    for (const row of initiativeCounts) {
      statusMap[row.status] = Number(row.count || 0);
    }
    const taskMap: Record<string, number> = {};
    for (const row of taskCounts) {
      taskMap[row.status] = Number(row.count || 0);
    }

    return {
      enabled: true,
      total:
        (statusMap.pending || 0) +
        (statusMap.running || 0) +
        (statusMap.paused || 0) +
        (statusMap.completed || 0) +
        (statusMap.cancelled || 0) +
        (statusMap.failed || 0),
      pending: statusMap.pending || 0,
      running: statusMap.running || 0,
      paused: statusMap.paused || 0,
      completed: statusMap.completed || 0,
      cancelled: statusMap.cancelled || 0,
      failed: statusMap.failed || 0,
      task_queued: taskMap.queued || 0,
      task_running: taskMap.running || 0,
      task_retry: taskMap.retry || 0,
      task_failed: taskMap.failed || 0,
    };
  }

  private insertTask(
    db: Database.Database,
    initiativeId: string,
    sequence: number,
    taskInput: CreateInitiativeTaskInput,
    createdAt: string,
  ): void {
    const taskType = String(taskInput.task_type || "").trim().toLowerCase();
    if (!taskType) {
      return;
    }
    const taskId = crypto.randomUUID();
    const payload =
      taskInput.payload && typeof taskInput.payload === "object" && !Array.isArray(taskInput.payload)
        ? taskInput.payload
        : {};
    const maxRetries = Math.min(Math.max(0, Math.floor(Number(taskInput.max_retries ?? 3))), 20);
    db.prepare(
      `
        INSERT INTO initiative_tasks (
          id, initiative_id, sequence, task_type, payload, status, retry_count, max_retries, next_run_at,
          created_at, updated_at, started_at, finished_at, last_error
        )
        VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?, NULL, NULL, NULL)
      `,
    ).run(
      taskId,
      initiativeId,
      sequence,
      taskType,
      stableStringify(payload),
      maxRetries,
      createdAt,
      createdAt,
      createdAt,
    );
  }

  private assertDb(): Database.Database {
    if (!this.db) {
      throw new Error("Initiative store is not initialized.");
    }
    return this.db;
  }
}
