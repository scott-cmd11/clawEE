import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { redactSensitive, stableStringify } from "./utils";

export type AuditActionType =
  | "ACTION_FORWARDED"
  | "RISK_SCORED"
  | "RISK_HIGH_WARNING"
  | "RISK_BLOCKED_ACTION"
  | "BUDGET_COST_RECORDED"
  | "TOKEN_BUDGET_BLOCKED"
  | "BUDGET_SUSPENDED"
  | "BUDGET_RESUMED"
  | "CONTROL_ACCESS_DENIED"
  | "CONTROL_SCOPE_DENIED"
  | "RATE_LIMIT_BLOCKED"
  | "POLICY_BLOCKED_ACTION"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_CREATED"
  | "APPROVAL_GRANTED"
  | "APPROVAL_DENIED"
  | "APPROVAL_CONFLICT_OF_INTEREST_DENIED"
  | "APPROVAL_TOKEN_REPLAY_BLOCKED"
  | "APPROVAL_ATTESTATION_GENERATED"
  | "APPROVAL_ATTESTATION_EXPORTED"
  | "APPROVAL_ATTESTATION_PERIODIC_EXPORTED"
  | "APPROVAL_ATTESTATION_VERIFIED"
  | "APPROVAL_ATTESTATION_SIGNING_RELOADED"
  | "APPROVAL_ATTESTATION_SNAPSHOTS_PRUNED"
  | "AUDIT_ATTESTATION_GENERATED"
  | "AUDIT_ATTESTATION_EXPORTED"
  | "AUDIT_ATTESTATION_VERIFIED"
  | "AUDIT_ATTESTATION_SIGNING_RELOADED"
  | "SECURITY_INVARIANT_VIOLATION"
  | "SECURITY_CONFORMANCE_EXPORTED"
  | "SECURITY_CONFORMANCE_VERIFIED"
  | "APPROVAL_POLICY_LOADED"
  | "APPROVAL_POLICY_RELOADED"
  | "HEARTBEAT_TICK"
  | "HEARTBEAT_TASK_DUE"
  | "MODALITY_OBSERVATION"
  | "MODALITY_PAYLOAD_BLOCKED"
  | "CHANNEL_EVENT_INGESTED"
  | "CHANNEL_INGRESS_PAYLOAD_BLOCKED"
  | "CHANNEL_MESSAGE_QUEUED"
  | "CHANNEL_MESSAGE_SIZE_BLOCKED"
  | "CHANNEL_INGRESS_SIGNATURE_DENIED"
  | "CHANNEL_INGRESS_REPLAY_BLOCKED"
  | "CHANNEL_INGRESS_EVENT_REPLAY_BLOCKED"
  | "CHANNEL_DELIVERY_SENT"
  | "CHANNEL_DELIVERY_FAILED"
  | "CHANNEL_DELIVERY_RETRY_FORCED"
  | "CHANNEL_DESTINATION_POLICY_LOADED"
  | "CHANNEL_DESTINATION_POLICY_RELOADED"
  | "CHANNEL_DESTINATION_BLOCKED"
  | "CHANNEL_CONNECTOR_CATALOG_LOADED"
  | "CHANNEL_CONNECTOR_CATALOG_RELOADED"
  | "CAPABILITY_CATALOG_LOADED"
  | "CAPABILITY_CATALOG_RELOADED"
  | "CAPABILITY_BLOCKED_ACTION"
  | "TRANSPORT_SECURITY_READY"
  | "TRANSPORT_SECURITY_VIOLATION"
  | "POLICY_CATALOG_LOADED"
  | "POLICY_CATALOG_RELOADED"
  | "MODEL_REGISTRY_RELOADED"
  | "CONTROL_TOKEN_CATALOG_LOADED"
  | "CONTROL_TOKEN_CATALOG_RELOADED"
  | "AIRGAP_ATTESTED"
  | "AIRGAP_POLICY_VIOLATION"
  | "MODEL_REGISTRY_LOADED"
  | "REPLAY_STORE_READY"
  | "CLUSTER_CONFIG_WARNING"
  | "INITIATIVE_CREATED"
  | "INITIATIVE_DEDUPED"
  | "INITIATIVE_TASK_SCHEDULED"
  | "INITIATIVE_TASK_STARTED"
  | "INITIATIVE_TASK_COMPLETED"
  | "INITIATIVE_TASK_FAILED"
  | "INITIATIVE_INTERRUPTED"
  | "INITIATIVE_STATUS_CHANGED"
  | "INITIATIVE_ENGINE_READY"
  | "AUDIT_CHAIN_VERIFIED"
  | "MODEL_POLICY_BLOCKED"
  | "RUNTIME_EGRESS_BLOCKED"
  | "AFFECTIVE_OVERRIDE_SET"
  | "AFFECTIVE_OVERRIDE_CLEARED"
  | "SYSTEM_ERROR";

export interface AuditRow {
  id: number;
  timestamp: string;
  action_type: AuditActionType;
  payload: string;
  previous_hash: string;
  current_hash: string;
}

export interface AuditIntegrityReport {
  valid: boolean;
  total_rows: number;
  checked_rows: number;
  first_invalid_id: number | null;
  reason: string | null;
  expected_hash: string | null;
  actual_hash: string | null;
  chain_tip: string;
}

export interface AuditLedger {
  init(): void;
  logAndSignAction(actionType: AuditActionType, payload: unknown): AuditRow;
  getRecent(limit?: number): AuditRow[];
  listForAttestation(limit?: number, since?: string): AuditRow[];
  getCount(): number;
  verifyIntegrity(): AuditIntegrityReport;
  close(): void;
}

const GENESIS_HASH = "0".repeat(64);

export class SqliteAuditLedger implements AuditLedger {
  private dbPath: string;
  private db: Database.Database | null = null;

  constructor(dbPath = path.join(os.homedir(), ".openclaw", "enterprise_audit.db")) {
    this.dbPath = dbPath;
  }

  init(): void {
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL
      );
    `);
  }

  logAndSignAction(actionType: AuditActionType, payload: unknown): AuditRow {
    const db = this.assertDb();
    const timestamp = new Date().toISOString();
    const serializedPayload = stableStringify(redactSensitive(payload));
    const previousHash = this.latestHash(db);
    const currentHash = this.computeCurrentHash(
      timestamp,
      actionType,
      serializedPayload,
      previousHash,
    );

    const result = db
      .prepare(
        `
          INSERT INTO audit_logs (timestamp, action_type, payload, previous_hash, current_hash)
          VALUES (?, ?, ?, ?, ?)
        `,
      )
      .run(timestamp, actionType, serializedPayload, previousHash, currentHash);

    const inserted = db
      .prepare(
        `
          SELECT id, timestamp, action_type, payload, previous_hash, current_hash
          FROM audit_logs
          WHERE id = ?
        `,
      )
      .get(Number(result.lastInsertRowid)) as AuditRow;

    return inserted;
  }

  getRecent(limit = 100): AuditRow[] {
    const db = this.assertDb();
    const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 1000);
    return db
      .prepare(
        `
          SELECT id, timestamp, action_type, payload, previous_hash, current_hash
          FROM audit_logs
          ORDER BY id DESC
          LIMIT ?
        `,
      )
      .all(safeLimit) as AuditRow[];
  }

  listForAttestation(limit = 1000, since = ""): AuditRow[] {
    const db = this.assertDb();
    const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 20000);
    const sinceValue = since.trim();
    if (sinceValue) {
      return db
        .prepare(
          `
            SELECT id, timestamp, action_type, payload, previous_hash, current_hash
            FROM audit_logs
            WHERE timestamp > ?
            ORDER BY id ASC
            LIMIT ?
          `,
        )
        .all(sinceValue, safeLimit) as AuditRow[];
    }
    return db
      .prepare(
        `
          SELECT id, timestamp, action_type, payload, previous_hash, current_hash
          FROM audit_logs
          ORDER BY id ASC
          LIMIT ?
        `,
      )
      .all(safeLimit) as AuditRow[];
  }

  getCount(): number {
    const db = this.assertDb();
    const row = db
      .prepare(
        `
          SELECT COUNT(*) AS count
          FROM audit_logs
        `,
      )
      .get() as { count: number };
    return Number(row.count || 0);
  }

  verifyIntegrity(): AuditIntegrityReport {
    const db = this.assertDb();
    const rows = db
      .prepare(
        `
          SELECT id, timestamp, action_type, payload, previous_hash, current_hash
          FROM audit_logs
          ORDER BY id ASC
        `,
      )
      .all() as AuditRow[];

    let expectedPreviousHash = GENESIS_HASH;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.previous_hash !== expectedPreviousHash) {
        return {
          valid: false,
          total_rows: rows.length,
          checked_rows: i,
          first_invalid_id: row.id,
          reason: "previous_hash mismatch",
          expected_hash: expectedPreviousHash,
          actual_hash: row.previous_hash,
          chain_tip: expectedPreviousHash,
        };
      }
      const expectedCurrentHash = this.computeCurrentHash(
        row.timestamp,
        row.action_type,
        row.payload,
        expectedPreviousHash,
      );
      if (row.current_hash !== expectedCurrentHash) {
        return {
          valid: false,
          total_rows: rows.length,
          checked_rows: i,
          first_invalid_id: row.id,
          reason: "current_hash mismatch",
          expected_hash: expectedCurrentHash,
          actual_hash: row.current_hash,
          chain_tip: expectedPreviousHash,
        };
      }
      expectedPreviousHash = row.current_hash;
    }

    return {
      valid: true,
      total_rows: rows.length,
      checked_rows: rows.length,
      first_invalid_id: null,
      reason: null,
      expected_hash: null,
      actual_hash: null,
      chain_tip: expectedPreviousHash,
    };
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  private assertDb(): Database.Database {
    if (!this.db) {
      throw new Error("Audit ledger is not initialized.");
    }
    return this.db;
  }

  private latestHash(db: Database.Database): string {
    return (
      (db.prepare("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1").get() as
        | { current_hash: string }
        | undefined)?.current_hash ?? GENESIS_HASH
    );
  }

  private computeCurrentHash(
    timestamp: string,
    actionType: string,
    serializedPayload: string,
    previousHash: string,
  ): string {
    return crypto
      .createHash("sha256")
      .update(`${timestamp}|${actionType}|${serializedPayload}|${previousHash}`)
      .digest("hex");
  }
}
