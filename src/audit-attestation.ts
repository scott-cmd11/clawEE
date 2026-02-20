import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  hmacSha256Hex,
  loadHmacKeyring,
  type HmacKeyring,
  signWithKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";
import type { AuditLedger, AuditRow } from "./audit-ledger";
import { stableStringify } from "./utils";

const GENESIS_HASH = "0".repeat(64);

export interface AuditAttestationEntry {
  id: number;
  timestamp: string;
  action_type: string;
  payload: unknown;
  ledger_previous_hash: string;
  ledger_current_hash: string;
  previous_hash: string;
  entry_hash: string;
}

export interface AuditAttestationPayload {
  generated_at: string;
  since: string | null;
  count: number;
  entries: AuditAttestationEntry[];
  final_hash: string;
  signature: string | null;
  signature_kid: string | null;
}

export interface AuditAttestationSealEntry {
  sealed_at: string;
  snapshot_path: string;
  payload_hash: string;
  previous_snapshot_hash: string;
  current_snapshot_hash: string;
  count: number;
  final_hash: string;
  signature: string | null;
  signature_kid: string | null;
}

export interface AuditAttestationVerification {
  valid: boolean;
  reason: string | null;
  count: number;
  computed_final_hash: string;
  stored_final_hash: string;
  signature_valid: boolean | null;
  payload_hash: string;
  generated_at: string;
}

export interface AuditAttestationChainVerification {
  valid: boolean;
  reason: string | null;
  entries: number;
  last_snapshot_hash: string;
}

function parsePayload(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return { parse_error: true, raw };
  }
}

function entryHash(input: {
  previousHash: string;
  row: {
    id: number;
    timestamp: string;
    action_type: string;
    previous_hash: string;
    current_hash: string;
  };
  payload: unknown;
}): string {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        previous_hash: input.previousHash,
        id: input.row.id,
        timestamp: input.row.timestamp,
        action_type: input.row.action_type,
        payload: input.payload,
        ledger_previous_hash: input.row.previous_hash,
        ledger_current_hash: input.row.current_hash,
      }),
    )
    .digest("hex");
}

function payloadHash(payload: AuditAttestationPayload): string {
  return crypto.createHash("sha256").update(stableStringify(payload)).digest("hex");
}

function sealHash(input: {
  sealedAt: string;
  snapshotPath: string;
  payloadHashValue: string;
  previousSnapshotHash: string;
  count: number;
  finalHash: string;
  signature: string | null;
  signatureKid: string | null;
  generatedAt: string;
}): string {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        sealed_at: input.sealedAt,
        snapshot_path: input.snapshotPath,
        payload_hash: input.payloadHashValue,
        previous_snapshot_hash: input.previousSnapshotHash,
        count: input.count,
        final_hash: input.finalHash,
        signature: input.signature,
        signature_kid: input.signatureKid,
        generated_at: input.generatedAt,
      }),
    )
    .digest("hex");
}

export class AuditAttestationService {
  private auditLedger: AuditLedger;
  private defaultExportPath: string;
  private signingKey: string;
  private signingKeyringPath: string;
  private signingKeyring: HmacKeyring | null = null;

  constructor(
    auditLedger: AuditLedger,
    defaultExportPath: string,
    signingKey: string,
    signingKeyringPath = "",
  ) {
    this.auditLedger = auditLedger;
    this.defaultExportPath = defaultExportPath;
    this.signingKey = signingKey.trim();
    this.signingKeyringPath = signingKeyringPath.trim();
    this.reloadSigningKeys();
  }

  reloadSigningKeys(): {
    signing_mode: "none" | "static" | "keyring";
    active_kid: string | null;
    key_count: number;
  } {
    this.signingKeyring = this.signingKeyringPath ? loadHmacKeyring(this.signingKeyringPath) : null;
    return this.getSigningState();
  }

  getSigningState(): {
    signing_mode: "none" | "static" | "keyring";
    active_kid: string | null;
    key_count: number;
  } {
    if (this.signingKeyring) {
      return {
        signing_mode: "keyring",
        active_kid: this.signingKeyring.activeKid,
        key_count: Object.keys(this.signingKeyring.keys).length,
      };
    }
    if (this.signingKey) {
      return {
        signing_mode: "static",
        active_kid: null,
        key_count: 0,
      };
    }
    return {
      signing_mode: "none",
      active_kid: null,
      key_count: 0,
    };
  }

  generate(limit = 1000, since = ""): AuditAttestationPayload {
    const rows = this.auditLedger.listForAttestation(limit, since);
    let previousHash = GENESIS_HASH;
    const entries: AuditAttestationEntry[] = [];

    for (const row of rows) {
      const payload = parsePayload(row.payload);
      const hash = entryHash({
        previousHash,
        row,
        payload,
      });
      entries.push({
        id: row.id,
        timestamp: row.timestamp,
        action_type: row.action_type,
        payload,
        ledger_previous_hash: row.previous_hash,
        ledger_current_hash: row.current_hash,
        previous_hash: previousHash,
        entry_hash: hash,
      });
      previousHash = hash;
    }

    const unsigned: AuditAttestationPayload = {
      generated_at: new Date().toISOString(),
      since: since.trim() || null,
      count: entries.length,
      entries,
      final_hash: previousHash,
      signature: null,
      signature_kid: null,
    };

    const canonical = stableStringify({
      generated_at: unsigned.generated_at,
      since: unsigned.since,
      count: unsigned.count,
      entries: unsigned.entries,
      final_hash: unsigned.final_hash,
    });

    if (this.signingKeyring) {
      const v2 = signWithKeyring(canonical, this.signingKeyring);
      return {
        ...unsigned,
        signature: v2.sig,
        signature_kid: v2.kid,
      };
    }
    if (this.signingKey) {
      return {
        ...unsigned,
        signature: hmacSha256Hex(this.signingKey, canonical),
        signature_kid: null,
      };
    }
    return unsigned;
  }

  exportToFile(options?: { path?: string; limit?: number; since?: string }): {
    output_path: string;
    count: number;
    final_hash: string;
    signature: string | null;
    signature_kid: string | null;
  } {
    const outPath = (options?.path || "").trim() || this.defaultExportPath;
    const payload = this.generate(options?.limit ?? 1000, options?.since ?? "");
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    return {
      output_path: outPath,
      count: payload.count,
      final_hash: payload.final_hash,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
    };
  }

  exportSealedSnapshot(options?: {
    snapshotPath?: string;
    chainPath?: string;
    limit?: number;
    since?: string;
  }): {
    snapshot_path: string;
    chain_path: string;
    count: number;
    final_hash: string;
    signature: string | null;
    signature_kid: string | null;
    current_snapshot_hash: string;
    previous_snapshot_hash: string;
    payload_hash: string;
    generated_at: string;
  } {
    const snapshotPath = (options?.snapshotPath || "").trim() || this.defaultExportPath;
    const chainPath = (options?.chainPath || "").trim() || `${snapshotPath}.chain.jsonl`;
    const payload = this.generate(options?.limit ?? 1000, options?.since ?? "");

    fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
    fs.mkdirSync(path.dirname(chainPath), { recursive: true });
    fs.writeFileSync(snapshotPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

    const payloadHashValue = payloadHash(payload);
    const previousSnapshotHash = this.readLastSnapshotHash(chainPath);
    const sealedAt = new Date().toISOString();
    const currentSnapshotHash = sealHash({
      sealedAt,
      snapshotPath,
      payloadHashValue,
      previousSnapshotHash,
      count: payload.count,
      finalHash: payload.final_hash,
      signature: payload.signature,
      signatureKid: payload.signature_kid,
      generatedAt: payload.generated_at,
    });

    const sealEntry: AuditAttestationSealEntry = {
      sealed_at: sealedAt,
      snapshot_path: snapshotPath,
      payload_hash: payloadHashValue,
      previous_snapshot_hash: previousSnapshotHash,
      current_snapshot_hash: currentSnapshotHash,
      count: payload.count,
      final_hash: payload.final_hash,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
    };
    fs.appendFileSync(chainPath, `${JSON.stringify(sealEntry)}\n`, "utf8");

    return {
      snapshot_path: snapshotPath,
      chain_path: chainPath,
      count: payload.count,
      final_hash: payload.final_hash,
      signature: payload.signature,
      signature_kid: payload.signature_kid,
      current_snapshot_hash: currentSnapshotHash,
      previous_snapshot_hash: previousSnapshotHash,
      payload_hash: payloadHashValue,
      generated_at: payload.generated_at,
    };
  }

  verifyPayload(payload: AuditAttestationPayload): AuditAttestationVerification {
    let previousHash = GENESIS_HASH;
    let reason: string | null = null;
    let valid = true;

    if (!Array.isArray(payload.entries)) {
      valid = false;
      reason = "Payload entries must be an array.";
    }

    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    if (valid && payload.count !== entries.length) {
      valid = false;
      reason = "Payload count does not match entries length.";
    }

    for (const entry of entries) {
      if (!valid) {
        break;
      }
      if (entry.previous_hash !== previousHash) {
        valid = false;
        reason = "Entry previous_hash mismatch.";
        break;
      }
      const expected = entryHash({
        previousHash,
        row: {
          id: Number(entry.id),
          timestamp: String(entry.timestamp),
          action_type: String(entry.action_type),
          previous_hash: String(entry.ledger_previous_hash),
          current_hash: String(entry.ledger_current_hash),
        },
        payload: entry.payload,
      });
      if (expected !== entry.entry_hash) {
        valid = false;
        reason = "Entry hash mismatch.";
        break;
      }
      previousHash = entry.entry_hash;
    }

    if (valid && payload.final_hash !== previousHash) {
      valid = false;
      reason = "Final hash mismatch.";
    }

    let signatureValid: boolean | null = null;
    const canonical = stableStringify({
      generated_at: payload.generated_at,
      since: payload.since,
      count: payload.count,
      entries: payload.entries,
      final_hash: payload.final_hash,
    });
    if (this.signingKeyring) {
      if (payload.signature && payload.signature_kid) {
        signatureValid = verifyWithKeyring(
          canonical,
          {
            kid: payload.signature_kid,
            sig: payload.signature,
          },
          this.signingKeyring,
        );
      } else if (payload.signature && !payload.signature_kid) {
        signatureValid = verifyWithAnyKey(canonical, payload.signature, this.signingKeyring).valid;
      } else {
        signatureValid = false;
      }
      if (!signatureValid && valid) {
        valid = false;
        reason = "Audit attestation keyring signature mismatch.";
      }
    } else if (this.signingKey) {
      const expectedSignature = hmacSha256Hex(this.signingKey, canonical);
      signatureValid = payload.signature === expectedSignature;
      if (!signatureValid && valid) {
        valid = false;
        reason = "Audit attestation signature mismatch.";
      }
    }

    return {
      valid,
      reason,
      count: entries.length,
      computed_final_hash: previousHash,
      stored_final_hash: payload.final_hash,
      signature_valid: signatureValid,
      payload_hash: payloadHash(payload),
      generated_at: payload.generated_at,
    };
  }

  verifySnapshotFile(snapshotPath: string): AuditAttestationVerification {
    const raw = fs.readFileSync(snapshotPath, "utf8");
    const payload = JSON.parse(raw) as AuditAttestationPayload;
    return this.verifyPayload(payload);
  }

  verifySealedChain(
    chainPath: string,
    options?: { verifySnapshots?: boolean },
  ): AuditAttestationChainVerification {
    if (!fs.existsSync(chainPath)) {
      return {
        valid: false,
        reason: "Chain file does not exist.",
        entries: 0,
        last_snapshot_hash: GENESIS_HASH,
      };
    }

    const verifySnapshots = options?.verifySnapshots !== false;
    const raw = fs.readFileSync(chainPath, "utf8");
    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    let previous = GENESIS_HASH;
    for (let i = 0; i < lines.length; i += 1) {
      let parsed: AuditAttestationSealEntry;
      try {
        parsed = JSON.parse(lines[i]) as AuditAttestationSealEntry;
      } catch {
        return {
          valid: false,
          reason: `Invalid JSON in chain line ${i + 1}.`,
          entries: i,
          last_snapshot_hash: previous,
        };
      }

      if (parsed.previous_snapshot_hash !== previous) {
        return {
          valid: false,
          reason: `Chain previous hash mismatch at line ${i + 1}.`,
          entries: i,
          last_snapshot_hash: previous,
        };
      }

      if (verifySnapshots) {
        if (!fs.existsSync(parsed.snapshot_path)) {
          return {
            valid: false,
            reason: `Snapshot file missing for chain line ${i + 1}.`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
        const snapshotRaw = fs.readFileSync(parsed.snapshot_path, "utf8");
        const snapshotPayload = JSON.parse(snapshotRaw) as AuditAttestationPayload;
        const verification = this.verifyPayload(snapshotPayload);
        if (!verification.valid) {
          return {
            valid: false,
            reason: `Snapshot verification failed at line ${i + 1}: ${verification.reason}`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
        if (verification.payload_hash !== parsed.payload_hash) {
          return {
            valid: false,
            reason: `Payload hash mismatch at chain line ${i + 1}.`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
        const expectedSealHash = sealHash({
          sealedAt: parsed.sealed_at,
          snapshotPath: parsed.snapshot_path,
          payloadHashValue: parsed.payload_hash,
          previousSnapshotHash: parsed.previous_snapshot_hash,
          count: parsed.count,
          finalHash: parsed.final_hash,
          signature: parsed.signature,
          signatureKid: parsed.signature_kid,
          generatedAt: verification.generated_at,
        });
        if (expectedSealHash !== parsed.current_snapshot_hash) {
          return {
            valid: false,
            reason: `Seal hash mismatch at chain line ${i + 1}.`,
            entries: i,
            last_snapshot_hash: previous,
          };
        }
      }

      previous = parsed.current_snapshot_hash;
    }

    return {
      valid: true,
      reason: null,
      entries: lines.length,
      last_snapshot_hash: previous,
    };
  }

  private readLastSnapshotHash(chainPath: string): string {
    if (!fs.existsSync(chainPath)) {
      return GENESIS_HASH;
    }
    const raw = fs.readFileSync(chainPath, "utf8");
    const lines = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (lines.length === 0) {
      return GENESIS_HASH;
    }
    const last = JSON.parse(lines[lines.length - 1]) as Partial<AuditAttestationSealEntry>;
    const hash = String(last.current_snapshot_hash || "").trim();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return GENESIS_HASH;
    }
    return hash;
  }
}
