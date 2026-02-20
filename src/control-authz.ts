import crypto from "node:crypto";
import fs from "node:fs";
import {
  hmacSha256Hex,
  loadHmacKeyring,
  type HmacKeyring,
  verifyWithAnyKey,
  verifyWithKeyring,
} from "./hmac-keyring";
import { stableStringify } from "./utils";

export type ControlPermission =
  | "*"
  | "system.read"
  | "budget.control"
  | "approvals.read"
  | "approvals.write"
  | "audit.read"
  | "channel.read"
  | "channel.send"
  | "channel.delivery.retry"
  | "channel.connector.reload"
  | "channel.destination.reload"
  | "modality.read"
  | "modality.write"
  | "initiative.read"
  | "initiative.write"
  | "policy.reload"
  | "model.reload"
  | "authz.reload"
  | "approvals.export"
  | "approvals.verify";

export interface ControlIdentity {
  principal: string;
  role: string;
  permissions: Set<ControlPermission>;
}

interface ControlTokenEntry {
  principal: string;
  role: string;
  tokenHash: string;
  permissions: Set<ControlPermission>;
  active: boolean;
}

interface ControlTokenCatalog {
  version: string;
  tokens: Array<{
    principal?: string;
    role?: string;
    token_hash: string;
    permissions?: ControlPermission[];
    active?: boolean;
  }>;
  signature?: string;
  signature_v2?: {
    kid: string;
    sig: string;
  };
}

function parseCatalog(
  filePath: string,
  signingKey: string,
  keyring: HmacKeyring | null,
): ControlTokenEntry[] {
  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw) as ControlTokenCatalog;
  if (!Array.isArray(parsed.tokens)) {
    throw new Error("Invalid control token catalog: tokens array is required.");
  }
  const canonical = {
    version: String(parsed.version || "v1"),
    tokens: parsed.tokens,
  };
  const canonicalPayload = stableStringify(canonical);

  if (keyring) {
    const v2 = parsed.signature_v2;
    if (v2 && typeof v2 === "object") {
      const valid = verifyWithKeyring(canonicalPayload, v2, keyring);
      if (!valid) {
        throw new Error("Control token catalog signature_v2 mismatch.");
      }
    } else {
      const legacySig = String(parsed.signature || "").trim().toLowerCase();
      if (!legacySig) {
        throw new Error("Control token catalog signature missing for keyring verification.");
      }
      const legacyCheck = verifyWithAnyKey(canonicalPayload, legacySig, keyring);
      if (!legacyCheck.valid) {
        throw new Error("Control token catalog legacy signature mismatch under keyring.");
      }
    }
  } else {
    const normalizedSigningKey = signingKey.trim();
    if (normalizedSigningKey) {
      const signature = String(parsed.signature || "").trim().toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(signature)) {
        throw new Error("Control token catalog signature missing or invalid format.");
      }
      const expected = hmacSha256Hex(normalizedSigningKey, canonicalPayload);
      if (signature !== expected) {
        throw new Error("Control token catalog signature mismatch.");
      }
    }
  }

  return parsed.tokens.map((item, index) => {
    const tokenHash = String(item.token_hash || "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(tokenHash)) {
      throw new Error(`Invalid token hash in control token catalog at index ${index}.`);
    }
    const permissions = new Set<ControlPermission>(
      Array.isArray(item.permissions) && item.permissions.length > 0
        ? item.permissions
        : ["system.read"],
    );
    return {
      principal: String(item.principal || `catalog-principal-${index + 1}`),
      role: String(item.role || "operator"),
      tokenHash,
      permissions,
      active: item.active !== false,
    };
  });
}

function tokenHash(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function sha256TokenHex(token: string): string {
  return tokenHash(token);
}

function constantTimeHexEquals(leftHex: string, rightHex: string): boolean {
  if (leftHex.length !== rightHex.length) {
    return false;
  }
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  if (left.length !== right.length || left.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

export class ControlAuthz {
  private entries: ControlTokenEntry[] = [];
  private legacyEntry: ControlTokenEntry;
  private catalogPath: string;
  private catalogSigningKey: string;
  private catalogKeyringPath: string;
  private catalogKeyring: HmacKeyring | null = null;

  constructor(
    legacyControlToken: string,
    catalogPath?: string,
    catalogSigningKey?: string,
    catalogKeyringPath?: string,
  ) {
    const legacyHash = tokenHash(legacyControlToken.trim());
    this.legacyEntry = {
      principal: "legacy-control-token",
      role: "superadmin",
      tokenHash: legacyHash,
      permissions: new Set<ControlPermission>(["*"]),
      active: true,
    };
    this.catalogPath = catalogPath?.trim() || "";
    this.catalogSigningKey = catalogSigningKey?.trim() || "";
    this.catalogKeyringPath = catalogKeyringPath?.trim() || "";
    this.reload();
  }

  authenticate(token: string): ControlIdentity | null {
    const normalized = token.trim();
    if (!normalized) {
      return null;
    }
    const providedHash = tokenHash(normalized);

    for (const entry of this.entries) {
      if (!entry.active) {
        continue;
      }
      if (constantTimeHexEquals(entry.tokenHash, providedHash)) {
        return {
          principal: entry.principal,
          role: entry.role,
          permissions: new Set(entry.permissions),
        };
      }
    }
    return null;
  }

  can(identity: ControlIdentity, permission: ControlPermission): boolean {
    return identity.permissions.has("*") || identity.permissions.has(permission);
  }

  reload(): { hasCatalog: boolean; tokenCount: number } {
    const loaded: ControlTokenEntry[] = [this.legacyEntry];
    this.catalogKeyring = this.catalogKeyringPath ? loadHmacKeyring(this.catalogKeyringPath) : null;
    if (this.catalogPath) {
      loaded.push(...parseCatalog(this.catalogPath, this.catalogSigningKey, this.catalogKeyring));
    }
    this.entries = loaded;
    return this.getState();
  }

  getState(): {
    hasCatalog: boolean;
    tokenCount: number;
    signing_mode: "none" | "static" | "keyring";
    keyring_active_kid: string | null;
    keyring_key_count: number;
  } {
    const signingMode = this.catalogKeyring
      ? "keyring"
      : this.catalogSigningKey
        ? "static"
        : "none";
    return {
      hasCatalog: this.catalogPath.length > 0,
      tokenCount: this.entries.length,
      signing_mode: signingMode,
      keyring_active_kid: this.catalogKeyring?.activeKid || null,
      keyring_key_count: this.catalogKeyring ? Object.keys(this.catalogKeyring.keys).length : 0,
    };
  }
}
