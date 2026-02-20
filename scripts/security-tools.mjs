import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
const GENESIS_HASH = "0".repeat(64);

function loadKeyring(pathValue) {
  const raw = fs.readFileSync(pathValue, "utf8");
  const parsed = JSON.parse(raw);
  const activeKid = String(parsed.active_kid || "").trim();
  const keys = parsed.keys || {};
  if (!activeKid || !keys[activeKid]) {
    throw new Error("Invalid keyring: active_kid missing or key not found.");
  }
  return {
    activeKid,
    keys,
  };
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
  const serialized = entries.map(([key, val]) => `${JSON.stringify(key)}:${stableStringify(val)}`);
  return `{${serialized.join(",")}}`;
}

function writeJson(filePath, payload) {
  fs.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function normalizeLowerList(values) {
  return [
    ...new Set(
      (Array.isArray(values) ? values : [])
        .map((v) => String(v).trim().toLowerCase())
        .filter(Boolean),
    ),
  ].sort();
}

function signControlCatalog(inputPath, signingKey, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const canonical = {
    version: String(parsed.version || "v1"),
    tokens: Array.isArray(parsed.tokens) ? parsed.tokens : [],
  };
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = { ...canonical, signature };
  writeJson(outputPath || inputPath, signed);
  return signature;
}

function signControlCatalogKeyring(inputPath, keyringPath, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const canonical = {
    version: String(parsed.version || "v1"),
    tokens: Array.isArray(parsed.tokens) ? parsed.tokens : [],
  };
  const keyring = loadKeyring(keyringPath);
  const sig = crypto
    .createHmac("sha256", String(keyring.keys[keyring.activeKid]))
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = {
    ...canonical,
    signature: parsed.signature || "",
    signature_v2: {
      kid: keyring.activeKid,
      sig,
    },
  };
  writeJson(outputPath || inputPath, signed);
  return {
    kid: keyring.activeKid,
    sig,
  };
}

function signConnectorCatalog(inputPath, signingKey, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const canonical = {
    version: String(parsed.version || "v1"),
    default_timeout_ms: Number(parsed.default_timeout_ms || 10000),
    channels: parsed.channels || {},
  };
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = { ...canonical, signature };
  writeJson(outputPath || inputPath, signed);
  return signature;
}

function signDestinationPolicy(inputPath, signingKey, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const canonical = {
    version: String(parsed.version || "v1"),
    defaults: {
      mode: parsed.defaults?.mode === "deny" ? "deny" : "allow",
      allow_patterns: Array.isArray(parsed.defaults?.allow_patterns)
        ? parsed.defaults.allow_patterns.map((v) => String(v).trim()).filter(Boolean)
        : [],
      deny_patterns: Array.isArray(parsed.defaults?.deny_patterns)
        ? parsed.defaults.deny_patterns.map((v) => String(v).trim()).filter(Boolean)
        : [],
    },
    channels: Object.fromEntries(
      Object.entries(parsed.channels || {}).map(([channel, rule]) => [
        String(channel).trim().toLowerCase(),
        {
          mode: rule?.mode === "deny" ? "deny" : "allow",
          allow_patterns: Array.isArray(rule?.allow_patterns)
            ? rule.allow_patterns.map((v) => String(v).trim()).filter(Boolean)
            : [],
          deny_patterns: Array.isArray(rule?.deny_patterns)
            ? rule.deny_patterns.map((v) => String(v).trim()).filter(Boolean)
            : [],
        },
      ]),
    ),
  };
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = { ...canonical, signature };
  writeJson(outputPath || inputPath, signed);
  return signature;
}

function signCapabilityCatalog(inputPath, signingKey, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const canonical = {
    version: String(parsed.version || "v1"),
    defaults: {
      mode: parsed.defaults?.mode === "deny" ? "deny" : "allow",
      allow_tools: normalizeLowerList(parsed.defaults?.allow_tools),
      deny_tools: normalizeLowerList(parsed.defaults?.deny_tools),
      allow_actions: normalizeLowerList(parsed.defaults?.allow_actions),
      deny_actions: normalizeLowerList(parsed.defaults?.deny_actions),
    },
    channels: Object.fromEntries(
      Object.entries(parsed.channels || {})
        .map(([channel, rules]) => [String(channel).trim().toLowerCase(), rules])
        .filter(([channel]) => Boolean(channel))
        .map(([channel, rules]) => [
          channel,
          {
            mode: rules?.mode === "deny" ? "deny" : "allow",
            allow_tools: normalizeLowerList(rules?.allow_tools),
            deny_tools: normalizeLowerList(rules?.deny_tools),
            allow_actions: normalizeLowerList(rules?.allow_actions),
            deny_actions: normalizeLowerList(rules?.deny_actions),
          },
        ]),
    ),
  };
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = {
    ...canonical,
    signature,
  };
  writeJson(outputPath || inputPath, signed);
  return signature;
}

function signCapabilityCatalogKeyring(inputPath, keyringPath, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const canonical = {
    version: String(parsed.version || "v1"),
    defaults: {
      mode: parsed.defaults?.mode === "deny" ? "deny" : "allow",
      allow_tools: normalizeLowerList(parsed.defaults?.allow_tools),
      deny_tools: normalizeLowerList(parsed.defaults?.deny_tools),
      allow_actions: normalizeLowerList(parsed.defaults?.allow_actions),
      deny_actions: normalizeLowerList(parsed.defaults?.deny_actions),
    },
    channels: Object.fromEntries(
      Object.entries(parsed.channels || {})
        .map(([channel, rules]) => [String(channel).trim().toLowerCase(), rules])
        .filter(([channel]) => Boolean(channel))
        .map(([channel, rules]) => [
          channel,
          {
            mode: rules?.mode === "deny" ? "deny" : "allow",
            allow_tools: normalizeLowerList(rules?.allow_tools),
            deny_tools: normalizeLowerList(rules?.deny_tools),
            allow_actions: normalizeLowerList(rules?.allow_actions),
            deny_actions: normalizeLowerList(rules?.deny_actions),
          },
        ]),
    ),
  };
  const keyring = loadKeyring(keyringPath);
  const sig = crypto
    .createHmac("sha256", String(keyring.keys[keyring.activeKid]))
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = {
    ...canonical,
    signature: parsed.signature || "",
    signature_v2: {
      kid: keyring.activeKid,
      sig,
    },
  };
  writeJson(outputPath || inputPath, signed);
  return {
    kid: keyring.activeKid,
    sig,
  };
}

function normalizeApprovalRequirement(input) {
  return {
    required_approvals: Math.min(5, Math.max(1, Math.floor(Number(input?.required_approvals || 1)))),
    required_roles: normalizeLowerList(input?.required_roles),
  };
}

function signApprovalPolicyCatalog(inputPath, signingKey, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const normalizeMap = (source) =>
    Object.fromEntries(
      Object.entries(source || {})
        .map(([key, req]) => [String(key).trim().toLowerCase(), normalizeApprovalRequirement(req)])
        .filter(([key]) => Boolean(key)),
    );
  const canonical = {
    version: String(parsed.version || "v1"),
    defaults: normalizeApprovalRequirement(parsed.defaults),
    risk_class_overrides: normalizeMap(parsed.risk_class_overrides),
    tool_overrides: normalizeMap(parsed.tool_overrides),
    channel_action_overrides: normalizeMap(parsed.channel_action_overrides),
  };
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = {
    ...canonical,
    signature,
  };
  writeJson(outputPath || inputPath, signed);
  return signature;
}

function signApprovalPolicyCatalogKeyring(inputPath, keyringPath, outputPath) {
  const raw = fs.readFileSync(inputPath, "utf8");
  const parsed = JSON.parse(raw);
  const normalizeMap = (source) =>
    Object.fromEntries(
      Object.entries(source || {})
        .map(([key, req]) => [String(key).trim().toLowerCase(), normalizeApprovalRequirement(req)])
        .filter(([key]) => Boolean(key)),
    );
  const canonical = {
    version: String(parsed.version || "v1"),
    defaults: normalizeApprovalRequirement(parsed.defaults),
    risk_class_overrides: normalizeMap(parsed.risk_class_overrides),
    tool_overrides: normalizeMap(parsed.tool_overrides),
    channel_action_overrides: normalizeMap(parsed.channel_action_overrides),
  };
  const keyring = loadKeyring(keyringPath);
  const sig = crypto
    .createHmac("sha256", String(keyring.keys[keyring.activeKid]))
    .update(stableStringify(canonical))
    .digest("hex");
  const signed = {
    ...canonical,
    signature: parsed.signature || "",
    signature_v2: {
      kid: keyring.activeKid,
      sig,
    },
  };
  writeJson(outputPath || inputPath, signed);
  return {
    kid: keyring.activeKid,
    sig,
  };
}

function entryHash(previousHash, entry) {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        previous_hash: previousHash,
        id: entry.id,
        created_at: entry.created_at,
        expires_at: entry.expires_at,
        status: entry.status,
        request_fingerprint: entry.request_fingerprint,
        reason: entry.reason,
        resolved_by: entry.resolved_by ?? null,
        resolved_at: entry.resolved_at ?? null,
        metadata: entry.metadata,
      }),
    )
    .digest("hex");
}

function payloadHash(payload) {
  return crypto.createHash("sha256").update(stableStringify(payload)).digest("hex");
}

function sealHash(input) {
  return crypto
    .createHash("sha256")
    .update(
      stableStringify({
        sealed_at: input.sealed_at,
        snapshot_path: input.snapshot_path,
        payload_hash: input.payload_hash,
        previous_snapshot_hash: input.previous_snapshot_hash,
        count: input.count,
        final_hash: input.final_hash,
        signature: input.signature ?? null,
        signature_kid: input.signature_kid ?? null,
        generated_at: input.generated_at,
      }),
    )
    .digest("hex");
}

function verifyAttestationSnapshot(snapshotPath, signingKey, keyringPath) {
  const raw = fs.readFileSync(snapshotPath, "utf8");
  const payload = JSON.parse(raw);
  let previous = GENESIS_HASH;
  let valid = true;
  let reason = null;

  if (!Array.isArray(payload.entries)) {
    valid = false;
    reason = "entries is not an array";
  }
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  if (valid && Number(payload.count) !== entries.length) {
    valid = false;
    reason = "count mismatch";
  }
  for (const entry of entries) {
    if (!valid) break;
    if (entry.previous_hash !== previous) {
      valid = false;
      reason = "previous_hash mismatch";
      break;
    }
    const expected = entryHash(previous, entry);
    if (expected !== entry.entry_hash) {
      valid = false;
      reason = "entry_hash mismatch";
      break;
    }
    previous = entry.entry_hash;
  }
  if (valid && payload.final_hash !== previous) {
    valid = false;
    reason = "final_hash mismatch";
  }

  let signatureValid = null;
  const signaturePayload = stableStringify({
    generated_at: payload.generated_at,
    since: payload.since ?? null,
    count: payload.count,
    entries: payload.entries,
    final_hash: payload.final_hash,
  });
  if (keyringPath) {
    const keyring = loadKeyring(keyringPath);
    if (payload.signature && payload.signature_kid && keyring.keys[payload.signature_kid]) {
      const expected = crypto
        .createHmac("sha256", String(keyring.keys[payload.signature_kid]))
        .update(signaturePayload)
        .digest("hex");
      signatureValid = payload.signature === expected;
    } else if (payload.signature) {
      let found = false;
      for (const secret of Object.values(keyring.keys)) {
        const expected = crypto
          .createHmac("sha256", String(secret))
          .update(signaturePayload)
          .digest("hex");
        if (payload.signature === expected) {
          found = true;
          break;
        }
      }
      signatureValid = found;
    } else {
      signatureValid = false;
    }
    if (!signatureValid && valid) {
      valid = false;
      reason = "keyring signature mismatch";
    }
  } else if (signingKey) {
    const expectedSignature = crypto.createHmac("sha256", signingKey).update(signaturePayload).digest("hex");
    signatureValid = payload.signature === expectedSignature;
    if (!signatureValid && valid) {
      valid = false;
      reason = "signature mismatch";
    }
  }

  return {
    valid,
    reason,
    snapshot_path: snapshotPath,
    count: entries.length,
    computed_final_hash: previous,
    stored_final_hash: payload.final_hash,
    signature_valid: signatureValid,
    payload_hash: payloadHash(payload),
    generated_at: payload.generated_at,
  };
}

function verifyAttestationChain(chainPath, signingKey, keyringPath) {
  if (!fs.existsSync(chainPath)) {
    return {
      valid: false,
      reason: "chain file missing",
      entries: 0,
      last_snapshot_hash: GENESIS_HASH,
    };
  }
  const lines = fs
    .readFileSync(chainPath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  let previous = GENESIS_HASH;
  for (let i = 0; i < lines.length; i += 1) {
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return {
        valid: false,
        reason: `invalid json at line ${i + 1}`,
        entries: i,
        last_snapshot_hash: previous,
      };
    }
    if (entry.previous_snapshot_hash !== previous) {
      return {
        valid: false,
        reason: `previous_snapshot_hash mismatch at line ${i + 1}`,
        entries: i,
        last_snapshot_hash: previous,
      };
    }
    if (!entry.snapshot_path || !fs.existsSync(entry.snapshot_path)) {
      return {
        valid: false,
        reason: `snapshot missing at line ${i + 1}`,
        entries: i,
        last_snapshot_hash: previous,
      };
    }
    const snapshot = verifyAttestationSnapshot(entry.snapshot_path, signingKey, keyringPath);
    if (!snapshot.valid) {
      return {
        valid: false,
        reason: `snapshot invalid at line ${i + 1}: ${snapshot.reason}`,
        entries: i,
        last_snapshot_hash: previous,
      };
    }
    if (snapshot.payload_hash !== entry.payload_hash) {
      return {
        valid: false,
        reason: `payload_hash mismatch at line ${i + 1}`,
        entries: i,
        last_snapshot_hash: previous,
      };
    }
    const expectedSealHash = sealHash({
      sealed_at: entry.sealed_at,
      snapshot_path: entry.snapshot_path,
      payload_hash: entry.payload_hash,
      previous_snapshot_hash: entry.previous_snapshot_hash,
      count: entry.count,
      final_hash: entry.final_hash,
      signature: entry.signature ?? null,
      signature_kid: entry.signature_kid ?? null,
      generated_at: snapshot.generated_at,
    });
    if (expectedSealHash !== entry.current_snapshot_hash) {
      return {
        valid: false,
        reason: `current_snapshot_hash mismatch at line ${i + 1}`,
        entries: i,
        last_snapshot_hash: previous,
      };
    }
    previous = entry.current_snapshot_hash;
  }
  return {
    valid: true,
    reason: null,
    entries: lines.length,
    last_snapshot_hash: previous,
    chain_path: chainPath,
  };
}

function auditHash(timestamp, actionType, payload, previousHash) {
  return crypto
    .createHash("sha256")
    .update(`${timestamp}|${actionType}|${payload}|${previousHash}`)
    .digest("hex");
}

function verifyAuditChain(auditDbPath) {
  if (!fs.existsSync(auditDbPath)) {
    return {
      valid: false,
      reason: "audit db file missing",
      total_rows: 0,
      checked_rows: 0,
      first_invalid_id: null,
      chain_tip: GENESIS_HASH,
    };
  }
  const db = new Database(auditDbPath, { readonly: true });
  try {
    const rows = db
      .prepare(
        `
          SELECT id, timestamp, action_type, payload, previous_hash, current_hash
          FROM audit_logs
          ORDER BY id ASC
        `,
      )
      .all();
    let previous = GENESIS_HASH;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.previous_hash !== previous) {
        return {
          valid: false,
          reason: "previous_hash mismatch",
          total_rows: rows.length,
          checked_rows: i,
          first_invalid_id: row.id,
          expected_hash: previous,
          actual_hash: row.previous_hash,
          chain_tip: previous,
        };
      }
      const expectedCurrent = auditHash(
        String(row.timestamp),
        String(row.action_type),
        String(row.payload),
        previous,
      );
      if (row.current_hash !== expectedCurrent) {
        return {
          valid: false,
          reason: "current_hash mismatch",
          total_rows: rows.length,
          checked_rows: i,
          first_invalid_id: row.id,
          expected_hash: expectedCurrent,
          actual_hash: row.current_hash,
          chain_tip: previous,
        };
      }
      previous = row.current_hash;
    }
    return {
      valid: true,
      reason: null,
      total_rows: rows.length,
      checked_rows: rows.length,
      first_invalid_id: null,
      chain_tip: previous,
    };
  } finally {
    db.close();
  }
}

function usage() {
  // eslint-disable-next-line no-console
  console.log(
    [
      "Usage:",
      "  node scripts/security-tools.mjs hash-token <token>",
      "  node scripts/security-tools.mjs sign-control-catalog <inputPath> <signingKey> [outputPath]",
      "  node scripts/security-tools.mjs sign-control-catalog-keyring <inputPath> <keyringPath> [outputPath]",
      "  node scripts/security-tools.mjs sign-connector-catalog <inputPath> <signingKey> [outputPath]",
      "  node scripts/security-tools.mjs sign-destination-policy <inputPath> <signingKey> [outputPath]",
      "  node scripts/security-tools.mjs sign-capability-catalog <inputPath> <signingKey> [outputPath]",
      "  node scripts/security-tools.mjs sign-capability-catalog-keyring <inputPath> <keyringPath> [outputPath]",
      "  node scripts/security-tools.mjs sign-approval-policy-catalog <inputPath> <signingKey> [outputPath]",
      "  node scripts/security-tools.mjs sign-approval-policy-catalog-keyring <inputPath> <keyringPath> [outputPath]",
      "  node scripts/security-tools.mjs verify-attestation-snapshot <snapshotPath> [signingKey]",
      "  node scripts/security-tools.mjs verify-attestation-chain <chainPath> [signingKey]",
      "  node scripts/security-tools.mjs verify-attestation-snapshot-keyring <snapshotPath> <keyringPath>",
      "  node scripts/security-tools.mjs verify-attestation-chain-keyring <chainPath> <keyringPath>",
      "  node scripts/security-tools.mjs verify-audit-chain <auditDbPath>",
    ].join("\n"),
  );
}

function main() {
  const [, , command, ...args] = process.argv;
  if (!command) {
    usage();
    process.exit(1);
  }

  switch (command) {
    case "hash-token": {
      if (args.length < 1) {
        usage();
        process.exit(1);
      }
      // eslint-disable-next-line no-console
      console.log(hashToken(args[0]));
      break;
    }
    case "sign-control-catalog": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, signingKey, outputPath] = args;
      const signature = signControlCatalog(path.resolve(inputPath), signingKey, outputPath ? path.resolve(outputPath) : "");
      // eslint-disable-next-line no-console
      console.log(signature);
      break;
    }
    case "sign-control-catalog-keyring": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, keyringPath, outputPath] = args;
      const signed = signControlCatalogKeyring(
        path.resolve(inputPath),
        path.resolve(keyringPath),
        outputPath ? path.resolve(outputPath) : "",
      );
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(signed, null, 2));
      break;
    }
    case "sign-connector-catalog": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, signingKey, outputPath] = args;
      const signature = signConnectorCatalog(path.resolve(inputPath), signingKey, outputPath ? path.resolve(outputPath) : "");
      // eslint-disable-next-line no-console
      console.log(signature);
      break;
    }
    case "sign-destination-policy": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, signingKey, outputPath] = args;
      const signature = signDestinationPolicy(
        path.resolve(inputPath),
        signingKey,
        outputPath ? path.resolve(outputPath) : "",
      );
      // eslint-disable-next-line no-console
      console.log(signature);
      break;
    }
    case "sign-capability-catalog": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, signingKey, outputPath] = args;
      const signature = signCapabilityCatalog(
        path.resolve(inputPath),
        signingKey,
        outputPath ? path.resolve(outputPath) : "",
      );
      // eslint-disable-next-line no-console
      console.log(signature);
      break;
    }
    case "sign-capability-catalog-keyring": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, keyringPath, outputPath] = args;
      const signed = signCapabilityCatalogKeyring(
        path.resolve(inputPath),
        path.resolve(keyringPath),
        outputPath ? path.resolve(outputPath) : "",
      );
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(signed, null, 2));
      break;
    }
    case "sign-approval-policy-catalog": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, signingKey, outputPath] = args;
      const signature = signApprovalPolicyCatalog(
        path.resolve(inputPath),
        signingKey,
        outputPath ? path.resolve(outputPath) : "",
      );
      // eslint-disable-next-line no-console
      console.log(signature);
      break;
    }
    case "sign-approval-policy-catalog-keyring": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [inputPath, keyringPath, outputPath] = args;
      const signed = signApprovalPolicyCatalogKeyring(
        path.resolve(inputPath),
        path.resolve(keyringPath),
        outputPath ? path.resolve(outputPath) : "",
      );
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(signed, null, 2));
      break;
    }
    case "verify-attestation-snapshot": {
      if (args.length < 1) {
        usage();
        process.exit(1);
      }
      const [snapshotPath, signingKey] = args;
      const result = verifyAttestationSnapshot(path.resolve(snapshotPath), signingKey || "", "");
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.valid ? 0 : 2);
      break;
    }
    case "verify-attestation-chain": {
      if (args.length < 1) {
        usage();
        process.exit(1);
      }
      const [chainPath, signingKey] = args;
      const result = verifyAttestationChain(path.resolve(chainPath), signingKey || "", "");
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.valid ? 0 : 2);
      break;
    }
    case "verify-attestation-snapshot-keyring": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [snapshotPath, keyringPath] = args;
      const result = verifyAttestationSnapshot(path.resolve(snapshotPath), "", path.resolve(keyringPath));
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.valid ? 0 : 2);
      break;
    }
    case "verify-attestation-chain-keyring": {
      if (args.length < 2) {
        usage();
        process.exit(1);
      }
      const [chainPath, keyringPath] = args;
      const result = verifyAttestationChain(path.resolve(chainPath), "", path.resolve(keyringPath));
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.valid ? 0 : 2);
      break;
    }
    case "verify-audit-chain": {
      if (args.length < 1) {
        usage();
        process.exit(1);
      }
      const [auditDbPath] = args;
      const result = verifyAuditChain(path.resolve(auditDbPath));
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.valid ? 0 : 2);
      break;
    }
    default:
      usage();
      process.exit(1);
  }
}

main();
