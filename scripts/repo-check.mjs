import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

const requiredFiles = [
  "README.md",
  "CHANGELOG.md",
  "RELEASE.md",
  "openapi/claw-ee.openapi.yaml",
  "Dockerfile",
  "docker-compose.yml",
  "LICENSE",
  "SECURITY.md",
  "CONTRIBUTING.md",
  ".env.example",
  ".github/workflows/security-smoke.yml",
  ".github/workflows/release.yml",
  ".github/workflows/production-validation.yml",
  ".github/pull_request_template.md",
  ".github/ISSUE_TEMPLATE/bug_report.yml",
  ".github/ISSUE_TEMPLATE/feature_request.yml",
  "config/policy-catalog.v1.json",
  "config/model-registry.v1.json",
  "config/capability-catalog.v1.json",
  "config/approval-policy-catalog.v1.json",
  "release-notes/v0.1.0.md",
  "docs/production-validation.md",
];

const strictWorkflowMarkers = [
  {
    path: ".github/workflows/security-smoke.yml",
    markers: ["smoke:security:strict", "REPLAY_REDIS_URL", "REPLAY_POSTGRES_URL"],
  },
  {
    path: ".github/workflows/release.yml",
    markers: ["smoke:security:strict", "REPLAY_REDIS_URL", "REPLAY_POSTGRES_URL"],
  },
  {
    path: ".github/workflows/production-validation.yml",
    markers: ["validate:production", "REPLAY_REDIS_URL", "REPLAY_POSTGRES_URL"],
  },
];

const signatureFiles = [
  "config/policy-catalog.v1.json",
  "config/capability-catalog.v1.json",
  "config/approval-policy-catalog.v1.json",
];

let failures = 0;

for (const rel of requiredFiles) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) {
    failures += 1;
    console.error(`missing: ${rel}`);
  }
}

for (const rel of signatureFiles) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) {
    continue;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(full, "utf8"));
    const sig = String(parsed.signature || "").trim();
    const hasV2 =
      parsed.signature_v2 &&
      typeof parsed.signature_v2 === "object" &&
      String(parsed.signature_v2.kid || "").trim() &&
      String(parsed.signature_v2.sig || "").trim();
    if (!sig && !hasV2) {
      failures += 1;
      console.error(`unsigned catalog: ${rel}`);
    }
  } catch (error) {
    failures += 1;
    console.error(`invalid json: ${rel}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

if (failures > 0) {
  console.error(`repo-check: failed (${failures} issues)`);
  process.exit(1);
}

const gatePath = path.join(root, "src", "uncertainty-gate.ts");
const deliveryPath = path.join(root, "src", "channel-delivery-service.ts");

if (!fs.existsSync(gatePath)) {
  failures += 1;
  console.error("missing: src/uncertainty-gate.ts");
} else {
  const gate = fs.readFileSync(gatePath, "utf8");
  const requiredMarkers = [
    'runtimeEgressGuard.assertAllowed("upstream_base_url")',
    "capabilityPolicy.evaluateToolExecution(",
    "modelRegistry.evaluate(",
    "policyEngine.evaluate(",
    "approvalService.getOrCreatePending(",
    "budgetController.evaluateProjected(",
    "app.get(\"/_clawee/control/security/invariants\"",
    "app.post(\"/_clawee/control/security/conformance/export\"",
    "app.post(\"/_clawee/control/security/conformance/verify\"",
    "app.post(\"/_clawee/intake/:provider/webhook\"",
    "app.post(\"/_clawee/intake/openclaw/work-item\"",
    "parseOpenClawWorkItem(",
    "verifyIntakeHmac(",
    "__claweeSecurityDecisionId",
    "invariantCheck({",
  ];
  for (const marker of requiredMarkers) {
    if (!gate.includes(marker)) {
      failures += 1;
      console.error(`missing security marker: ${marker}`);
    }
  }
  const guardIndex = gate.indexOf("app.use(guardMiddleware);");
  const proxyIndex = gate.indexOf("app.use(\"/\", proxy);");
  if (guardIndex === -1 || proxyIndex === -1) {
    failures += 1;
    console.error("missing middleware ordering markers for guard/proxy");
  } else if (guardIndex > proxyIndex) {
    failures += 1;
    console.error("invalid middleware order: proxy registered before guard");
  }
}

for (const workflow of strictWorkflowMarkers) {
  const full = path.join(root, workflow.path);
  if (!fs.existsSync(full)) {
    continue;
  }
  const content = fs.readFileSync(full, "utf8");
  for (const marker of workflow.markers) {
    if (!content.includes(marker)) {
      failures += 1;
      console.error(`missing workflow strict marker in ${workflow.path}: ${marker}`);
    }
  }
}

if (!fs.existsSync(deliveryPath)) {
  failures += 1;
  console.error("missing: src/channel-delivery-service.ts");
} else {
  const delivery = fs.readFileSync(deliveryPath, "utf8");
  if (!delivery.includes("destinationPolicy.evaluate(")) {
    failures += 1;
    console.error("missing security marker: destinationPolicy.evaluate(");
  }
}

if (failures > 0) {
  console.error(`repo-check: failed (${failures} issues)`);
  process.exit(1);
}

console.log("repo-check: ok");
