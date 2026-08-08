// Dev-only fixtures mirroring the backend demo profile (acme/payment-service,
// the Log4Shell PR). Enabled with VITE_MOCK=1 so the dashboard renders without
// a running backend — used for UI work and offline preview. Never bundled when
// VITE_MOCK is unset (tree-shaken; api.ts guards on the flag).
import type {
  Finding,
  GateEvaluation,
  OrgOverview,
  RepositorySummary,
  ScanSummary,
  TrendPoint,
} from "./types";

const ORG_ID = "6f1a0b2c-1111-4a00-9000-000000000001";
const REPO_ID = "6f1a0b2c-2222-4a00-9000-000000000002";
const REPO2_ID = "6f1a0b2c-2222-4a00-9000-000000000003";
const REPO3_ID = "6f1a0b2c-2222-4a00-9000-000000000004";
const BASE_SCAN = "6f1a0b2c-3333-4a00-9000-000000000005";
const HEAD_SCAN = "6f1a0b2c-3333-4a00-9000-000000000006";
const PRIOR_SCAN = "6f1a0b2c-3333-4a00-9000-000000000007";

const iso = (daysAgo: number) => new Date(Date.now() - daysAgo * 86_400_000).toISOString();

export const repositories: RepositorySummary[] = [
  { id: REPO_ID, fullName: "acme/payment-service", defaultBranch: "main", organizationId: ORG_ID },
  { id: REPO2_ID, fullName: "acme/checkout-web", defaultBranch: "main", organizationId: ORG_ID },
  { id: REPO3_ID, fullName: "acme/ledger-core", defaultBranch: "main", organizationId: ORG_ID },
];

export const orgOverview: OrgOverview = {
  organizationId: ORG_ID,
  login: "acme",
  repositoryCount: 3,
  openFindings: 9,
  openCriticals: 3,
  kevFindings: 1,
  repositories: [
    {
      repositoryId: REPO_ID,
      fullName: "acme/payment-service",
      latestScanId: HEAD_SCAN,
      latestGate: "FAIL",
      lastScannedAt: iso(0),
      openFindings: 5,
      openCriticals: 3,
      kevFindings: 1,
      topRiskScore: 0.96,
    },
    {
      repositoryId: REPO2_ID,
      fullName: "acme/checkout-web",
      latestScanId: PRIOR_SCAN,
      latestGate: "WARN",
      lastScannedAt: iso(2),
      openFindings: 4,
      openCriticals: 0,
      kevFindings: 0,
      topRiskScore: 0.58,
    },
    {
      repositoryId: REPO3_ID,
      fullName: "acme/ledger-core",
      latestScanId: null,
      latestGate: null,
      lastScannedAt: null,
      openFindings: 0,
      openCriticals: 0,
      kevFindings: 0,
      topRiskScore: 0,
    },
  ],
};

export const trend: TrendPoint[] = [
  { scanId: "s1", commitSha: "9a1c3e2", scannedAt: iso(28), gate: "PASS", totalFindings: 2, criticals: 0, highs: 1, topRiskScore: 0.34 },
  { scanId: "s2", commitSha: "b52d81f", scannedAt: iso(21), gate: "PASS", totalFindings: 2, criticals: 0, highs: 1, topRiskScore: 0.34 },
  { scanId: BASE_SCAN, commitSha: "a3f8c2d", scannedAt: iso(14), gate: "PASS", totalFindings: 2, criticals: 0, highs: 1, topRiskScore: 0.34 },
  { scanId: "s4", commitSha: "c7e0a91", scannedAt: iso(7), gate: "WARN", totalFindings: 3, criticals: 0, highs: 2, topRiskScore: 0.61 },
  { scanId: HEAD_SCAN, commitSha: "e7b4d1f", scannedAt: iso(0), gate: "FAIL", totalFindings: 5, criticals: 3, highs: 1, topRiskScore: 0.96 },
];

export const scans: ScanSummary[] = [
  {
    id: HEAD_SCAN,
    repositoryId: REPO_ID,
    commitSha: "e7b4d1f82c9a6e3b5d0f8c2a7e4b9d1c6f3a8e5b",
    ref: "feat/audit-logging",
    prNumber: 42,
    trigger: "PR",
    status: "COMPLETED",
    gateResult: "FAIL",
    createdAt: iso(0),
    finishedAt: iso(0),
    totalFindings: 5,
    findingsBySeverity: { CRITICAL: 3, HIGH: 1, MEDIUM: 1 },
    topRiskScore: 0.96,
    engines: [
      { engine: "TRIVY", version: "0.63.0", status: "COMPLETED", durationMs: 4120 },
      { engine: "SEMGREP", version: "1.99.0", status: "COMPLETED", durationMs: 8330 },
      { engine: "DEPENDENCY_CHECK", version: "12.1.0", status: "COMPLETED", durationMs: 15200 },
    ],
  },
  {
    id: BASE_SCAN,
    repositoryId: REPO_ID,
    commitSha: "a3f8c2d94b7e1a5c8f2b6d0e9a4c7b3f5d8e1a2c",
    ref: "main",
    prNumber: null,
    trigger: "PUSH",
    status: "COMPLETED",
    gateResult: "PASS",
    createdAt: iso(14),
    finishedAt: iso(14),
    totalFindings: 2,
    findingsBySeverity: { HIGH: 1, MEDIUM: 1 },
    topRiskScore: 0.34,
    engines: [{ engine: "TRIVY", version: "0.63.0", status: "COMPLETED", durationMs: 3980 }],
  },
];

const finding = (
  id: string,
  severity: Finding["severity"],
  risk: number,
  vulnId: string | null,
  title: string,
  pkg: string | null,
  installed: string | null,
  fixed: string | null,
  kev: boolean,
  cvss: number | null,
  epss: number | null,
  sources: Finding["sources"],
  type: Finding["type"] = "SCA",
  filePath: string | null = null,
  status: Finding["status"] = "OPEN",
): Finding => ({
  id,
  type,
  severity,
  riskScore: risk,
  title,
  vulnerability: vulnId
    ? { id: vulnId, cvss, epss, knownExploited: kev, kevAdded: kev ? "2021-12-10" : null, summary: title }
    : null,
  packageCoordinates: pkg,
  installedVersion: installed,
  fixedVersion: fixed,
  dependencyScope: type === "SCA" ? "TRANSITIVE_RUNTIME" : null,
  filePath,
  status,
  sources,
});

export const findings: Finding[] = [
  finding("f1", "CRITICAL", 0.96, "CVE-2021-44228", "Apache Log4j2 JNDI RCE (Log4Shell)",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "2.14.1", "2.15.0", true, 10.0, 0.9758,
    [{ engine: "TRIVY", ruleId: "CVE-2021-44228" }, { engine: "DEPENDENCY_CHECK", ruleId: "CVE-2021-44228" }]),
  finding("f2", "CRITICAL", 0.83, "CVE-2022-1471", "SnakeYAML Constructor deserialization RCE",
    "pkg:maven/org.yaml/snakeyaml@1.30", "1.30", "2.0", false, 9.8, 0.121,
    [{ engine: "TRIVY", ruleId: "CVE-2022-1471" }, { engine: "DEPENDENCY_CHECK", ruleId: "CVE-2022-1471" }]),
  finding("f3", "CRITICAL", 0.79, "CVE-2021-45046", "Log4Shell incomplete-fix bypass",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "2.14.1", "2.16.0", false, 9.0, 0.088,
    [{ engine: "TRIVY", ruleId: "CVE-2021-45046" }, { engine: "DEPENDENCY_CHECK", ruleId: "CVE-2021-45046" }]),
  finding("f4", "HIGH", 0.52, null, "formatted-sql-string",
    null, null, null, false, null, null,
    [{ engine: "SEMGREP", ruleId: "java.lang.security.audit.formatted-sql-string" }],
    "SAST", "src/main/java/com/acme/payment/audit/AuditLogRepository.java"),
  finding("f5", "MEDIUM", 0.21, "CVE-2023-2976", "Guava temp-directory information disclosure",
    "pkg:maven/com.google.guava/guava@31.0-jre", "31.0-jre", "32.0.0-android", false, 5.5, 0.005,
    [{ engine: "TRIVY", ruleId: "CVE-2023-2976" }]),
];

export const gate: GateEvaluation = {
  status: "FAIL",
  rules: [
    {
      rule: "fail-on-kev",
      level: "FAIL",
      passed: false,
      message: "1 finding(s) on actively exploited (CISA KEV) vulnerabilities",
      offenders: ["CVE-2021-44228 · pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
    },
    {
      rule: "fail-risk-threshold",
      level: "FAIL",
      passed: false,
      message: "3 finding(s) with risk score ≥ 0.75",
      offenders: [
        "CVE-2021-44228 · pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "CVE-2022-1471 · pkg:maven/org.yaml/snakeyaml@1.30",
        "CVE-2021-45046 · pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      ],
    },
    { rule: "max-critical", level: "FAIL", passed: false, message: "3 CRITICAL finding(s), budget is 0", offenders: ["CVE-2021-44228", "CVE-2022-1471", "CVE-2021-45046"] },
    { rule: "warn-risk-threshold", level: "WARN", passed: false, message: "4 finding(s) with risk score ≥ 0.50", offenders: [] },
  ],
};

export const mock = {
  repositories: () => Promise.resolve(repositories),
  orgOverview: () => Promise.resolve(orgOverview),
  trend: () => Promise.resolve(trend),
  scansForRepo: () => Promise.resolve(scans),
  scan: (scanId: string) => Promise.resolve(scans.find((s) => s.id === scanId) ?? scans[0]),
  findings: () => Promise.resolve(findings),
  gate: () => Promise.resolve(gate),
};
