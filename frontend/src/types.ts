// Mirrors the backend DTO records in io.chainsentry.dashboard.dto.

export type GateStatus = "PASS" | "WARN" | "FAIL";
export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "TIMED_OUT";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingType = "SCA" | "SAST" | "CONTAINER" | "SECRET";
export type FindingStatus = "OPEN" | "FIXED" | "SUPPRESSED";
export type ScannerType = "TRIVY" | "SEMGREP" | "DEPENDENCY_CHECK";
export type ScanTrigger = "PR" | "PUSH" | "MANUAL" | "ACTION_UPLOAD";

export interface RepositorySummary {
  id: string;
  fullName: string;
  defaultBranch: string;
  organizationId: string;
}

export interface RepositoryOverview {
  repositoryId: string;
  fullName: string;
  latestScanId: string | null;
  latestGate: GateStatus | null;
  lastScannedAt: string | null;
  openFindings: number;
  openCriticals: number;
  kevFindings: number;
  topRiskScore: number;
}

export interface OrgOverview {
  organizationId: string;
  login: string;
  repositoryCount: number;
  openFindings: number;
  openCriticals: number;
  kevFindings: number;
  repositories: RepositoryOverview[];
}

export interface TrendPoint {
  scanId: string;
  commitSha: string;
  scannedAt: string | null;
  gate: GateStatus | null;
  totalFindings: number;
  criticals: number;
  highs: number;
  topRiskScore: number;
}

export interface EngineRun {
  engine: ScannerType;
  version: string | null;
  status: ScanStatus;
  durationMs: number | null;
}

export interface ScanSummary {
  id: string;
  repositoryId: string;
  commitSha: string;
  ref: string | null;
  prNumber: number | null;
  trigger: ScanTrigger;
  status: ScanStatus;
  gateResult: GateStatus | null;
  createdAt: string;
  finishedAt: string | null;
  totalFindings: number;
  findingsBySeverity: Partial<Record<Severity, number>>;
  topRiskScore: number;
  engines: EngineRun[];
}

export interface VulnerabilityInfo {
  id: string;
  cvss: number | null;
  epss: number | null;
  knownExploited: boolean;
  kevAdded: string | null;
  summary: string | null;
}

export interface FindingSource {
  engine: ScannerType;
  ruleId: string | null;
}

export interface Finding {
  id: string;
  type: FindingType;
  severity: Severity;
  riskScore: number;
  title: string | null;
  vulnerability: VulnerabilityInfo | null;
  packageCoordinates: string | null;
  installedVersion: string | null;
  fixedVersion: string | null;
  dependencyScope: string | null;
  filePath: string | null;
  status: FindingStatus;
  sources: FindingSource[];
}

export interface GateRule {
  rule: string;
  level: GateStatus;
  passed: boolean;
  message: string;
  offenders: string[];
}

export interface GateEvaluation {
  status: GateStatus;
  rules: GateRule[];
}
