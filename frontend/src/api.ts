import type {
  Finding,
  GateEvaluation,
  OrgOverview,
  RepositorySummary,
  ScanSummary,
  TrendPoint,
} from "./types";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`${path} → HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

const liveApi = {
  repositories: () => get<RepositorySummary[]>("/api/v1/repos"),
  orgOverview: (orgId: string) => get<OrgOverview>(`/api/v1/orgs/${orgId}/overview`),
  trend: (repoId: string) => get<TrendPoint[]>(`/api/v1/repos/${repoId}/trend`),
  scansForRepo: (repoId: string) => get<ScanSummary[]>(`/api/v1/repos/${repoId}/scans`),
  scan: (scanId: string) => get<ScanSummary>(`/api/v1/scans/${scanId}`),
  findings: (scanId: string) => get<Finding[]>(`/api/v1/scans/${scanId}/findings`),
  gate: (scanId: string) => get<GateEvaluation>(`/api/v1/scans/${scanId}/gate`),
};

// VITE_MOCK=1 swaps in offline fixtures (dev/UI work only). The dynamic import
// keeps the mock out of the production bundle when the flag is unset.
const useMock = import.meta.env.VITE_MOCK === "1";
export const api = useMock ? (await import("./mock")).mock : liveApi;
