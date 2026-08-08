import { useParams } from "react-router-dom";
import { api } from "../api";
import { Failed, Loading, useAsync } from "../components/Async";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { GateHero } from "../components/GateHero";
import { RiskMeter } from "../components/RiskMeter";
import { StatTile } from "../components/StatTile";
import { shortSha } from "../format";
import type { Finding, GateEvaluation, RepositorySummary, ScanSummary } from "../types";

interface ScanData {
  scan: ScanSummary;
  repo: RepositorySummary | undefined;
  findings: Finding[];
  gate: GateEvaluation;
}

function gateDetail(gate: GateEvaluation): string {
  const failed = gate.rules.filter((r) => !r.passed && r.level === "FAIL").length;
  const warned = gate.rules.filter((r) => !r.passed && r.level === "WARN").length;
  if (failed) return `${failed} blocking rule${failed > 1 ? "s" : ""} tripped`;
  if (warned) return `${warned} warning rule${warned > 1 ? "s" : ""} tripped, none blocking`;
  return "All policy rules satisfied";
}

export function ScanDetail() {
  const { scanId = "" } = useParams();
  const { data, error, loading } = useAsync<ScanData>(
    async () => {
      const scan = await api.scan(scanId);
      const [repos, findings, gate] = await Promise.all([
        api.repositories(),
        api.findings(scanId),
        api.gate(scanId),
      ]);
      return { scan, repo: repos.find((r) => r.id === scan.repositoryId), findings, gate };
    },
    [scanId],
  );

  if (loading) return <Loading what="scan" />;
  if (error) return <Failed error={error} />;
  if (!data) return null;
  const { scan, repo, findings, gate } = data;
  const name = repo?.fullName ?? "repository";
  const [owner, ...rest] = name.split("/");

  return (
    <div>
      <Breadcrumbs
        trail={[
          { label: owner, to: repo ? `/orgs/${repo.organizationId}/overview` : undefined },
          { label: rest.join("/") || name, to: `/repos/${scan.repositoryId}` },
          { label: shortSha(scan.commitSha) },
        ]}
      />
      <div className="page-head">
        <h1>
          Scan <span className="mono">{shortSha(scan.commitSha)}</span>
        </h1>
        <span className="sub">
          {scan.trigger}
          {scan.prNumber ? ` · PR #${scan.prNumber}` : ""}
          {scan.ref ? ` · ${scan.ref}` : ""}
        </span>
      </div>

      <GateHero gate={scan.gateResult} detail={gateDetail(gate)} />

      <div className="tiles">
        <StatTile label="Findings" value={scan.totalFindings} />
        <StatTile
          label="Critical"
          value={scan.findingsBySeverity.CRITICAL ?? 0}
          tone={scan.findingsBySeverity.CRITICAL ? "critical" : undefined}
        />
        <StatTile label="High" value={scan.findingsBySeverity.HIGH ?? 0} />
        <StatTile label="Top risk" value={scan.topRiskScore.toFixed(2)} />
      </div>

      <h2>Policy gate</h2>
      <div className="card">
        {gate.rules.map((rule) => (
          <div className="gate-rule" key={rule.rule}>
            <span className={`tick ${rule.passed ? "ok" : "bad"}`}>{rule.passed ? "✓" : "✕"}</span>
            <div style={{ flex: 1 }}>
              <div className="mono small strong">{rule.rule}</div>
              <div className="dim small">{rule.message}</div>
              {rule.offenders.length > 0 && (
                <ul className="offenders">
                  {rule.offenders.map((o) => (
                    <li key={o} className="mono">
                      {o}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ))}
      </div>

      <h2>Findings · risk-ranked</h2>
      <div className="card flush">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th className="num">Risk</th>
                <th>Severity</th>
                <th>Finding</th>
                <th>Package / location</th>
                <th>Fix</th>
                <th>Engines</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id} style={{ opacity: f.status === "SUPPRESSED" ? 0.5 : 1 }}>
                  <td className="num">
                    <RiskMeter score={f.riskScore} />
                  </td>
                  <td>
                    <span className={`pill ${f.severity}`}>{f.severity}</span>
                  </td>
                  <td>
                    <span className="mono small strong">{f.vulnerability?.id ?? f.title}</span>
                    {f.vulnerability?.knownExploited && <span className="kev-flag">🔥 KEV</span>}
                    {f.status === "SUPPRESSED" && <span className="dim small"> · suppressed</span>}
                    {f.vulnerability && (
                      <div className="dim small">
                        {f.vulnerability.cvss != null && `CVSS ${f.vulnerability.cvss}`}
                        {f.vulnerability.epss != null &&
                          ` · EPSS ${(f.vulnerability.epss * 100).toFixed(1)}%`}
                      </div>
                    )}
                  </td>
                  <td className="mono small dim">{f.packageCoordinates ?? f.filePath ?? "—"}</td>
                  <td className="mono small">{f.fixedVersion ?? <span className="dim">—</span>}</td>
                  <td>
                    {f.sources.map((s) => (
                      <span className="engine-tag" key={s.engine}>
                        {s.engine}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
