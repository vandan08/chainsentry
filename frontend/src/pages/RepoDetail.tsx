import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { Failed, Loading, useAsync } from "../components/Async";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { GateBadge } from "../components/GateBadge";
import { RiskMeter } from "../components/RiskMeter";
import { SeverityBar } from "../components/SeverityBar";
import { TrendChart } from "../components/TrendChart";
import { shortSha, timeAgo } from "../format";
import type { RepositorySummary, ScanSummary, TrendPoint } from "../types";

interface RepoData {
  repo: RepositorySummary | undefined;
  trend: TrendPoint[];
  scans: ScanSummary[];
}

export function RepoDetail() {
  const { repoId = "" } = useParams();
  const navigate = useNavigate();
  const { data, error, loading } = useAsync<RepoData>(
    async () => {
      const [repos, trend, scans] = await Promise.all([
        api.repositories(),
        api.trend(repoId),
        api.scansForRepo(repoId),
      ]);
      return { repo: repos.find((r) => r.id === repoId), trend, scans };
    },
    [repoId],
  );

  if (loading) return <Loading what="repository" />;
  if (error) return <Failed error={error} />;
  if (!data) return null;

  const name = data.repo?.fullName ?? "repository";
  const [owner, ...rest] = name.split("/");
  return (
    <div>
      <Breadcrumbs
        trail={[
          { label: owner, to: data.repo ? `/orgs/${data.repo.organizationId}/overview` : undefined },
          { label: rest.join("/") || name },
        ]}
      />
      <div className="page-head">
        <h1>{name}</h1>
        <span className="sub">{data.scans.length} scans · default branch {data.repo?.defaultBranch}</span>
      </div>

      <h2>Findings over time</h2>
      <div className="card">
        <TrendChart points={data.trend} />
      </div>

      <h2>Scans</h2>
      <div className="card flush">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Commit</th>
                <th>Trigger</th>
                <th>Gate</th>
                <th>Severity mix</th>
                <th className="num">Top risk</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {data.scans.map((scan) => (
                <tr key={scan.id} className="rowlink" onClick={() => navigate(`/scans/${scan.id}`)}>
                  <td className="mono strong">
                    {shortSha(scan.commitSha)}
                    {scan.prNumber ? <span className="dim small"> · PR #{scan.prNumber}</span> : null}
                  </td>
                  <td className="dim small">{scan.trigger}</td>
                  <td>
                    <GateBadge gate={scan.gateResult} />
                  </td>
                  <td>
                    <SeverityBar counts={scan.findingsBySeverity} total={scan.totalFindings} />
                  </td>
                  <td className="num">
                    <RiskMeter score={scan.topRiskScore} />
                  </td>
                  <td className="dim small">{timeAgo(scan.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
