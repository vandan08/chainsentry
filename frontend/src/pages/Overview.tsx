import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { Failed, useAsync } from "../components/Async";
import { GateBadge } from "../components/GateBadge";
import { RiskMeter } from "../components/RiskMeter";
import { StatTile } from "../components/StatTile";
import { TilesSkeleton } from "../components/Skeleton";
import { timeAgo } from "../format";
import type { OrgOverview } from "../types";

export function Overview() {
  const { orgId = "" } = useParams();
  const navigate = useNavigate();
  const { data, error, loading } = useAsync<OrgOverview>(() => api.orgOverview(orgId), [orgId]);

  if (error) return <Failed error={error} />;
  if (loading || !data) {
    return (
      <div>
        <div className="page-head">
          <h1>Security posture</h1>
        </div>
        <TilesSkeleton />
      </div>
    );
  }

  const clean = data.repositories.filter((r) => r.latestScanId).length;
  return (
    <div>
      <div className="page-head">
        <h1>{data.login}</h1>
        <span className="sub">security posture across {data.repositoryCount} repositories</span>
      </div>

      <div className="tiles">
        <StatTile label="Repositories" value={data.repositoryCount} foot={`${clean} scanned`} />
        <StatTile label="Open findings" value={data.openFindings} />
        <StatTile
          label="Open criticals"
          value={data.openCriticals}
          tone="critical"
          foot={data.openCriticals ? "block the gate" : "none"}
        />
        <StatTile
          label="Actively exploited"
          value={data.kevFindings}
          tone="kev"
          icon={<span aria-hidden>🔥</span>}
          foot="in CISA KEV"
        />
      </div>

      <h2>Repositories</h2>
      <div className="card flush">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Gate</th>
                <th className="num">Findings</th>
                <th className="num">Critical</th>
                <th className="num">KEV</th>
                <th className="num">Top risk</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {data.repositories.map((repo) => (
                <tr
                  key={repo.repositoryId}
                  className="rowlink"
                  onClick={() => navigate(`/repos/${repo.repositoryId}`)}
                >
                  <td>
                    <Link to={`/repos/${repo.repositoryId}`} className="strong">
                      {repo.fullName}
                    </Link>
                  </td>
                  <td>
                    <GateBadge gate={repo.latestGate} />
                  </td>
                  <td className="num">{repo.openFindings}</td>
                  <td className="num">
                    {repo.openCriticals ? <span className="pill CRITICAL">{repo.openCriticals}</span> : ""}
                  </td>
                  <td className="num">
                    {repo.kevFindings ? <span className="kev-flag">🔥 {repo.kevFindings}</span> : ""}
                  </td>
                  <td className="num">
                    {repo.latestScanId ? <RiskMeter score={repo.topRiskScore} /> : <span className="dim">—</span>}
                  </td>
                  <td className="dim small">{timeAgo(repo.lastScannedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
