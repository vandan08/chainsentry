import { Navigate } from "react-router-dom";
import { api } from "../api";
import { Failed, Loading, useAsync } from "../components/Async";
import type { RepositorySummary } from "../types";

/**
 * There's no user→org mapping without login, so the landing route resolves the
 * org from the first tracked repository and redirects into its overview. With
 * no repos yet, it shows the getting-started empty state.
 */
export function Landing() {
  const { data, error, loading } = useAsync<RepositorySummary[]>(() => api.repositories(), []);

  if (loading) return <Loading what="workspace" />;
  if (error) return <Failed error={error} />;
  if (data && data.length > 0) {
    return <Navigate to={`/orgs/${data[0].organizationId}/overview`} replace />;
  }
  return (
    <div className="card" style={{ textAlign: "center", padding: "48px 24px" }}>
      <div style={{ fontSize: 28, marginBottom: 8 }}>🛡️</div>
      <div className="strong" style={{ fontSize: 16, marginBottom: 4 }}>
        No repositories tracked yet
      </div>
      <div className="dim small" style={{ maxWidth: 420, margin: "0 auto" }}>
        Install the GitHub App on a repository, or run the ChainSentry Action with an{" "}
        <span className="mono">upload-url</span>, then reload.
      </div>
    </div>
  );
}
