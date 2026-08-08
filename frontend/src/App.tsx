import { Link, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Logo } from "./components/Logo";
import { Landing } from "./pages/Landing";
import { Overview } from "./pages/Overview";
import { RepoDetail } from "./pages/RepoDetail";
import { ScanDetail } from "./pages/ScanDetail";

function UserMenu() {
  const { user, enabled, loading } = useAuth();
  if (loading || !enabled) return null; // open mode or still resolving
  if (!user) {
    return (
      <a className="badge none" href="/auth/github/login">
        Sign in with GitHub
      </a>
    );
  }
  return (
    <span className="small dim" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      {user.avatarUrl && (
        <img src={user.avatarUrl} alt="" width={20} height={20} style={{ borderRadius: "50%" }} />
      )}
      {user.login}
      <a href="/auth/logout" className="badge none">
        Sign out
      </a>
    </span>
  );
}

export function App() {
  return (
    <div className="shell">
      <header className="topbar">
        <Link to="/" className="brand">
          <Logo />
          Chain<span>Sentry</span>
        </Link>
        <span className="crumb">supply-chain security</span>
        <span className="spacer" />
        <UserMenu />
      </header>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/orgs/:orgId/overview" element={<Overview />} />
        <Route path="/repos/:repoId" element={<RepoDetail />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
      </Routes>
    </div>
  );
}
