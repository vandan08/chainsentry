import { useEffect, useState } from "react";

export interface CurrentUser {
  login: string;
  name: string | null;
  avatarUrl: string | null;
}

interface AuthState {
  user: CurrentUser | null;
  /** null = login is disabled server-side (no OAuth config); the app runs open. */
  enabled: boolean;
  loading: boolean;
}

/**
 * GET /api/v1/me returns 200 with the user, 401 when login is enabled but the
 * caller is signed out, or 204 when OAuth isn't configured (open mode).
 *
 * Anything else — including the 404 you get on a deployment where the OAuth
 * endpoints aren't implemented at all — is also open mode. Without that check
 * the 404's JSON error body parses as a `CurrentUser`, and the topbar renders
 * a "Sign out" link for a user who doesn't exist, pointing at a route that
 * isn't there either.
 */
export function useAuth(): AuthState {
  const [state, setState] = useState<AuthState>({ user: null, enabled: true, loading: true });

  useEffect(() => {
    fetch("/api/v1/me", { headers: { Accept: "application/json" } })
      .then(async (r) => {
        if (r.status === 204) return setState({ user: null, enabled: false, loading: false });
        if (r.status === 401) return setState({ user: null, enabled: true, loading: false });
        if (!r.ok) return setState({ user: null, enabled: false, loading: false });
        const user = (await r.json()) as CurrentUser;
        if (!user?.login) return setState({ user: null, enabled: false, loading: false });
        setState({ user, enabled: true, loading: false });
      })
      .catch(() => setState({ user: null, enabled: false, loading: false }));
  }, []);

  return state;
}
