import { useEffect, useState } from "react";

interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

/** Minimal data-fetching hook — no query library for a portfolio dashboard. */
export function useAsync<T>(loader: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ data: null, error: null, loading: true });

  useEffect(() => {
    let live = true;
    setState({ data: null, error: null, loading: true });
    loader()
      .then((data) => live && setState({ data, error: null, loading: false }))
      .catch((e: Error) => live && setState({ data: null, error: e.message, loading: false }));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}

export function Loading({ what }: { what: string }) {
  return <div className="state">Loading {what}…</div>;
}

export function Failed({ error }: { error: string }) {
  return <div className="state">Could not load: {error}</div>;
}
