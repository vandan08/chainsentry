# ChainSentry dashboard

React + Vite + TypeScript. Org overview, per-repo trend chart, and scan detail
(risk-ranked findings + gate breakdown), consuming the backend read-model API.

```bash
npm install
npm run dev        # http://localhost:5173, proxies /api + /auth to :8080
npm run build      # type-check + production bundle into dist/
```

Point the dev proxy at a different backend with `BACKEND_URL` (this machine's
`local` profile serves on 8081):

```bash
BACKEND_URL=http://localhost:8081 npm run dev
```

- **Data**: `src/api.ts` + `src/types.ts` mirror `io.chainsentry.dashboard.dto`.
- **Auth**: `src/auth.ts` reads `GET /api/v1/me` — 204 means OAuth is unconfigured
  and the app runs open; 401 shows "Sign in with GitHub".
- **Colors**: role-based CSS custom properties in `src/index.css`, light/dark via
  `prefers-color-scheme`; chart severity uses the fixed status palette so a color
  never doubles as a category.
