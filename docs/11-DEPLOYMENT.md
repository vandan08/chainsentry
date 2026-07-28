# 11 — Deployment

How the public demo instance gets from this repo to a URL.

If Vercel is the only platform you've used: the difference here is that
ChainSentry is not a static site. It's a JVM process that needs a PostgreSQL
database alongside it. Vercel doesn't run long-lived JVM processes, so the
deploy target is a container host instead. The good news is that the shape is
the same — connect the repo, it builds on push, you get a URL.

---

## What actually gets deployed

**One container, one URL.** `Dockerfile` at the repo root builds the React
dashboard, copies the compiled bundle into the Spring Boot jar's static
resources, and ships a single image. The SPA and the API are served from the
same origin, so there is no CORS setup, no second deployment, and no
`VITE_API_URL` to keep in sync.

```
frontend/ ──npm run build──┐
                           ├──► one jar ──► one container ──► https://…
backend/  ──mvn package────┘
```

**The demo profile needs no Docker at runtime.** In production ChainSentry
shells out to Trivy/Semgrep/Dependency-Check containers — which a managed host
won't let you do. The `demo` profile swaps the engine fleet for
`FixtureScannerEngine`, which replays *recorded real scanner reports* through
the real normalization → dedup → risk → policy pipeline. Everything downstream
of the scanner process is genuine; only the subprocess is canned. That's what
makes a $0–7/month deployment possible.

**Two profiles, two jobs.** `SPRING_PROFILES_ACTIVE=prod,demo`:

| profile | responsibility |
|---|---|
| `prod` | hosting shape: `PORT`, `DATABASE_URL`, forwarded headers, graceful shutdown, small connection pool, read-only guard |
| `demo` | what the instance shows: the seeded `acme` org, 6 repos, 23 backdated scans, frozen EPSS/KEV snapshot |

**The public instance is read-only.** `chainsentry.demo.read-only=true`
registers `ReadOnlyModeFilter`, which refuses every non-GET request with a 403
problem detail. Reads hit the real API — visitors get real JSON, not a mock —
but nobody can suppress a finding or trigger a scan on your portfolio link.

---

## Option A — Render (recommended if this is your first non-Vercel deploy)

Closest thing to the Vercel workflow: connect the repo, it builds on every push.

1. Push this branch to GitHub.
2. Go to [dashboard.render.com](https://dashboard.render.com) → **New** →
   **Blueprint**, and select the repo. Render reads [`render.yaml`](../render.yaml)
   and proposes two resources: the `chainsentry` web service and a
   `chainsentry-db` Postgres.
3. **Apply**. First build takes ~5–8 minutes (Maven downloads the world once;
   later builds reuse the cached layer).
4. Open the URL. The landing page is at `/`, the dashboard at `/app`.

The blueprint wires `DATABASE_URL` from the database automatically. Flyway
migrates on first boot and `DemoDataLoader` seeds the world — watch the logs
for the `── ChainSentry demo ready ──` banner.

### Free-tier caveats you should know before putting the link on a profile

| caveat | effect | fix |
|---|---|---|
| Free web services sleep after 15 min idle | first visitor waits ~50 s for a cold start | upgrade the service to Starter (~$7/mo), **or** ping `/actuator/health` every 10 min from a free scheduler like cron-job.org |
| Free Postgres is deleted after 30 days | the instance comes back empty | move to a Neon/Supabase free database (no expiry) and set `DATABASE_URL` manually, or upgrade the Render database |
| 512 MB RAM | JVM must be told the container's limit | already handled — `MaxRAMPercentage=70` and SerialGC in the Dockerfile |

For a link a client might click cold, the honest recommendation is the ~$7/mo
Starter service. A 50-second white screen undoes the impression the project is
there to make.

### Keeping the demo data fresh

Seeding is idempotent on `acme/payment-service`, so restarts don't duplicate
anything. To reseed from scratch, drop and recreate the schema, then restart
the service:

```bash
psql "$DATABASE_URL" -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
```

---

## Option B — Fly.io (better free-tier behaviour)

Fly's machines auto-stop when idle and wake in ~2–3 seconds rather than ~50, so
the free path gives a much better first impression than Render's.

```bash
fly launch --no-deploy          # detects the Dockerfile; creates fly.toml
fly postgres create --name chainsentry-db
fly postgres attach chainsentry-db      # sets DATABASE_URL for you
fly secrets set SPRING_PROFILES_ACTIVE=prod,demo CHAINSENTRY_DEMO_READ_ONLY=true
fly deploy
```

In the generated `fly.toml`, set `internal_port = 8080` and add
`auto_stop_machines = "suspend"` / `min_machines_running = 0` under
`[http_service]` for the fast wake.

---

## Option C — Railway (fastest to a working URL)

No cold starts, ~$5/month of trial credit. New Project → Deploy from GitHub
repo → add a Postgres plugin. Railway injects `DATABASE_URL` on its own; add
`SPRING_PROFILES_ACTIVE=prod,demo` in **Variables** and it deploys.

---

## Option D — any Docker host / VPS

```bash
docker build -t chainsentry .
docker run -d -p 80:8080 \
  -e SPRING_PROFILES_ACTIVE=prod,demo \
  -e DATABASE_URL="postgres://user:pass@db-host:5432/chainsentry" \
  chainsentry
```

---

## Configuration reference

Everything the container reads from the environment:

| variable | default | meaning |
|---|---|---|
| `PORT` | `8080` | assigned by the platform |
| `DATABASE_URL` | — | libpq form (`postgres://user:pass@host:port/db`), translated to JDBC by `DatabaseUrlEnvironmentPostProcessor`. Set `SPRING_DATASOURCE_URL` instead to bypass it. |
| `SPRING_PROFILES_ACTIVE` | — | `prod,demo` for the public instance |
| `CHAINSENTRY_DEMO_READ_ONLY` | `true` | `false` makes the deployment fully interactive |
| `CHAINSENTRY_FEEDS_SYNC` | `false` | `true` pulls live EPSS/KEV daily (changes demo risk scores) |
| `DB_POOL_SIZE` | `5` | lower it on free Postgres plans |
| `JAVA_OPTS` | `-XX:MaxRAMPercentage=70 -XX:+UseSerialGC` | heap sizing for small containers |

GitHub App credentials and the Anthropic API key are deliberately **not** wired
into the deployment. Absent, the App integration and the AI explain/fix-PR
endpoints disable themselves cleanly (503 / no-op) rather than erroring — a
public demo shouldn't hold write credentials to your repositories.

---

## Verifying a deployment

```bash
curl -fsS https://<your-url>/actuator/health          # {"status":"UP"}
curl -fsS https://<your-url>/api/v1/repos | head      # six seeded repositories
curl -isS -X POST https://<your-url>/api/v1/repos/x/scans | head -1   # 403, read-only
```

Then open `/` (landing) and `/app` (dashboard) and confirm a hard refresh on a
deep link like `/scans/<uuid>` still renders — that path goes through
`SpaForwardingController`.

---

## Troubleshooting

**Build fails resolving dependencies.** The Maven layer is cached on
`backend/pom.xml`; if the POM changed, the layer re-downloads. First build after
a POM change is slow, not broken.

**Boot fails with `Connection to localhost:5432 refused`, even though
`DATABASE_URL` is set.** The translation didn't take effect and the app fell
back to the localhost default in `application.yml`. Two causes, both pinned by
`DatabaseUrlEnvironmentPostProcessorTest`: the `spring.factories` key must name
`org.springframework.boot.EnvironmentPostProcessor` (Boot 4 moved it, and the
old FQN is ignored silently), and the translated property source must sit
*above* `application.yml` in precedence. As a workaround on any platform, set
`SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME` and
`SPRING_DATASOURCE_PASSWORD` directly — those bypass the translation entirely.

**App starts then exits 137.** Out of memory. The container was killed, not the
JVM — lower `MaxRAMPercentage` or move up a plan size.

**`FlywayValidateException` on boot.** The database has a schema from an older
migration set. Drop and recreate `public` (see above); the demo data is
regenerated on the next start.

**Blank page on a deep link, but `/` works.** The SPA fallback isn't matching.
`SpaForwardingController` lists client routes explicitly — a new top-level route
in `App.tsx` needs adding there too.

**Dashboard loads but every panel errors.** The SPA is being served without the
API on the same origin, i.e. the frontend was deployed separately. Deploy the
root `Dockerfile`, not `backend/Dockerfile`.
