# ChainSentry — agent notes

Supply-chain security platform (portfolio project): scans code/deps/containers in CI, ranks findings by CVSS × EPSS × CISA-KEV × dependency scope, diffs SBOMs per PR, enforces policy-as-code, emits OpenVEX.

## Map
- `backend/` — Spring Boot 4.1, Java 24, Maven. Modular-monolith packages under `io.chainsentry.*` (github, orchestration, scanner, normalization, risk, sbom, policy, remediation, dashboard, demo, shared). Modules stay acyclic: cross-module triggers flow through Spring events in `shared/event` (`ScanRequested` in, `ScanCompleted` out). Schema owned by Flyway (`db/migration`), `ddl-auto: validate`.
- `frontend/` — React 19 + Vite. `/` is the marketing landing page (`pages/Home.tsx`, styles in `landing.css`); it renders **outside** the dashboard shell in `App.tsx` (full-bleed, its own glass nav) and stays dark in both colour schemes, so `landing.css` defines its own tokens rather than inheriting `index.css`. The hero plays `src/asset/chainserity.mp4` (3.2 MB; poster `hero-poster.jpg` cut from frame 0 with ffmpeg) behind a two-stop scrim. `/app` resolves the org and redirects into the dashboard. Recharts is lazy-loaded so it stays out of the landing page's bundle.
- `github-action/` — composite action + `gate.py` policy gate.
- `docs/` — numbered design docs; `06-ROADMAP.md` is the source of truth for what to build next (phases with checklists — keep it updated as work lands).

## Conventions
- Records over Lombok; constructor injection; no field injection.
- Enum-like DB columns are VARCHAR + CHECK (not Postgres enums) to match `@Enumerated(STRING)`.
- Conventional Commits; feature branches `feat/p<phase>-<topic>`.
- Local run needs Docker (`docker compose up -d` for Postgres/Redis). ⚠️ Machine's `JAVA_HOME` may point at JDK 17 — Maven needs JDK 24 (`C:\Program Files\Java\jdk-24`); see `docs/08-DEV-SETUP.md`.
- Secrets go in `application-local.yml` (gitignored), never in `application.yml`.

## Deployment
Root `Dockerfile` (not `backend/Dockerfile`) is the deployment image: it builds the SPA and copies `frontend/dist` into `backend/src/main/resources/static/` before packaging, so one container serves both. `SPRING_PROFILES_ACTIVE=prod,demo`; `DATABASE_URL` in libpq form is translated to JDBC by `DatabaseUrlEnvironmentPostProcessor` (registered via `META-INF/spring.factories`). `chainsentry.demo.read-only` refuses every non-GET request. Deep links work through `SpaForwardingController`, which lists client routes explicitly — **a new top-level route in `App.tsx` must be added there too**. Full guide: `docs/11-DEPLOYMENT.md`.

## Build & test
```
cd backend && mvn verify                 # 131 unit tests, Docker-free
cd backend && mvn verify -Pintegration   # + ScanPipelineIT (Testcontainers Postgres, needs Docker)
```
Testcontainers 2.x (Boot 4 manages it): artifacts are `testcontainers-postgresql` / `testcontainers-junit-jupiter` — the 1.x names have no managed version.

## Gotchas (learned the hard way)
- **Spring Boot 4 modularized auto-configuration**: Flyway needs `spring-boot-flyway`, `RestClient.Builder` needs `spring-boot-restclient` on the classpath — `flyway-core` alone silently never migrates.
- **Boot 4 moved `EnvironmentPostProcessor`** from `org.springframework.boot.env` to `org.springframework.boot` and deprecated the old interface. Registering the old FQN in `META-INF/spring.factories` fails *silently* — the app boots and falls back to `application.yml`'s localhost datasource, which only surfaces as connection-refused on the deployment platform. `DatabaseUrlEnvironmentPostProcessorTest` pins the registration so a future move breaks the build, not the deploy.
- **Boot 4 split the test slices out of `spring-boot-starter-test`** — `@WebMvcTest`/`MockMvc` need `spring-boot-starter-webmvc-test` (test scope), and the annotation lives in `org.springframework.boot.webmvc.test.autoconfigure`.
- **Jackson 3** (`tools.jackson.*`) is what Boot 4 resolves; use `tools.jackson.dataformat:jackson-dataformat-yaml`, not the `com.fasterxml` one (that drags in a second databind).
- Demo mode: `mvn spring-boot:run -Dspring-boot.run.profiles=demo` seeds a scripted world (6 repos, 23 backdated scans across ~5 weeks, mixed PASS/FAIL) and serves the dashboard at `/`. `DemoDataLoader.WORLD` is the script; every commit is mapped onto one of two recorded report sets via `DemoFixtures.Flavor`. Seeding is idempotent on `acme/payment-service` — to reseed, drop and recreate the `public` schema, then restart.
- On this machine ports 5432 (credlayer), 5433 (talon) and 8080 are taken by other projects — add the `local` profile (gitignored overrides: Postgres 5434, server 8081). The React dashboard (`frontend/`, `npm run dev` on 5173) proxies `/api` to `BACKEND_URL`, which must be set to `http://localhost:8081` to match.
