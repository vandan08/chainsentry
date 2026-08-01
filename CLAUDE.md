# ChainSentry — agent notes

Supply-chain security platform (portfolio project): scans code/deps/containers in CI, ranks findings by CVSS × EPSS × CISA-KEV × dependency scope, diffs SBOMs per PR, enforces policy-as-code, emits OpenVEX.

## Map
- `backend/` — Spring Boot 4.1, Java 24, Maven. Modular-monolith packages under `io.chainsentry.*` (github, orchestration, scanner, normalization, risk, sbom, policy, remediation, dashboard, demo, shared). Modules stay acyclic: cross-module triggers flow through Spring events in `shared/event` (`ScanRequested` in, `ScanCompleted` out). Schema owned by Flyway (`db/migration`), `ddl-auto: validate`.
- `github-action/` — composite action + `gate.py` policy gate.
- `docs/` — numbered design docs; `06-ROADMAP.md` is the source of truth for what to build next (phases with checklists — keep it updated as work lands).

## Conventions
- Records over Lombok; constructor injection; no field injection.
- Enum-like DB columns are VARCHAR + CHECK (not Postgres enums) to match `@Enumerated(STRING)`.
- Conventional Commits; feature branches `feat/p<phase>-<topic>`.
- Local run needs Docker (`docker compose up -d` for Postgres/Redis). ⚠️ Machine's `JAVA_HOME` may point at JDK 17 — Maven needs JDK 24 (`C:\Program Files\Java\jdk-24`); see `docs/08-DEV-SETUP.md`.
- Secrets go in `application-local.yml` (gitignored), never in `application.yml`.

## Build & test
```
cd backend && mvn verify                 # 113 unit tests, Docker-free
cd backend && mvn verify -Pintegration   # + ScanPipelineIT (Testcontainers Postgres, needs Docker)
```
Testcontainers 2.x (Boot 4 manages it): artifacts are `testcontainers-postgresql` / `testcontainers-junit-jupiter` — the 1.x names have no managed version.

## Gotchas (learned the hard way)
- **Spring Boot 4 modularized auto-configuration**: Flyway needs `spring-boot-flyway`, `RestClient.Builder` needs `spring-boot-restclient` on the classpath — `flyway-core` alone silently never migrates.
- **Jackson 3** (`tools.jackson.*`) is what Boot 4 resolves; use `tools.jackson.dataformat:jackson-dataformat-yaml`, not the `com.fasterxml` one (that drags in a second databind).
- Demo mode: `mvn spring-boot:run -Dspring-boot.run.profiles=demo` seeds two fixture scans + dashboard at `/`. On this machine ports 5432/8080 are taken by other projects — add the `local` profile (gitignored overrides: Postgres 5433, server 8081).
