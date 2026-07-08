# Development Setup

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| JDK | **24+** | You have `C:\Program Files\Java\jdk-24`. ⚠️ Your `JAVA_HOME` currently points to `jdk-17` — Maven uses `JAVA_HOME`, so the build will fail until you update it (below). Recommended: install **JDK 25 (LTS)** via Temurin and bump `<java.version>` in `backend/pom.xml` to 25. |
| Maven | 3.9+ | installed ✅ |
| Docker Desktop | current | Postgres/Redis via compose + scanner engine containers |
| Git | 2.4x | installed ✅ |
| gh CLI | 2.x | installed ✅ (run `gh auth login` once) |
| ngrok | any | for GitHub webhook development (you have it in `Projects\ngrok-v3-stable-windows-amd64`) |

### Fix JAVA_HOME (one-time, PowerShell as admin)

```powershell
[Environment]::SetEnvironmentVariable('JAVA_HOME', 'C:\Program Files\Java\jdk-24', 'User')
# restart the terminal, then verify:
mvn -version   # should say "Java version: 24"
```

## First run

```powershell
# 1. Infra
docker compose up -d          # Postgres :5432, Redis :6379

# 2. Build & test
cd backend
mvn verify

# 3. Run
mvn spring-boot:run
```

Verify: `http://localhost:8080/actuator/health` → `{"status":"UP"}`.

## Demo mode — the 30-second demo, no scanner engines needed

The `demo` profile replays recorded Trivy reports through the **real** pipeline
(normalization → dedup → risk scoring → policy gate → SBOM), seeds a frozen
EPSS/KEV snapshot, and runs two scans of a fictional `acme/payment-service` on
startup: a clean-ish push to `main` (gate **PASS**) and PR #42 that pulls in
log4j-core 2.14.1 (gate **FAIL**).

```powershell
docker compose up -d
cd backend
mvn spring-boot:run "-Dspring-boot.run.profiles=demo"
```

Then open `http://localhost:8080/` — the dashboard shows both scans,
risk-ranked findings, the gate verdict with the exact rules that fired, and
the PR's supply-chain delta. Only container execution is canned; a real Trivy
run (non-demo profile) needs Docker and uses the same code path.

### Port conflicts

If 5432 or 8080 are taken on your machine (they are on this one), override
locally — both files are gitignored:

- `docker-compose.override.yml` at the repo root remaps Postgres
  (`ports: !override` → `"5433:5432"`).
- `backend/src/main/resources/application-local.yml` sets the matching
  `spring.datasource.url` and `server.port`; add `local` to the active
  profiles: `-Dspring-boot.run.profiles=demo,local`.

## Configuration

- Defaults live in `backend/src/main/resources/application.yml` and work with the compose services out of the box.
- Machine-local secrets (GitHub App keys etc.) go in `application-local.yml` (gitignored); activate with `--spring.profiles.active=local`.

## Pre-pull scanner images (optional, speeds up Phase 1 work)

```powershell
docker pull aquasec/trivy:latest
docker pull semgrep/semgrep:latest
docker pull owasp/dependency-check:latest
```

Trivy downloads its vulnerability DB on first run (~600 MB) — cache it in a named volume:
`docker run -v trivy-cache:/root/.cache aquasec/trivy image alpine:3.19` once.

## Conventions

- **Branches:** `main` protected; feature branches `feat/<phase>-<topic>`, e.g. `feat/p1-trivy-adapter`.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`) — enables changelog generation later.
- **Tests:** unit tests next to code; integration tests use Testcontainers and are tagged so CI can split them.
- **Formatting:** default IntelliJ Java style; records over Lombok; constructor injection only.
