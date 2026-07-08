# ChainSentry

> **Supply-chain security, built into your CI.** ChainSentry scans your code, dependencies, and containers, then tells you which findings *actually matter* — ranked by real-world exploitability, not just CVSS labels.

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)]()
[![Java](https://img.shields.io/badge/Java-24-orange?logo=openjdk)]()
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1-6DB33F?logo=springboot&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-blue)]()

---

## The problem

Post-Log4Shell and SolarWinds, every engineering org knows it needs supply-chain security. But the tools they get are noisy: a typical scan of a mid-size service produces **hundreds of findings**, of which fewer than 5% are ever exploited in the wild. Teams either drown in alerts or turn the scanner off.

## What makes ChainSentry different

Most scanner wrappers stop at "run Trivy, dump results." ChainSentry treats scanning as step one of five:

| Capability | What it means |
|---|---|
| 🎯 **Risk-based prioritization** | Every finding gets a composite risk score: CVSS base × **EPSS** exploit probability × **CISA KEV** (known-exploited) membership × dependency scope (direct vs transitive, runtime vs test). A "Critical" CVE in a test-only dependency ranks below a "High" that's in the KEV catalog. |
| 🔀 **PR supply-chain delta** | On every pull request, ChainSentry diffs the SBOM of the head branch against the base and comments: *"This PR adds 4 new transitive dependencies; 1 carries a critical, actively-exploited CVE."* Reviewers see the risk **they are about to merge**, not the whole backlog. |
| 📜 **Policy-as-code** | A `chainsentry.yml` in the repo defines the gate: fail on KEV, fail on critical with fix available, allow time-boxed suppressions with an owner and expiry date. Policies are versioned with the code they protect. |
| 🧾 **SBOM + OpenVEX** | Generates CycloneDX SBOMs on every build, and turns approved suppressions into **OpenVEX** statements — machine-readable "not affected, because…" documents that downstream consumers and auditors can verify. |
| 🤖 **AI-assisted remediation** | Claude-powered explanations of *why* a finding matters in this codebase, plus draft upgrade PRs for fixable dependency vulnerabilities. |
| 🧩 **Unified finding model** | Trivy, Semgrep, and OWASP Dependency-Check results are normalized to one SARIF-based model and de-duplicated across scanners, so one real vulnerability = one finding. |

## Architecture at a glance

```mermaid
flowchart LR
    subgraph GitHub
        PR[Pull Request / Push] --> GA[ChainSentry Action]
        App[GitHub App webhooks]
    end

    GA -->|upload scan bundle| API
    App -->|installation, PR events| API

    subgraph "ChainSentry Platform (Spring Boot 4, modular monolith)"
        API[Ingestion API] --> Q[(Job Queue)]
        Q --> ORCH[Scan Orchestrator<br/>virtual threads]
        ORCH --> T[Trivy adapter]
        ORCH --> S[Semgrep adapter]
        ORCH --> D[Dependency-Check adapter]
        T & S & D --> NORM[SARIF Normalizer<br/>+ dedup]
        NORM --> RISK[Risk Engine<br/>CVSS × EPSS × KEV]
        RISK --> POL[Policy Engine]
        SBOM[SBOM Service<br/>CycloneDX + diff] --> POL
        POL --> CHECKS[GitHub Checks API<br/>+ PR comments]
        RISK --> DB[(PostgreSQL)]
    end

    DB --> DASH[Dashboard]
    FEEDS[NVD / EPSS / KEV feeds] --> RISK
```

Full details in [docs/02-ARCHITECTURE.md](docs/02-ARCHITECTURE.md).

## Tech stack

- **Java 24** (→ 25 LTS), virtual threads for scanner orchestration
- **Spring Boot 4.1** / Spring Framework 7, modular-monolith (Spring Modulith conventions)
- **PostgreSQL 16** + Flyway migrations, **Redis** for job queue & feed caching
- **Trivy · Semgrep · OWASP Dependency-Check** as containerized scanner engines
- **CycloneDX** SBOMs, **OpenVEX**, **SARIF** interchange
- **GitHub App** (webhooks, Checks API) + **GitHub Action** (composite, fails builds on policy breach)
- **Testcontainers** integration tests, GitHub Actions CI
- Full list & reasoning: [docs/03-TECH-STACK.md](docs/03-TECH-STACK.md)

## Repository layout

```
chainsentry/
├── backend/            Spring Boot platform (API, orchestrator, engines)
├── github-action/      Composite GitHub Action (scan + gate in CI)
├── docs/               Vision, architecture, data model, API, roadmap
├── docker-compose.yml  Local dev: Postgres, Redis
└── .github/workflows/  CI for this repo itself
```

## Quick start — see the whole thing in 30 seconds

```bash
# 1. Infrastructure (Postgres + Redis)
docker compose up -d

# 2. Demo mode (needs JDK 24+, see docs/08-DEV-SETUP.md — no scanner engines required)
cd backend
mvn spring-boot:run -Dspring-boot.run.profiles=demo
```

Open **`http://localhost:8080/`**. The demo profile replays recorded Trivy
reports through the real pipeline and seeds two scans of a fictional
`acme/payment-service`:

- a push to `main` — two modest findings, gate **PASS** ✅
- PR #42 ("add audit logging") — an innocent-looking internal starter drags in
  `log4j-core 2.14.1`, gate **FAIL** ❌

The dashboard shows what makes ChainSentry different: snakeyaml's CVSS-9.8
CRITICAL ranks at **0.38** (no known exploitation, transitive), while both
KEV-listed log4j CVEs rank above **0.93** — and the gate names the exact rules
and findings that blocked the merge. The **supply-chain delta** panel shows
precisely what the PR is about to merge.

Without the demo profile, scans run real Trivy containers against shallow
clones — same pipeline, same policy engine (`mvn spring-boot:run`, Docker
required).

```
POST /api/v1/repos/{id}/scans          trigger a scan
GET  /api/v1/scans/{id}                status + severity counts + gate result
GET  /api/v1/scans/{id}/findings       risk-ranked findings
GET  /api/v1/scans/{id}/gate           which policy rule fired, and on what
GET  /api/v1/scans/{id}/sbom           CycloneDX document
GET  /api/v1/sboms/diff?base=&head=    the PR supply-chain delta
```

## Project status

🧪 **Working POC** — scan pipeline, normalization + dedup, EPSS/KEV-driven
risk ranking, policy-as-code gate, SBOM diff, demo dashboard, and a CI gate
with real CISA-KEV membership checks all work end to end. See the
[roadmap](docs/06-ROADMAP.md) for what's shipped vs next (multi-engine,
GitHub App, AI remediation).

## Docs

| Doc | Contents |
|---|---|
| [01-VISION.md](docs/01-VISION.md) | Problem, market, positioning, why this project matters |
| [02-ARCHITECTURE.md](docs/02-ARCHITECTURE.md) | Modules, flows, key design decisions |
| [03-TECH-STACK.md](docs/03-TECH-STACK.md) | Every technology choice + the reasoning |
| [04-DATA-MODEL.md](docs/04-DATA-MODEL.md) | Entities, ERD, scoring formula |
| [05-API-DESIGN.md](docs/05-API-DESIGN.md) | REST API surface |
| [06-ROADMAP.md](docs/06-ROADMAP.md) | Phased delivery plan with checklists |
| [07-GITHUB-APP-SETUP.md](docs/07-GITHUB-APP-SETUP.md) | Registering and wiring the GitHub App |
| [08-DEV-SETUP.md](docs/08-DEV-SETUP.md) | Local environment setup |
| [09-INTERVIEW-TALKING-POINTS.md](docs/09-INTERVIEW-TALKING-POINTS.md) | How to present this project |

## License

MIT
