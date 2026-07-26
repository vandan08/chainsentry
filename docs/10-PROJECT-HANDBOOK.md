# ChainSentry Project Handbook

One document to understand the whole project: what it does, how a scan flows through it,
every technology used, **where** it's used, **why** it was chosen, and what its **USP**
(unique selling point) is — both for the tech itself and for you when explaining the project.

> Companion docs: [01-VISION](01-VISION.md) (the "why build this"), [02-ARCHITECTURE](02-ARCHITECTURE.md)
> (deep design decisions), [06-ROADMAP](06-ROADMAP.md) (what's done / next), [08-DEV-SETUP](08-DEV-SETUP.md)
> (how to run it on this machine).

---

## 1. What ChainSentry is, in one paragraph

ChainSentry is a **supply-chain security platform**. It scans code, dependencies, and container
images in CI (triggered by GitHub pull requests or a GitHub Action), merges the output of three
different scanners into one deduplicated finding model, then does the thing most scanners don't:
it ranks every finding by **real-world exploitability** (CVSS × EPSS × CISA-KEV × dependency scope),
diffs the **SBOM of every PR** (what components did this PR add/remove/upgrade, and what vulns came
with them), enforces **policy-as-code** gates from a `chainsentry.yml` file, and emits **OpenVEX**
evidence for suppressed findings. An AI layer (Claude API) explains findings in context and drafts
guarded upgrade PRs.

**The product wedge:** scanners like Trivy are engines, not platforms — no history, no policy, no
PR context. Snyk/Dependabot detect well but prioritize badly (CVSS noise) and produce no VEX.
ChainSentry is the *prioritization + evidence layer on top of best-of-breed open-source engines*.

---

## 2. The system at a glance

```
GitHub PR webhook ──► github module ──► ScanRequested event
                                              │
                      ┌───────────────────────▼────────────────────────┐
                      │ orchestration: ScanJob PENDING → RUNNING       │
                      │ fan-out on virtual threads                     │
                      └───┬───────────────┬───────────────┬────────────┘
                          ▼               ▼               ▼
                       Trivy           Semgrep      Dependency-Check     (containers, read-only mounts)
                          └───────────────┴───────────────┘
                                          ▼
                      normalization: raw JSON → unified Finding, dedup fingerprint
                                          ▼
                      risk: enrich with EPSS/KEV/scope → composite risk score
                                          ▼
                      policy: evaluate chainsentry.yml gates + suppressions
                                          ▼
                      github: Check Run (pass/fail) + annotations      ──► back to the PR
                                          ▼
                      dashboard read API ──► React dashboard
```

Everything lives in **one deployable** (`backend/`), split into acyclic modules under
`io.chainsentry.*`. Cross-module triggers flow only through Spring events in `shared/event`
(`ScanRequested` in, `ScanCompleted` out) — that's what keeps the monolith modular.

| Module | Responsibility |
|---|---|
| `github` | Webhook ingestion (HMAC-verified), Checks API, PR comments, installation tokens |
| `orchestration` | Scan lifecycle, queueing, scanner fan-out, retries, timeouts |
| `scanner` | Engine adapters behind the `ScannerEngine` SPI |
| `normalization` | SARIF-aligned mapping, cross-scanner dedup, fingerprinting |
| `risk` | Risk score engine; EPSS/KEV feed sync |
| `sbom` | CycloneDX generation/storage, SBOM diff, OpenVEX emission |
| `policy` | `chainsentry.yml` parsing, gate evaluation, suppressions |
| `remediation` | Claude-backed explanations + guarded upgrade PRs |
| `dashboard` | Read-model REST API for the UI |
| `demo` | Seeded fixture scans for the demo profile |
| `shared` | IDs, value types, error model, events |

---

## 3. Technology reference — where, why, USP

### 3.1 Platform core

#### Java 24 (→ 25 LTS)
- **Where:** the entire backend.
- **Why:** the workload is orchestration of long-blocking work (scanner containers run for
  seconds to minutes). Virtual threads let one node drive hundreds of concurrent scans with
  plain, sequential-looking code — no reactive framework needed. Records replace DTO boilerplate
  (project convention: records over Lombok); pattern matching cleans up the normalization code.
- **USP:** *virtual threads* — thread-per-task concurrency at massive scale without async/await
  or Reactor. This is the single biggest reason a "spawn 3 scanners and wait" design stays simple.
- **Note:** pom targets 24 to match the installed JDK; bump `<java.version>` to 25 when JDK 25
  lands — no code changes expected. ⚠️ This machine's `JAVA_HOME` may point at JDK 17; Maven
  needs `C:\Program Files\Java\jdk-24`.

#### Spring Boot 4.1 (Framework 7, Jakarta EE 11)
- **Where:** application skeleton, dependency injection, web layer (`spring-boot-starter-webmvc`),
  JPA (`spring-boot-starter-data-jpa`), validation, actuator health endpoints.
- **Why:** the industry-default Java application framework; Boot 4 (not 3.x) signals a current
  stack. Constructor injection everywhere, no field injection (project convention).
- **USP:** auto-configuration + starters — a production-grade app (metrics, health, migrations,
  connection pools) from a short pom.
- **Gotcha you must remember:** Boot 4 **modularized auto-configuration**. `flyway-core` alone
  silently never migrates — you need `spring-boot-flyway`. `RestClient.Builder` needs
  `spring-boot-restclient`. And Boot 4 resolves **Jackson 3** (`tools.jackson.*`), so YAML support
  is `tools.jackson.dataformat:jackson-dataformat-yaml`, *not* the `com.fasterxml` artifact
  (which drags in a second databind).

#### Spring Modulith (architecture style)
- **Where:** the module layout above; boundary enforcement; event-driven module communication.
- **Why:** a one-person project shouldn't pay the operational cost of microservices, but should
  still have enforceable boundaries. Each module hides internals (package-private), exposes an
  API, and talks to others via events.
- **USP:** *microservice-grade separation without the network* — plus each module is a clean
  extraction seam if scale ever demands a real service split. This is the architecture story
  of the project.

#### PostgreSQL 16
- **Where:** all persistent state — repos, scans, findings, vulnerabilities (EPSS/KEV data),
  suppressions, SBOM documents, outbox events.
- **Why:** the data is fundamentally relational (findings ↔ scans ↔ repos), but raw scanner
  reports and CycloneDX SBOMs are documents — **JSONB** stores those in the same database with
  queryability. One database, two storage styles; no need for MongoDB or S3 at this volume.
- **USP:** JSONB — relational integrity *and* schemaless documents in one engine.
- **Convention:** enum-like columns are `VARCHAR + CHECK` constraints (not Postgres enums) to
  match JPA's `@Enumerated(STRING)`. On this machine Postgres runs on **5433** (`local` profile)
  because 5432 is taken.

#### Flyway
- **Where:** `backend/src/main/resources/db/migration` — every schema change from commit #1.
- **Why:** the schema is owned by versioned SQL migrations; Hibernate runs `ddl-auto: validate`
  and is never allowed to touch the schema. Migrations are reviewable, ordered, and reproducible.
- **USP:** the database schema has a git history like the code does.

#### Redis 7
- **Where:** job queue (Streams + consumer groups), EPSS/KEV feed cache, rate-limit counters.
- **Why:** already needed for caching, and Redis Streams covers the queue requirement — consumer
  groups give at-least-once delivery with claim-based retry. Combined with a **Postgres outbox**
  (job row + event written in one transaction), no scan is ever lost.
- **USP:** one dependency, three jobs (queue + cache + counters). Choosing this over Kafka is a
  deliberate anti-overengineering decision — see §5.

#### Maven 3.9
- **Where:** backend build; `mvn verify` = 113 Docker-free unit tests, `mvn verify -Pintegration`
  adds the Testcontainers pipeline test.
- **Why:** ubiquitous in the Java ecosystem; convention over configuration; trivially extendable
  to multi-module later.
- **USP:** everyone can read a pom.

### 3.2 Security & scanning domain

#### Trivy (Aqua Security)
- **Where:** `scanner` module adapter; the workhorse engine. Container image scanning,
  filesystem SCA, secret detection, **and CycloneDX SBOM generation** (behind the
  `SbomGenerator` SPI). Also runs in the GitHub Action.
- **Why:** the broadest single open-source engine — one tool covers four scan types — with
  first-class JSON and CycloneDX output.
- **USP:** breadth + native SBOM generation; the de-facto standard OSS scanner post-Log4Shell.

#### Semgrep
- **Where:** `scanner` module adapter for **SAST** — code-level findings (injection, crypto
  misuse), per-language rules.
- **Why:** Trivy covers dependencies/containers but not your *own* code. Semgrep fills the
  static-analysis gap with fast, readable, customizable rules.
- **USP:** rules look like the code they match — writing a custom rule takes minutes, not a
  compiler-theory degree.

#### OWASP Dependency-Check
- **Where:** `scanner` module adapter; a **second SCA opinion** alongside Trivy.
- **Why (this is the clever part):** the overlap with Trivy is *intentional*. Two engines
  reporting the same CVE on the same artifact is exactly what exercises the cross-engine
  **dedup pipeline** — and each engine catches feed gaps the other misses.
- **USP for the project:** it proves the normalization layer is real, not theoretical.

#### How engines run: Docker-out-of-Docker
Every engine runs as its **official container image** (`aquasec/trivy`, `semgrep/semgrep`,
`owasp/dependency-check`) launched by the adapter with the workspace mounted **read-only**,
a hard timeout, and CPU/memory limits. Why: engine upgrade = image tag bump (no library
lock-in), an engine crash can't take the platform down, and execution is identical locally,
in CI, and server-side.

#### CycloneDX (SBOM format)
- **Where:** `sbom` module — generated per scan by Trivy, stored as JSONB, diffed base-vs-head
  per PR (`GET /sboms/diff`).
- **Why over SPDX:** better tooling in the *security* ecosystem, native Trivy support, and it's
  vulnerability-analysis oriented (SPDX grew out of license compliance).
- **USP:** the **SBOM diff is the PR story** — "this PR added log4j-core 2.14.1 carrying
  CVE-2021-44228" is the demo to lead with. Also the compliance answer: EO 14028, EU Cyber
  Resilience Act, and NIST SSDF all push SBOM requirements.

#### OpenVEX
- **Where:** `sbom`/`policy` modules — every approved suppression generates a machine-readable
  exploitability statement; `GET /repos/{id}/vex` aggregates them.
- **Why:** "we know this CVE doesn't affect us" usually lives in a Slack thread. VEX makes the
  claim machine-readable and auditable. Almost nobody generates it — that's the differentiator.
- **USP:** turns tribal knowledge into evidence. An `ACCEPTED_RISK` suppression maps to an
  OpenVEX `affected` + action statement — never a silent pass.

#### SARIF 2.1
- **Where:** `normalization` module — the unified internal finding model is SARIF-aligned;
  `GET /scans/{id}/sarif` exports it; the Action can upload it to GitHub's code-scanning tab.
- **Why:** every scanner speaks its own JSON dialect; SARIF is the OASIS-standard interchange
  format, and aligning the internal model with it makes export trivial.
- **USP:** free extra visibility — findings appear in GitHub's native Security tab at no cost.
- **Dedup fingerprint:** `hash(vulnId | normalized package coordinates | location)` — purl-keyed
  so engines disagreeing on file paths still collapse into one Finding with multiple `sources`.

#### EPSS (FIRST.org) + CISA KEV
- **Where:** `risk` module — daily scheduled sync jobs pull the EPSS CSV and KEV JSON into
  Postgres; a `VulnerabilityFeedsUpdated` event re-ranks already-persisted findings.
- **Why:** this is **the core thesis of the whole product**. CVSS measures theoretical severity;
  EPSS measures *probability of exploitation in the wild* (fewer than ~5% of "High/Critical"
  CVEs are ever exploited). KEV is the "actively being exploited right now" list.
- **The formula (the differentiator):**
  ```
  risk = 0.25·(CVSS/10) + 0.40·EPSS + 0.25·KEV + 0.10·scope_factor
  ```
  EPSS gets the largest weight because exploit probability is what CVSS lacks; KEV is a step
  function (∈{0,1}) because "actively exploited" should dominate; scope_factor discounts
  transitive/test-only dependencies (direct-runtime 1.0 → transitive-test 0.15). Weights are
  org-configurable.
- **USP:** a KEV-listed medium outranks a theoretical critical. That one sentence is the pitch.

### 3.3 Integration & delivery

#### GitHub App
- **Where:** `github` module — webhooks (PR/push/installation), Checks API, PR comments.
- **Why over an OAuth App:** per-installation tokens are short-lived and least-privilege
  (`checks:write`, `contents:read`, `pull_requests:write`, `metadata:read`); Checks API access;
  org-level install. Every webhook delivery is HMAC-verified (raw body, constant-time compare)
  and deduplicated by delivery ID. The RS256 App JWT → installation token exchange is cached
  to ~5 minutes before expiry.
- **USP:** the PR *is* the decision point — a red Check Run before merge beats a nightly report
  after. Setup steps: [07-GITHUB-APP-SETUP](07-GITHUB-APP-SETUP.md).

#### GitHub Action (composite) + `gate.py`
- **Where:** `github-action/` — runs Trivy inside the CI runner, evaluates severity budgets and
  real KEV membership, optionally uploads the normalized bundle to the platform
  (`POST /api/v1/scans/upload`).
- **Why composite (not Docker action):** it can pull engine images directly and stays fast.
- **USP — the dual-mode story:** server-side scan (SaaS mode, code is cloned by the platform,
  powers history/dashboard) vs CI-side scan (Action mode, **code never leaves the customer's
  infra**). *The policy gate evaluates identically in both modes.* This is the strongest
  security-architecture talking point in the project.

#### Testcontainers 2.x
- **Where:** `mvn verify -Pintegration` → `ScanPipelineIT` runs the full pipeline against a
  **real Postgres** in Docker; asserts the log4j finding, cross-engine dedup, gate verdicts,
  and JSONB SBOM storage.
- **Why:** an H2-mocked test proves nothing about JSONB, CHECK constraints, or Flyway. Real
  dependencies, disposable containers, no shared test infra.
- **USP:** integration tests you can trust, on any machine with Docker.
- **Gotcha:** Boot 4 manages Testcontainers **2.x** — artifacts are `testcontainers-postgresql`
  / `testcontainers-junit-jupiter`; the 1.x names have no managed version.

#### Testing strategy overall
- 113 Docker-free unit tests (`mvn verify`) including **golden-file tests** for normalization:
  recorded engine JSON in → expected Findings out. Deliberate split: plain `verify` needs no
  Docker so CI and quick local loops stay fast; `-Pintegration` opts into the heavy test.

### 3.4 Dashboard (frontend/)

| Tech | Where / why | USP |
|---|---|---|
| **React 19 + TypeScript** | The dashboard SPA: org overview, repo trend, scan detail. TS catches API-shape drift at compile time. | The default hiring-market frontend stack; TS types mirror the read-API DTOs. |
| **Vite 6** | Dev server + build (`npm run dev` / `tsc -b && vite build`). | Instant HMR, near-zero config — the modern replacement for CRA/webpack setups. |
| **React Router 7** | Client-side routing between overview → repo → scan detail. | Standard SPA navigation. |
| **Recharts** | Trend chart (risk over time per repo). | Declarative charts as React components; no D3 boilerplate for simple dashboards. |

Design stance: the dashboard is deliberately thin — it talks only to the `dashboard` module's
**read-model API**. The platform is the substance; a small polished UI beats a big half-finished one.

### 3.5 AI layer (remediation module)

#### Claude API
- **Where:** `remediation` module — `POST /findings/{id}/explain` and `POST /findings/{id}/fix-pr`.
  `claude-sonnet-5` default, `claude-fable-5` for complex patches. API key lives in
  `application-local.yml` (gitignored); returns 503 when unconfigured.
- **Why:** an explanation grounded in the data ChainSentry already has (CVSS/EPSS/KEV/scope/risk
  score, repo context) is far more useful than a generic CVE description.
- **The guardrails are the USP** (this is what makes it interview-worthy, not the LLM call):
  - Fix PRs use a **deterministic version bump — no LLM in the write path**.
  - Draft-only, hardcoded — never auto-merged.
  - File whitelist (`pom.xml`/`package.json` only), single unambiguous version-string
    replacement **or refuse**, bounded size delta before pushing.
  - The lesson: AI proposes, deterministic code disposes.

### 3.6 Cross-cutting

| Concern | Choice | Why |
|---|---|---|
| Observability | Micrometer → Prometheus, OpenTelemetry traces | Per-engine scan duration / failure-rate metrics from day one. |
| Platform security | HMAC webhooks, encrypted tokens at rest, ephemeral tmpfs workspaces, non-root no-network engines, rate limiting | A security tool must be visibly secure itself. |
| Config/secrets | `application-local.yml` (gitignored) | Secrets never in `application.yml`. |
| Commits/branches | Conventional Commits, `feat/p<phase>-<topic>` | Git history is part of the portfolio. |
| Demo | `demo` profile: recorded fixtures through the *real* pipeline | `mvn spring-boot:run -Dspring-boot.run.profiles=demo` seeds a PASS and a FAIL scan + dashboard at `/`. Add `local` profile on this machine (ports 5433/8081). |

---

## 4. Where things are decided — quick index

| "Where does … happen?" | Module / place |
|---|---|
| Webhook signature check, delivery dedup | `github` |
| Job queue, retries, virtual-thread fan-out | `orchestration` (Redis Streams + Postgres outbox) |
| `docker run aquasec/trivy …` | `scanner` adapters (ProcessBuilder / Docker API) |
| Same CVE from two engines → one finding | `normalization` (purl-keyed fingerprint) |
| The 0.25/0.40/0.25/0.10 formula | `risk` |
| SBOM generate/store/diff, VEX emission | `sbom` |
| `chainsentry.yml` gates, suppressions | `policy` |
| Claude explain / draft fix PR | `remediation` |
| Data the React app reads | `dashboard` read API |
| Schema | `db/migration` Flyway scripts, JPA only validates |

---

## 5. Deliberately NOT used (know these cold — they're interview gold)

| Rejected | In favor of | Reasoning |
|---|---|---|
| **Kafka / RabbitMQ** | Redis Streams | Redis is already there for caching; Streams gives consumer groups + persistence at this scale. Kafka here would be résumé-driven development. |
| **Microservices / K8s** | Modular monolith (Modulith) | One-person project; boundaries enforced in-process; extraction later is cheap, premature distribution isn't. |
| **Lombok** | Records + modern Java | Less annotation-processor risk on new Java versions; the language caught up. |
| **MongoDB / S3** | Postgres JSONB | Findings/SBOMs are relational + document-shaped; raw reports are MBs, not GBs. One database. |
| **Reactive stack (WebFlux)** | Virtual threads | Same scalability for blocking workloads, sequential readable code. |
| **SPDX** | CycloneDX | CycloneDX is vuln-analysis oriented with better security tooling and native Trivy support. |
| **Embedding scanner libraries** | Containers via Docker API | Isolation, upgradability (tag bump), honest SaaS architecture. |
| **LLM writing patch files** | Deterministic version bump | The AI never touches the write path; guardrails over vibes. |

---

## 6. The 60-second pitch (memorize this)

1. **Problem:** a mature service has hundreds of CVEs; CVSS calls a third of them critical;
   EPSS data says under 5% will ever be exploited. Teams can't tell which 5%, and they find
   out after merge, not at the PR.
2. **Solution:** ChainSentry orchestrates best-of-breed OSS scanners in CI, dedupes them into
   one finding model, ranks by **CVSS × EPSS × KEV × scope**, diffs the **SBOM per PR**, gates
   merges with **policy-as-code**, and emits **OpenVEX** evidence.
3. **Money demo:** open a PR adding log4j 2.14.1 → red Check Run + rich PR comment in 90 seconds.
4. **Architecture in one breath:** Spring Boot 4 modular monolith on Java 24 virtual threads;
   scanners run as sandboxed containers; Postgres (relational + JSONB) with Flyway; Redis
   Streams queue with a transactional outbox; React 19 dashboard; Claude-backed remediation
   with deterministic guardrails.
5. **What makes it different:** a KEV-listed medium outranks a theoretical critical — and every
   suppression becomes auditable VEX evidence instead of a Slack thread.
