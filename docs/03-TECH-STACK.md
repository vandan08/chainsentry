# Tech Stack (and why each piece)

## Platform

| Choice | Version | Why |
|---|---|---|
| **Java** | 24 now → **25 LTS** | Virtual threads (mature since 21), pattern matching, records everywhere, sequenced collections. Pom targets 24 to match the installed JDK; bump `<java.version>` to 25 once JDK 25 is installed — no code changes expected. |
| **Spring Boot** | **4.1.x** (June 2026) | Current stable line on Spring Framework 7 / Jakarta EE 11. Using Boot 4 (not 3.x) signals an up-to-date stack — most tutorials are still on 3.x. |
| **Spring Modulith** | latest matching Boot 4 | Enforced module boundaries + event-driven inter-module communication + `@ApplicationModuleTest` slice tests. The architecture story of the project. |
| **PostgreSQL** | 16 | Relational core + JSONB for raw scanner reports and SBOM documents. One database, two storage styles. |
| **Flyway** | managed by Boot | Versioned schema migrations from commit #1. |
| **Redis** | 7 | Job queue (Streams + consumer groups), EPSS/KEV feed cache, rate-limit counters. |
| **Maven** | 3.9 | Ubiquitous in the Java job market; multi-module later if needed. |

## Security/scanning domain

| Choice | Role |
|---|---|
| **Trivy** | Container image scanning, filesystem SCA, secret detection, **CycloneDX SBOM generation**. The workhorse engine. |
| **Semgrep** | SAST — code-level findings (injection, crypto misuse, etc.), custom rules per language. |
| **OWASP Dependency-Check** | Second SCA opinion; overlap with Trivy is *intentional* — it exercises the dedup pipeline and catches feed gaps. |
| **CycloneDX** | SBOM format (chosen over SPDX: better tooling in the security ecosystem, native Trivy support, vuln-analysis oriented). |
| **OpenVEX** | Machine-readable exploitability statements generated from approved suppressions. |
| **SARIF 2.1** | Interchange format for the unified finding model; also uploadable to GitHub code scanning UI for free extra visibility. |
| **EPSS (FIRST.org)** | Daily exploit-probability scores per CVE — the core of prioritization. |
| **CISA KEV** | Known Exploited Vulnerabilities catalog — the "drop everything" flag. |

## Integration & delivery

| Choice | Role |
|---|---|
| **GitHub App** | Webhooks (PR/push/installation), Checks API, PR comments, short-lived installation tokens. |
| **GitHub Action** (composite) | CI-side scanning + build gate. Composite (not Docker action) so it can pull engine images directly and stay fast. |
| **Docker Java client** | Launching scanner containers with mounts, limits, timeouts. |
| **Testcontainers** | Integration tests against real Postgres/Redis/scanner images. |
| **GitHub Actions CI** | Build, test, and — dogfooding — ChainSentry scanning itself. |

## Dashboard (phase 4)

React 19 + TypeScript + Vite, TanStack Query, Tailwind. Served separately; talks to the `dashboard` module's read API. (Deliberately phase 4 — the platform is the substance; a thin polished UI beats a big half-finished one.)

## AI layer (phase 5)

**Claude API** (`claude-sonnet-5` default; `claude-fable-5` for complex patches) for finding explanations in repo context and draft upgrade PRs. Structured tool-use output → validated JSON → never auto-merged, always a draft PR.

## Explicitly *not* used, and why (interview gold)

- **Kafka** — Redis Streams covers the queue need at this scale; adding Kafka would be résumé-driven development.
- **Microservices/K8s (v1)** — modular monolith on a single node; boundaries are enforced by Modulith, extraction is a later decision with data.
- **Lombok** — records + modern Java remove most boilerplate; fewer annotation-processor surprises on new Java versions.
- **MongoDB** — findings/SBOMs are relational + JSONB-shaped; Postgres does both.
