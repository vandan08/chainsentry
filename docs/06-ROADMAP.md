# Roadmap

Phased so that **every phase ends with something demoable**. Estimates assume part-time solo work; adjust freely. Ship phases as tagged releases (`v0.1.0`, `v0.2.0`, …) with release notes — the git history is part of the portfolio.

---

## Phase 0 — Foundation (this commit) ✅
- [x] Vision, architecture, data model, API design docs
- [x] Spring Boot 4.1 skeleton (Java 24), module packages, health endpoint
- [x] Docker Compose (Postgres + Redis), Flyway V1 migration
- [x] CI workflow (build + test)
- [x] Risk score calculator with unit tests (the differentiator, testable from day one)

## Phase 1 — Scan pipeline MVP (~2 weeks) → `v0.1.0`
**Demo: point ChainSentry at a vulnerable repo, get deduped risk-ranked findings via REST.**
- [ ] `ScannerEngine` SPI + Trivy adapter (Docker Java client, mounted workspace, timeout)
- [ ] Git clone service (shallow clone into ephemeral workspace)
- [ ] Scan job lifecycle: PENDING → RUNNING → COMPLETED/FAILED, persisted
- [ ] Trivy JSON → unified Finding normalization + fingerprinting
- [ ] `POST /repos/{id}/scans`, `GET /scans/{id}`, `GET /scans/{id}/findings`
- [ ] Testcontainers integration test: scan a fixture project with a known CVE (e.g. log4j-core 2.14.1), assert the finding
- [ ] Golden-file tests for normalization

## Phase 2 — Multi-engine + risk engine (~2 weeks) → `v0.2.0`
**Demo: same CVE from two engines = one finding; KEV CVE outranks a plain critical.**
- [ ] Semgrep + Dependency-Check adapters; parallel fan-out on virtual threads
- [ ] Cross-engine dedup (FINDING_SOURCE)
- [ ] EPSS + KEV feed sync jobs (scheduled, cached in Redis, stored in VULNERABILITY)
- [ ] Composite risk scoring wired into persistence; re-rank on feed updates
- [ ] SBOM generation (Trivy CycloneDX) + storage + `GET /scans/{id}/sbom`

## Phase 3 — GitHub App + policy gate (~2–3 weeks) → `v0.3.0`  ⭐ the money demo
**Demo: open a PR adding log4j 2.14.1 → red Check Run + rich PR comment in 90 seconds.**
- [ ] GitHub App registration, webhook endpoint, HMAC verification, delivery dedup
- [ ] Installation token service (JWT → token, cached)
- [ ] PR/push events → scan trigger; Checks API run with annotations
- [ ] `chainsentry.yml` parser + policy gate evaluation
- [ ] SBOM diff (base vs head) + PR summary comment ("supply-chain delta")
- [ ] Suppressions with expiry + OpenVEX statement generation

## Phase 4 — GitHub Action + dashboard (~2–3 weeks) → `v0.4.0`
**Demo: `uses: <you>/chainsentry-action@v1` in any workflow; dashboard shows trend.**
- [ ] Composite Action: run engines in the runner, normalize, evaluate policy locally, fail on breach
- [ ] Optional upload to platform (`/scans/upload`) for history
- [ ] SARIF output → GitHub code scanning tab
- [ ] React dashboard: org overview, repo findings (risk-sorted), scan detail, trend chart
- [ ] GitHub OAuth login

## Phase 5 — AI remediation (~1–2 weeks) → `v0.5.0`
**Demo: click "explain" → contextual explanation; click "fix" → draft upgrade PR appears.**
- [ ] Claude API integration: finding explanation with repo context
- [ ] Upgrade-PR drafting for fixable SCA findings (bump version, run build, open draft PR)
- [ ] Guardrails: draft-only, diff size limits, never touches non-manifest files

## Phase 6 — SaaS polish (ongoing)
- [ ] Multi-tenancy hardening (org isolation tests), rate limiting
- [ ] Signed scan attestations (cosign/Sigstore) — provenance story
- [ ] Deploy: Fly.io/Render/Hetzner + managed Postgres; demo instance with a seeded vulnerable repo
- [ ] Landing page with live demo GIF
- [ ] Dogfood: ChainSentry scans ChainSentry in its own CI (badge in README)

---

## Definition of done (every phase)
Tests pass in CI · README/docs updated · tagged release with notes · a 30-second demo you can actually show.

## Biggest risks & mitigations
| Risk | Mitigation |
|---|---|
| Scanner engines are heavy/slow locally | Cache engine DBs in named volumes; fixture repos kept tiny |
| GitHub App complexity stalls momentum | Phase 3 is isolated; Phases 1–2 already demo without GitHub |
| Scope creep (it's a big vision) | Each phase demoable standalone; cut from the top of later phases, never mid-phase |
