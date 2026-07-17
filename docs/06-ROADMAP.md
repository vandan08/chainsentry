# Roadmap

Phased so that **every phase ends with something demoable**. Estimates assume part-time solo work; adjust freely. Ship phases as tagged releases (`v0.1.0`, `v0.2.0`, …) with release notes — the git history is part of the portfolio.

---

## Phase 0 — Foundation (this commit) ✅
- [x] Vision, architecture, data model, API design docs
- [x] Spring Boot 4.1 skeleton (Java 24), module packages, health endpoint
- [x] Docker Compose (Postgres + Redis), Flyway V1 migration
- [x] CI workflow (build + test)
- [x] Risk score calculator with unit tests (the differentiator, testable from day one)

## Phase 1 — Scan pipeline MVP ✅ (POC vertical slice, shipped with parts of P2/P3 below)
**Demo: `mvn spring-boot:run -Dspring-boot.run.profiles=demo` → risk-ranked findings, gate verdict, SBOM delta, dashboard.**
- [x] `ScannerEngine` SPI + Trivy adapter (`docker run` via ProcessBuilder, read-only mount, hard timeout)
- [x] Git clone service (shallow clone into ephemeral workspace)
- [x] Scan job lifecycle: PENDING → RUNNING → COMPLETED/FAILED, persisted
- [x] Trivy JSON → unified Finding normalization + fingerprinting + scope inference
- [x] `POST /repos/{id}/scans`, `GET /scans/{id}`, `GET /scans/{id}/findings`, `GET /scans/{id}/gate`
- [x] Demo profile: recorded Trivy/CycloneDX fixtures through the real pipeline, frozen EPSS/KEV snapshot, seeded PASS + FAIL scans
- [ ] Testcontainers integration test: scan a fixture project with a known CVE (e.g. log4j-core 2.14.1), assert the finding
- [x] Golden-file tests for normalization (48 unit tests, Docker-free `mvn verify`)

## Phase 2 — Multi-engine + risk engine ✅ → `v0.2.0`
**Demo: same CVE from two engines = one finding; KEV CVE outranks a plain critical.**
- [x] Semgrep + Dependency-Check adapters (fan-out on virtual threads already in place)
- [x] Cross-engine dedup (FINDING_SOURCE) — fingerprint collapse + per-engine sources; purl-keyed
      fingerprints survive engines disagreeing on file paths, later engines gap-fill scope/fix data
- [x] EPSS + KEV feed sync jobs (scheduled daily, opt-in, stored in VULNERABILITY; Redis caching still TODO)
- [x] Composite risk scoring wired into persistence (org-overridable weights)
- [x] Re-rank persisted findings when feeds update (`VulnerabilityFeedsUpdated` event → `FindingReRankService`)
- [x] SBOM storage (CycloneDX) + `GET /scans/{id}/sbom` (Trivy CycloneDX generator behind `SbomGenerator` SPI)

## Phase 3 — GitHub App + policy gate ✅ → `v0.3.0`  ⭐ the money demo
**Demo: open a PR adding log4j 2.14.1 → red Check Run + rich PR comment in 90 seconds.**
- [x] Webhook endpoint, HMAC verification (raw body, constant-time), delivery dedup (App registration
      itself is the manual step in docs/07-GITHUB-APP-SETUP.md)
- [x] Installation token service (RS256 App JWT → installation token, cached to ~5 min before expiry)
- [x] PR/push events → scan trigger (via `ScanRequested` event); Check Run with risk-ranked
      annotations on completion (`ScanCompleted` → `CheckRunPublisher`)
- [x] `chainsentry.yml` parser + policy gate evaluation (per-rule verdicts with offenders; repo file > platform default)
- [x] SBOM diff (base vs head) — `GET /sboms/diff` with vuln-annotated added/changed/removed (PR comment still TODO)
- [x] Suppressions with expiry + OpenVEX statement generation — `POST /findings/{id}/suppress`,
      `GET /repos/{id}/vex` aggregate; scan pipeline re-applies unexpired suppressions;
      ACCEPTED_RISK maps to OpenVEX `affected` + action statement, never a silent pass

## Phase 4 — GitHub Action + dashboard (~2–3 weeks) → `v0.4.0`
**Demo: `uses: <you>/chainsentry-action@v1` in any workflow; dashboard shows trend.**
- [x] Composite Action: Trivy in the runner + `gate.py` (severity budgets, real KEV membership via CISA catalog)
- [ ] Optional upload to platform (`/scans/upload`) for history
- [ ] SARIF output → GitHub code scanning tab
- [x] Dashboard (static, no build step): scans, risk-ranked findings, gate detail, SBOM delta — served at `/`
- [ ] React dashboard with org overview + trend chart; GitHub OAuth login

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
