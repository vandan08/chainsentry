# Vision & Positioning

## Elevator pitch

> ChainSentry is a DevSecOps platform that scans code, dependencies, and containers in CI — then ranks findings by **real-world exploitability** (EPSS + CISA KEV), diffs the **supply-chain risk of every pull request**, and enforces **policy-as-code** gates. It ships SBOMs and OpenVEX documents so security teams get evidence, not just alerts.

## The problem, precisely

1. **Alert fatigue.** A single `mvn dependency:tree` on a mature service surfaces 200–800 CVEs across transitive dependencies. CVSS says a third are "High or Critical". EPSS data says fewer than ~5% will ever be exploited. Teams can't tell which 5%.
2. **Scanning happens too late.** Nightly scans of `main` tell you what you already merged. The decision point is the pull request.
3. **Suppressions are tribal knowledge.** "We know CVE-2023-XXXX doesn't affect us" lives in a Slack thread. Auditors and downstream consumers can't verify it. OpenVEX exists exactly for this and almost nobody generates it.
4. **Every scanner speaks its own language.** Trivy JSON ≠ Semgrep JSON ≠ Dependency-Check XML. The same vulnerability shows up 2–3 times with different IDs.
5. **Compliance pressure is real and growing.** US Executive Order 14028, the EU Cyber Resilience Act, and NIST SSDF all push SBOM requirements onto vendors. "Do you produce SBOMs?" is now a procurement question.

## Who would pay (SaaS framing)

| Segment | Pain | ChainSentry answer |
|---|---|---|
| Startups (5–50 devs) | No security team; need "secure by default" CI | GitHub App, 5-minute install, sane default policy |
| Mid-market platform teams | Drowning in Snyk/Dependabot noise | Risk-ranked findings, PR-delta view |
| Vendors selling to enterprise/gov | Must produce SBOM + VEX evidence | Automatic CycloneDX + OpenVEX per release |

Pricing sketch (to show product thinking): free for public repos, per-repo tiers for private, enterprise tier for policy management + SSO + audit exports.

## Competitive landscape & the wedge

- **Snyk, Dependabot, Renovate** — great at *detection and upgrade PRs*, weak at *prioritization* (CVSS-driven noise) and produce no VEX.
- **Trivy/Grype standalone** — engines, not platforms: no history, no policy, no PR context.
- **GitHub Advanced Security** — strong but expensive and GitHub-only-code-scanning focused; SBOM/VEX story is thin.

**ChainSentry's wedge:** *the prioritization + evidence layer on top of best-of-breed open-source engines.* We don't compete with Trivy — we orchestrate it and make its output decision-ready.

## Why this project impresses (portfolio lens)

- Demonstrates understanding of the **software supply chain** end-to-end: SCA, SAST, container scanning, SBOM, VEX, attestation — the vocabulary of post-Log4Shell security engineering.
- Real **distributed-systems shape**: webhook ingestion, async job orchestration, external process management, third-party API integration (GitHub), feed synchronization (NVD/EPSS/KEV).
- Real **product thinking**: prioritization formula, policy DSL, PR-first UX — not just a CRUD app.
- Uses the **current Java platform**: Java 24/25, virtual threads, Spring Boot 4 / Framework 7, modular monolith.

## Non-goals (v1)

- Not building our own vulnerability database (we consume NVD/OSV/GHSA via the engines).
- Not runtime protection (no agents, no eBPF) — CI-time only.
- Not GitLab/Bitbucket in v1 — GitHub first, the abstraction layer keeps the door open.
- No Kubernetes admission control in v1 (roadmap candidate).
