# Interview Talking Points

How to present ChainSentry so it lands. Structure every answer as **decision → alternative considered → why**.

## The 30-second pitch

> "I built a supply-chain security platform that scans code, dependencies, and containers in CI. The interesting part isn't running the scanners — it's what happens after: I normalize three engines into one deduplicated finding model, rank findings by real-world exploitability using EPSS and CISA's Known-Exploited catalog instead of raw CVSS, and diff the SBOM on every pull request so reviewers see exactly what supply-chain risk they're about to merge. Suppressions generate OpenVEX documents, so 'we're not affected' becomes verifiable evidence instead of a Slack message."

## Domain depth signals (drop these naturally)

- **Why CVSS alone fails:** CVSS measures severity *if exploited*, not *likelihood of exploitation*. EPSS models that likelihood daily; KEV confirms active exploitation. ~5% of CVEs are ever exploited — prioritizing by CVSS alone means 95% noise.
- **Log4Shell as the design case:** CVSS 10.0, KEV day-one, transitive dependency in thousands of services. ChainSentry's PR-delta would have flagged its *introduction*, not just its existence.
- **SBOM ≠ checkbox:** EO 14028 and the EU Cyber Resilience Act make SBOMs a procurement requirement. VEX is the other half nobody builds — an SBOM says what you ship, VEX says which of its CVEs actually affect you.
- **purl, SARIF, CycloneDX vs SPDX** — knowing the interchange standards is what separates "I called Trivy" from "I work in this domain."

## Architecture questions you should invite

**"Why a modular monolith and not microservices?"**
Solo project, one deploy target. Spring Modulith enforces the boundaries at build time (module tests fail on illegal dependencies), events decouple the modules, and any module is an extraction seam later. Distribution is a cost you pay when data says you must — not a default.

**"Why virtual threads?"**
Scanner runs block for seconds-to-minutes on process I/O. Platform threads would cap concurrency in the hundreds per node with thread-per-scan; virtual threads make thread-per-scan cheap while keeping the code sequential and debuggable — no reactive rewrite.

**"How do you avoid losing scans?"**
Webhook handler persists the job and an outbox event in one Postgres transaction; a relay publishes to Redis Streams; consumer groups give at-least-once delivery; idempotency key (repo, SHA, engine-set) makes redelivery safe. That's the transactional-outbox pattern — say the name.

**"How do you dedup across scanners?"**
Fingerprint = hash(vuln ID, package URL, normalized location). Same CVE from Trivy and Dependency-Check collapses into one finding with two sources. Also an honest answer to "why run two SCA engines?" — coverage differs, and the overlap validates the pipeline.

**"How is the scanning itself secured?"**
Engines run as containers: read-only workspace mount, non-root, no network, CPU/memory limits, hard timeout. Webhooks are HMAC-verified before parsing. Installation tokens are short-lived and never logged. A security tool with sloppy security is a punchline — this is the part reviewers poke at.

## Trade-offs to volunteer (maturity signal)

- Redis Streams over Kafka: right-sized, already needed Redis. Kafka here would be résumé-driven development.
- Dual-mode scanning (server-side vs in-CI upload): SaaS convenience vs "code never leaves your infra" — enterprise buyers ask for the second, so the policy engine evaluates identically in both.
- JSONB for raw reports now, object storage later: measured simplicity, with the migration path named.

## Demo script (3 minutes)

1. Open a PR that bumps in `log4j-core:2.14.1` on the demo repo.
2. Check Run goes red; PR comment shows: *supply-chain delta — 1 new component, CVE-2021-44228, EPSS 0.97, KEV ✓, fix 2.17.1, risk 0.94*.
3. Show the same CVE reported by two engines → one finding, two sources.
4. Suppress a different finding with justification + expiry → show the generated OpenVEX JSON.
5. Dashboard trend: "this is what a security team would actually look at Monday morning."

## Honest scope answers

If asked "is this production-ready?": "It's a working platform with production-shaped architecture; what it lacks is production *history* — no on-call hardening, no scale data. I can tell you exactly what I'd measure first: engine p95 duration, feed-sync lag, and webhook-to-check latency."
