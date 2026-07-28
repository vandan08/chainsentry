package io.chainsentry.demo;

import io.chainsentry.demo.DemoFixtures.Flavor;
import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.orchestration.ScanOrchestrator;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import io.chainsentry.shared.model.ScanTrigger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.List;

/**
 * Seeds the demo world on startup: one org, a handful of repositories each with
 * a scripted scan history, and a frozen EPSS/KEV feed snapshot so risk scores
 * are reproducible. Every scan runs the real pipeline — only the scanner
 * containers are canned — so normalization, cross-engine dedup, risk scoring
 * and the policy gate all execute as they would in production.
 *
 * <p>Scans are backdated across the past few weeks so the trend chart and the
 * "last scanned" column show a plausible history rather than 20 scans landing
 * in the same second. Idempotent — restarting against the same database skips
 * seeding.
 */
@Component
@Profile("demo")
class DemoDataLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataLoader.class);
    private static final String FLAGSHIP_REPO = "acme/payment-service";

    /**
     * The seeded world. The flagship repository ends on the canonical
     * base → head pair (a clean main, then PR #42 pulling in Log4Shell); the
     * others give the org overview a mix of healthy, regressed and remediated
     * postures.
     */
    private static final List<RepoScript> WORLD = List.of(
            new RepoScript(FLAGSHIP_REPO, 8675309L, List.of(
                    ScanScript.push(Flavor.CLEAN, 34),
                    ScanScript.push(Flavor.CLEAN, 21),
                    ScanScript.pr(Flavor.VULNERABLE, 38, "feat/retry-policy", 12),
                    ScanScript.pushAt(Flavor.CLEAN, 5, DemoFixtures.BASE_COMMIT),
                    ScanScript.prAt(Flavor.VULNERABLE, 42, "feat/audit-logging", 1, DemoFixtures.HEAD_COMMIT))),

            new RepoScript("acme/checkout-web", 5150001L, List.of(
                    ScanScript.push(Flavor.VULNERABLE, 28),
                    ScanScript.pr(Flavor.VULNERABLE, 114, "fix/bump-log4j", 19),
                    ScanScript.push(Flavor.CLEAN, 9),
                    ScanScript.push(Flavor.CLEAN, 2))),

            new RepoScript("acme/identity-gateway", 5150002L, List.of(
                    ScanScript.push(Flavor.CLEAN, 24),
                    ScanScript.push(Flavor.CLEAN, 15),
                    ScanScript.pr(Flavor.VULNERABLE, 77, "feat/token-exchange", 6),
                    ScanScript.push(Flavor.VULNERABLE, 3))),

            new RepoScript("acme/ledger-core", 5150003L, List.of(
                    ScanScript.push(Flavor.CLEAN, 30),
                    ScanScript.push(Flavor.CLEAN, 20),
                    ScanScript.push(Flavor.CLEAN, 11),
                    ScanScript.push(Flavor.CLEAN, 4))),

            new RepoScript("acme/fraud-detector", 5150004L, List.of(
                    ScanScript.push(Flavor.CLEAN, 26),
                    ScanScript.push(Flavor.CLEAN, 13),
                    ScanScript.pr(Flavor.VULNERABLE, 23, "feat/rule-engine", 8),
                    ScanScript.push(Flavor.CLEAN, 2))),

            new RepoScript("acme/notification-worker", 5150005L, List.of(
                    ScanScript.push(Flavor.CLEAN, 16),
                    ScanScript.push(Flavor.CLEAN, 7))));

    private final OrganizationRepository organizations;
    private final TrackedRepositoryRepository repositories;
    private final VulnerabilityRepository vulnerabilities;
    private final ScanJobRepository scanJobs;
    private final ScanOrchestrator orchestrator;
    private final DemoFixtures fixtures;
    private final ObjectMapper objectMapper;
    private final int serverPort;

    DemoDataLoader(OrganizationRepository organizations, TrackedRepositoryRepository repositories,
                   VulnerabilityRepository vulnerabilities, ScanJobRepository scanJobs,
                   ScanOrchestrator orchestrator, DemoFixtures fixtures, ObjectMapper objectMapper,
                   @Value("${server.port}") int serverPort) {
        this.organizations = organizations;
        this.repositories = repositories;
        this.vulnerabilities = vulnerabilities;
        this.scanJobs = scanJobs;
        this.orchestrator = orchestrator;
        this.fixtures = fixtures;
        this.objectMapper = objectMapper;
        this.serverPort = serverPort;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (repositories.findByFullName(FLAGSHIP_REPO).isPresent()) {
            log.info("Demo data already present — skipping seed");
            return;
        }
        seedVulnerabilitySnapshot();

        Organization org = organizations.save(new Organization("acme", 424242L));
        Instant now = Instant.now();
        ScanJob flagshipBase = null;
        ScanJob flagshipHead = null;
        int scanCount = 0;

        for (RepoScript repoScript : WORLD) {
            TrackedRepository repo = repositories.save(new TrackedRepository(
                    org.id(), repoScript.githubId(), repoScript.name(), "main"));

            for (int i = 0; i < repoScript.scans().size(); i++) {
                ScanScript script = repoScript.scans().get(i);
                ScanJob scan = runScan(repo, repoScript.name(), i, script, now);
                scanCount++;
                if (repoScript.name().equals(FLAGSHIP_REPO)) {
                    if (DemoFixtures.BASE_COMMIT.equals(scan.commitSha())) {
                        flagshipBase = scan;
                    } else if (DemoFixtures.HEAD_COMMIT.equals(scan.commitSha())) {
                        flagshipHead = scan;
                    }
                }
            }
        }

        log.info("""

                ── ChainSentry demo ready ──────────────────────────────────────
                Org         acme  ({} repositories, {} scans)
                Flagship    {}  ({})
                Base scan   {}  (push to main)
                Head scan   {}  (PR #42 — adds log4j-core 2.14.1)
                Dashboard   http://localhost:{}/
                Org API     http://localhost:{}/api/v1/orgs/{}/overview
                SBOM delta  http://localhost:{}/api/v1/sboms/diff?base={}&head={}
                ────────────────────────────────────────────────────────────────""",
                WORLD.size(), scanCount,
                FLAGSHIP_REPO, repositories.findByFullName(FLAGSHIP_REPO).orElseThrow().id(),
                flagshipBase == null ? "n/a" : flagshipBase.id(),
                flagshipHead == null ? "n/a" : flagshipHead.id(),
                serverPort,
                serverPort, org.id(),
                serverPort,
                flagshipBase == null ? "n/a" : flagshipBase.id(),
                flagshipHead == null ? "n/a" : flagshipHead.id());
    }

    /** Registers the commit's fixture flavor, runs the real pipeline, then backdates it. */
    private ScanJob runScan(TrackedRepository repo, String repoName, int index, ScanScript script, Instant now) {
        String commitSha = script.commitSha() != null ? script.commitSha() : syntheticSha(repoName, index);
        fixtures.register(commitSha, script.flavor());

        ScanJob scan = scanJobs.save(new ScanJob(
                repo.id(), commitSha, script.ref(), script.prNumber(), script.trigger()));
        orchestrator.runPipeline(scan.id());

        ScanJob completed = scanJobs.findById(scan.id()).orElseThrow();
        Instant startedAt = now.minus(Duration.ofDays(script.daysAgo()));
        completed.backdate(startedAt, startedAt.plusSeconds(47));
        return scanJobs.save(completed);
    }

    /** Deterministic stand-in commit SHA, so reseeding produces the same world. */
    private static String syntheticSha(String repoName, int index) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1")
                    .digest((repoName + "#" + index).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is required by every JVM", e);
        }
    }

    /** Frozen 2026-07 snapshot of the EPSS/KEV feeds for the five demo CVEs. */
    private void seedVulnerabilitySnapshot() {
        JsonNode snapshot = objectMapper.readTree(fixtures.vulnerabilitySnapshot());
        Instant syncedAt = Instant.now();
        for (JsonNode entry : snapshot) {
            Vulnerability vuln = new Vulnerability(
                    entry.path("id").asString(),
                    BigDecimal.valueOf(entry.path("cvss").asDouble()),
                    entry.path("vector").asText(null),
                    entry.path("summary").asText(null));
            vuln.updateEpss(BigDecimal.valueOf(entry.path("epss").asDouble()), syncedAt);
            if (entry.path("kev").asBoolean(false)) {
                vuln.markInKev(LocalDate.parse(entry.path("kevAdded").asString()), syncedAt);
            }
            vulnerabilities.save(vuln);
        }
    }

    private record RepoScript(String name, long githubId, List<ScanScript> scans) {
    }

    /** One scan in a repository's history. A null {@code commitSha} is generated. */
    private record ScanScript(Flavor flavor, ScanTrigger trigger, String ref, Integer prNumber,
                              int daysAgo, String commitSha) {

        static ScanScript push(Flavor flavor, int daysAgo) {
            return new ScanScript(flavor, ScanTrigger.PUSH, "main", null, daysAgo, null);
        }

        static ScanScript pushAt(Flavor flavor, int daysAgo, String commitSha) {
            return new ScanScript(flavor, ScanTrigger.PUSH, "main", null, daysAgo, commitSha);
        }

        static ScanScript pr(Flavor flavor, int prNumber, String ref, int daysAgo) {
            return new ScanScript(flavor, ScanTrigger.PR, ref, prNumber, daysAgo, null);
        }

        static ScanScript prAt(Flavor flavor, int prNumber, String ref, int daysAgo, String commitSha) {
            return new ScanScript(flavor, ScanTrigger.PR, ref, prNumber, daysAgo, commitSha);
        }
    }
}
