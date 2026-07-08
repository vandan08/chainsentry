package io.chainsentry.demo;

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
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

/**
 * Seeds the demo world on startup: one org, one repo, a vulnerability feed
 * snapshot (frozen EPSS/KEV values so the demo is reproducible), then runs
 * both fixture scans synchronously so the API and dashboard have data the
 * moment the app is up. Idempotent — restarting against the same database
 * skips seeding.
 */
@Component
@Profile("demo")
class DemoDataLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataLoader.class);
    private static final String REPO_FULL_NAME = "acme/payment-service";

    private final OrganizationRepository organizations;
    private final TrackedRepositoryRepository repositories;
    private final VulnerabilityRepository vulnerabilities;
    private final ScanJobRepository scanJobs;
    private final ScanOrchestrator orchestrator;
    private final DemoFixtures fixtures;
    private final ObjectMapper objectMapper;

    DemoDataLoader(OrganizationRepository organizations, TrackedRepositoryRepository repositories,
                   VulnerabilityRepository vulnerabilities, ScanJobRepository scanJobs,
                   ScanOrchestrator orchestrator, DemoFixtures fixtures, ObjectMapper objectMapper) {
        this.organizations = organizations;
        this.repositories = repositories;
        this.vulnerabilities = vulnerabilities;
        this.scanJobs = scanJobs;
        this.orchestrator = orchestrator;
        this.fixtures = fixtures;
        this.objectMapper = objectMapper;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (repositories.findByFullName(REPO_FULL_NAME).isPresent()) {
            log.info("Demo data already present — skipping seed");
            return;
        }
        seedVulnerabilitySnapshot();

        Organization org = organizations.save(new Organization("acme", 424242L));
        TrackedRepository repo = repositories.save(
                new TrackedRepository(org.id(), 8675309L, REPO_FULL_NAME, "main"));

        ScanJob baseScan = scanJobs.save(new ScanJob(
                repo.id(), DemoFixtures.BASE_COMMIT, "main", null, ScanTrigger.PUSH));
        orchestrator.runPipeline(baseScan.id());

        ScanJob headScan = scanJobs.save(new ScanJob(
                repo.id(), DemoFixtures.HEAD_COMMIT, "feat/audit-logging", 42, ScanTrigger.PR));
        orchestrator.runPipeline(headScan.id());

        log.info("""

                ── ChainSentry demo ready ──────────────────────────────────────
                Repo        {}  ({})
                Base scan   {}  (push to main)
                Head scan   {}  (PR #42 — adds log4j-core 2.14.1)
                Dashboard   http://localhost:8080/
                SBOM delta  http://localhost:8080/api/v1/sboms/diff?base={}&head={}
                ────────────────────────────────────────────────────────────────""",
                REPO_FULL_NAME, repo.id(), baseScan.id(), headScan.id(), baseScan.id(), headScan.id());
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
}
