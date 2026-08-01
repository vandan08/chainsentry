package io.chainsentry;

import io.chainsentry.demo.DemoFixtures;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.normalization.FindingSource;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.sbom.SbomRepository;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.ScannerType;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The whole pipeline against a real Postgres: Flyway migrations, JPA
 * mappings, CHECK constraints, JSONB columns — everything the Docker-free
 * unit suite can't touch. The demo profile's recorded engine reports run
 * through the genuine normalize → dedup → risk → gate path at startup;
 * this test asserts what landed in the database.
 *
 * <p>Runs only under {@code mvn verify -Pintegration} (needs a Docker daemon).
 */
@SpringBootTest
@ActiveProfiles("demo")
@Testcontainers
@Tag("integration")
class ScanPipelineIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private TrackedRepositoryRepository repositories;
    @Autowired
    private ScanJobRepository scanJobs;
    @Autowired
    private FindingRepository findings;
    @Autowired
    private SbomRepository sboms;

    private ScanJob headScan() {
        TrackedRepository repo = repositories.findByFullName("acme/payment-service").orElseThrow();
        return scanJobs.findByRepositoryIdAndCommitShaAndTrigger(
                repo.id(), DemoFixtures.HEAD_COMMIT, ScanTrigger.PR).orElseThrow();
    }

    @Test
    void headScanCompletesAndFailsTheGateOnLog4Shell() {
        ScanJob scan = headScan();

        assertThat(scan.status()).isEqualTo(ScanStatus.COMPLETED);
        assertThat(scan.gateResult()).isEqualTo(GateStatus.FAIL);
    }

    @Test
    void knownCveIsFoundDedupedAcrossEnginesAndRiskRanked() {
        List<Finding> headFindings = findings.findByScanJobIdOrderByRiskScoreDesc(headScan().id());

        Finding log4shell = headFindings.stream()
                .filter(f -> "CVE-2021-44228".equals(f.vulnerabilityId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("log4j-core 2.14.1 finding missing"));

        assertThat(log4shell.packageCoordinates())
                .isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        // One finding, two reporting engines — cross-engine dedup survived real persistence.
        assertThat(log4shell.sources()).extracting(FindingSource::engine)
                .containsExactlyInAnyOrder(ScannerType.TRIVY, ScannerType.DEPENDENCY_CHECK);
        // KEV + EPSS from the frozen snapshot push it to the top of the ranking.
        assertThat(log4shell.riskScoreOrZero()).isGreaterThan(0.9);
        assertThat(headFindings.getFirst().vulnerabilityId()).isEqualTo("CVE-2021-44228");
    }

    @Test
    void sastFindingsFromSemgrepPersistAlongsideScaFindings() {
        List<Finding> headFindings = findings.findByScanJobIdOrderByRiskScoreDesc(headScan().id());

        assertThat(headFindings)
                .filteredOn(f -> f.type() == FindingType.SAST)
                .anySatisfy(f -> {
                    assertThat(f.sources()).extracting(FindingSource::engine)
                            .containsExactly(ScannerType.SEMGREP);
                    assertThat(f.line()).isNotNull();
                });
    }

    @Test
    void baseScanPassesTheGate() {
        TrackedRepository repo = repositories.findByFullName("acme/payment-service").orElseThrow();
        ScanJob base = scanJobs.findByRepositoryIdAndCommitShaAndTrigger(
                repo.id(), DemoFixtures.BASE_COMMIT, ScanTrigger.PUSH).orElseThrow();

        assertThat(base.gateResult()).isEqualTo(GateStatus.PASS);
    }

    @Test
    void sbomIsStoredAsJsonbForTheScan() {
        assertThat(sboms.findByScanJobId(headScan().id())).isPresent();
    }
}
