package io.chainsentry.normalization;

import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-engine dedup: the same CVE on the same artifact reported by two
 * engines must collapse into one finding with two sources.
 */
class NormalizationServiceTest {

    private static final UUID SCAN_ID = UUID.randomUUID();
    private static final String PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

    /** Stub normalizer that ignores the payload and returns canned findings. */
    private record StubNormalizer(ScannerType engine, List<NormalizedFinding> canned) implements ReportNormalizer {
        @Override
        public List<NormalizedFinding> normalize(RawReport report) {
            return canned;
        }
    }

    private NormalizedFinding log4shellFrom(ScannerType engine, Double cvss) {
        return new NormalizedFinding(engine, "CVE-2021-44228", "CVE-2021-44228", FindingType.SCA,
                Severity.CRITICAL, "Log4Shell", "JNDI RCE", PURL, "2.14.1", "2.15.0",
                DependencyScope.TRANSITIVE_RUNTIME, "pom.xml", null, cvss, null);
    }

    private RawReport reportFor(ScannerType engine) {
        return new RawReport(engine, "test", "{}", Duration.ZERO);
    }

    @Test
    void sameCveFromTwoEnginesCollapsesIntoOneFinding() {
        NormalizationService service = new NormalizationService(List.of(
                new StubNormalizer(ScannerType.TRIVY, List.of(log4shellFrom(ScannerType.TRIVY, 10.0))),
                new StubNormalizer(ScannerType.DEPENDENCY_CHECK,
                        List.of(log4shellFrom(ScannerType.DEPENDENCY_CHECK, null)))));

        NormalizationResult result = service.normalize(SCAN_ID,
                List.of(reportFor(ScannerType.TRIVY), reportFor(ScannerType.DEPENDENCY_CHECK)));

        assertThat(result.findings()).hasSize(1);
        Finding finding = result.findings().getFirst();
        assertThat(finding.sources()).extracting(FindingSource::engine)
                .containsExactlyInAnyOrder(ScannerType.TRIVY, ScannerType.DEPENDENCY_CHECK);
        assertThat(finding.scanJobId()).isEqualTo(SCAN_ID);
        assertThat(finding.vulnerabilityId()).isEqualTo("CVE-2021-44228");
    }

    @Test
    void vulnerabilityMetadataPrefersEntriesWithCvss() {
        // Dependency-Check reports first but without CVSS; Trivy's entry carries the score.
        NormalizationService service = new NormalizationService(List.of(
                new StubNormalizer(ScannerType.DEPENDENCY_CHECK,
                        List.of(log4shellFrom(ScannerType.DEPENDENCY_CHECK, null))),
                new StubNormalizer(ScannerType.TRIVY, List.of(log4shellFrom(ScannerType.TRIVY, 10.0)))));

        NormalizationResult result = service.normalize(SCAN_ID,
                List.of(reportFor(ScannerType.DEPENDENCY_CHECK), reportFor(ScannerType.TRIVY)));

        assertThat(result.vulnerabilityMetadata().get("CVE-2021-44228").cvssScore()).isEqualTo(10.0);
    }

    @Test
    void dedupSurvivesEnginesDisagreeingOnFilePath() {
        // Trivy reports the lockfile, Dependency-Check the resolved jar — same CVE, same purl.
        NormalizedFinding fromTrivy = log4shellFrom(ScannerType.TRIVY, 10.0);
        NormalizedFinding fromDc = new NormalizedFinding(ScannerType.DEPENDENCY_CHECK, "CVE-2021-44228",
                "CVE-2021-44228", FindingType.SCA, Severity.CRITICAL, "CVE-2021-44228", null, PURL,
                "2.14.1", null, null, "target/dependency/log4j-core-2.14.1.jar", null, null, null);
        NormalizationService service = new NormalizationService(List.of(
                new StubNormalizer(ScannerType.TRIVY, List.of(fromTrivy)),
                new StubNormalizer(ScannerType.DEPENDENCY_CHECK, List.of(fromDc))));

        NormalizationResult result = service.normalize(SCAN_ID,
                List.of(reportFor(ScannerType.TRIVY), reportFor(ScannerType.DEPENDENCY_CHECK)));

        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().getFirst().sources()).hasSize(2);
    }

    @Test
    void laterEngineFillsPackageGapsButNeverOverwrites() {
        // DC (no graph, no fix data) reports first; Trivy arrives with scope + fixed version.
        NormalizedFinding sparse = new NormalizedFinding(ScannerType.DEPENDENCY_CHECK, "CVE-2021-44228",
                "CVE-2021-44228", FindingType.SCA, Severity.CRITICAL, "CVE-2021-44228", null, PURL,
                "2.14.1", null, null, "target/dependency/log4j-core-2.14.1.jar", null, null, null);
        NormalizationService service = new NormalizationService(List.of(
                new StubNormalizer(ScannerType.DEPENDENCY_CHECK, List.of(sparse)),
                new StubNormalizer(ScannerType.TRIVY, List.of(log4shellFrom(ScannerType.TRIVY, 10.0)))));

        NormalizationResult result = service.normalize(SCAN_ID,
                List.of(reportFor(ScannerType.DEPENDENCY_CHECK), reportFor(ScannerType.TRIVY)));

        Finding finding = result.findings().getFirst();
        assertThat(finding.fixedVersion()).isEqualTo("2.15.0");
        assertThat(finding.dependencyScope()).isEqualTo(DependencyScope.TRANSITIVE_RUNTIME);
    }

    @Test
    void differentCvesStayDistinct() {
        NormalizedFinding other = new NormalizedFinding(ScannerType.TRIVY, "CVE-2021-45046", "CVE-2021-45046",
                FindingType.SCA, Severity.CRITICAL, "Log4Shell bypass", null, PURL, "2.14.1", "2.16.0",
                DependencyScope.TRANSITIVE_RUNTIME, "pom.xml", null, 9.0, null);
        NormalizationService service = new NormalizationService(List.of(
                new StubNormalizer(ScannerType.TRIVY, List.of(log4shellFrom(ScannerType.TRIVY, 10.0), other))));

        NormalizationResult result = service.normalize(SCAN_ID, List.of(reportFor(ScannerType.TRIVY)));

        assertThat(result.findings()).hasSize(2);
    }
}
