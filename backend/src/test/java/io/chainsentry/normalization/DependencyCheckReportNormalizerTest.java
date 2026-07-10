package io.chainsentry.normalization;

import io.chainsentry.TestFixtures;
import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Golden-file test: the recorded Dependency-Check report must normalize into exactly these findings. */
class DependencyCheckReportNormalizerTest {

    private final DependencyCheckReportNormalizer normalizer =
            new DependencyCheckReportNormalizer(JsonMapper.builder().build());

    private RawReport report(String resource) {
        return new RawReport(ScannerType.DEPENDENCY_CHECK, "test", TestFixtures.read(resource), Duration.ZERO);
    }

    @Test
    void normalizesHeadReportIntoFourScaFindings() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/dependency-check-report-head.json"));

        assertThat(findings).hasSize(4);
        assertThat(findings).allMatch(f -> f.type() == FindingType.SCA);
        assertThat(findings).extracting(NormalizedFinding::vulnerabilityId)
                .containsExactlyInAnyOrder("CVE-2021-44228", "CVE-2021-45046", "CVE-2022-1471", "CVE-2023-2976");
    }

    @Test
    void mapsLog4ShellFieldsCompletely() {
        NormalizedFinding log4shell = normalizer.normalize(report("demo/dependency-check-report-head.json")).stream()
                .filter(f -> "CVE-2021-44228".equals(f.vulnerabilityId()))
                .findFirst()
                .orElseThrow();

        assertThat(log4shell.engine()).isEqualTo(ScannerType.DEPENDENCY_CHECK);
        assertThat(log4shell.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(log4shell.purl()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        assertThat(log4shell.installedVersion()).isEqualTo("2.14.1");
        assertThat(log4shell.fixedVersion()).isEqualTo("2.15.0"); // NVD versionEndExcluding
        assertThat(log4shell.cvssScore()).isEqualTo(10.0);
        assertThat(log4shell.scope()).as("DC has no dependency graph").isNull();
        assertThat(log4shell.filePath())
                .as("container mount prefix must be stripped")
                .isEqualTo("target/dependency/log4j-core-2.14.1.jar");
    }

    @Test
    void fingerprintMatchesTrivysForTheSameCveDespiteDifferentPaths() {
        // Trivy reports Log4Shell against pom.xml, DC against the resolved jar —
        // the package-keyed fingerprint must collapse them anyway.
        NormalizedFinding fromDc = normalizer.normalize(report("demo/dependency-check-report-head.json")).stream()
                .filter(f -> "CVE-2021-44228".equals(f.vulnerabilityId()))
                .findFirst()
                .orElseThrow();

        assertThat(fromDc.fingerprint()).isEqualTo(FindingFingerprint.forPackage(
                "CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"));
    }

    @Test
    void baseReportHasOnlyTheGuavaFinding() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/dependency-check-report-base.json"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().vulnerabilityId()).isEqualTo("CVE-2023-2976");
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void rejectsGarbagePayload() {
        RawReport garbage = new RawReport(ScannerType.DEPENDENCY_CHECK, "test", "not json {", Duration.ZERO);

        assertThatThrownBy(() -> normalizer.normalize(garbage))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
