package io.chainsentry.normalization;

import io.chainsentry.TestFixtures;
import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Golden-file test: the recorded Trivy report must normalize into exactly these findings. */
class TrivyReportNormalizerTest {

    private final TrivyReportNormalizer normalizer = new TrivyReportNormalizer(JsonMapper.builder().build());

    private RawReport report(String resource) {
        return new RawReport(ScannerType.TRIVY, "test", TestFixtures.read(resource), Duration.ZERO);
    }

    @Test
    void normalizesHeadReportIntoFiveFindings() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/trivy-report-head.json"));

        assertThat(findings).hasSize(5);
        assertThat(findings).extracting(NormalizedFinding::vulnerabilityId)
                .containsExactlyInAnyOrder("CVE-2021-44228", "CVE-2021-45046", "CVE-2022-1471",
                        "CVE-2020-36518", "CVE-2023-2976");
    }

    @Test
    void mapsLog4ShellFieldsCompletely() {
        NormalizedFinding log4shell = normalizer.normalize(report("demo/trivy-report-head.json")).stream()
                .filter(f -> "CVE-2021-44228".equals(f.vulnerabilityId()))
                .findFirst()
                .orElseThrow();

        assertThat(log4shell.engine()).isEqualTo(ScannerType.TRIVY);
        assertThat(log4shell.type()).isEqualTo(FindingType.SCA);
        assertThat(log4shell.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(log4shell.purl()).isEqualTo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        assertThat(log4shell.installedVersion()).isEqualTo("2.14.1");
        assertThat(log4shell.fixedVersion()).startsWith("2.15.0");
        assertThat(log4shell.filePath()).isEqualTo("pom.xml");
        assertThat(log4shell.cvssScore()).isEqualTo(10.0);
        assertThat(log4shell.title()).contains("Log4Shell");
    }

    @Test
    void derivesDependencyScopeFromPackageRelationship() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/trivy-report-head.json"));

        NormalizedFinding transitive = byVulnId(findings, "CVE-2021-44228"); // log4j via audit-logging-starter
        NormalizedFinding direct = byVulnId(findings, "CVE-2020-36518");     // jackson-databind, declared in pom

        assertThat(transitive.scope()).isEqualTo(DependencyScope.TRANSITIVE_RUNTIME);
        assertThat(direct.scope()).isEqualTo(DependencyScope.DIRECT_RUNTIME);
    }

    @Test
    void baseReportHasNoCriticals() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/trivy-report-base.json"));

        assertThat(findings).hasSize(2);
        assertThat(findings).noneMatch(f -> f.severity() == Severity.CRITICAL);
    }

    @Test
    void rejectsGarbagePayload() {
        RawReport garbage = new RawReport(ScannerType.TRIVY, "test", "not json {", Duration.ZERO);

        assertThatThrownBy(() -> normalizer.normalize(garbage))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private NormalizedFinding byVulnId(List<NormalizedFinding> findings, String vulnId) {
        return findings.stream().filter(f -> vulnId.equals(f.vulnerabilityId())).findFirst().orElseThrow();
    }
}
