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

/** Golden-file test: the recorded Semgrep report must normalize into exactly these findings. */
class SemgrepReportNormalizerTest {

    private final SemgrepReportNormalizer normalizer = new SemgrepReportNormalizer(JsonMapper.builder().build());

    private RawReport report(String resource) {
        return new RawReport(ScannerType.SEMGREP, "test", TestFixtures.read(resource), Duration.ZERO);
    }

    @Test
    void normalizesHeadReportIntoTwoSastFindings() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/semgrep-report-head.json"));

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.type() == FindingType.SAST);
        assertThat(findings).allMatch(f -> f.vulnerabilityId() == null, "SAST findings carry no CVE");
    }

    @Test
    void mapsSqlInjectionFindingCompletely() {
        NormalizedFinding sqli = normalizer.normalize(report("demo/semgrep-report-head.json")).stream()
                .filter(f -> f.engineRuleId().contains("formatted-sql-string"))
                .findFirst()
                .orElseThrow();

        assertThat(sqli.engine()).isEqualTo(ScannerType.SEMGREP);
        assertThat(sqli.severity()).isEqualTo(Severity.HIGH); // Semgrep ERROR
        assertThat(sqli.title()).isEqualTo("formatted-sql-string");
        assertThat(sqli.summary()).contains("SQL injection");
        assertThat(sqli.filePath())
                .as("container mount prefix must be stripped")
                .isEqualTo("src/main/java/com/acme/payment/audit/AuditLogRepository.java");
        assertThat(sqli.line()).isEqualTo(57);
        assertThat(sqli.purl()).isNull();
    }

    @Test
    void mapsWarningSeverityToMedium() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/semgrep-report-base.json"));

        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void distinctSastFindingsGetDistinctFingerprints() {
        List<NormalizedFinding> findings = normalizer.normalize(report("demo/semgrep-report-head.json"));

        assertThat(findings.get(0).fingerprint()).isNotEqualTo(findings.get(1).fingerprint());
    }

    @Test
    void rejectsGarbagePayload() {
        RawReport garbage = new RawReport(ScannerType.SEMGREP, "test", "not json {", Duration.ZERO);

        assertThatThrownBy(() -> normalizer.normalize(garbage))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
