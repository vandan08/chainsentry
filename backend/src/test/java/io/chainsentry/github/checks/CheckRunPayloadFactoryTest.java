package io.chainsentry.github.checks;

import io.chainsentry.normalization.Finding;
import io.chainsentry.shared.event.ScanCompleted;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class CheckRunPayloadFactoryTest {

    private static final UUID SCAN_ID = UUID.randomUUID();

    private final CheckRunPayloadFactory factory = new CheckRunPayloadFactory(JsonMapper.builder().build());

    private ScanCompleted scan(GateStatus gate, boolean succeeded) {
        return new ScanCompleted(SCAN_ID, UUID.randomUUID(), "e7b4d1f", 42, ScanTrigger.PR, gate, succeeded);
    }

    private Finding log4shell() {
        Finding finding = new Finding(SCAN_ID, "fp", FindingType.SCA, Severity.CRITICAL,
                "Apache Log4j2 JNDI RCE (Log4Shell)");
        finding.describePackage("CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "2.14.1", "2.15.0", DependencyScope.TRANSITIVE_RUNTIME);
        finding.locate("pom.xml", null);
        finding.applyRiskScore(new BigDecimal("0.9603"));
        return finding;
    }

    @Test
    void failedGateBecomesFailureConclusionWithAnnotations() {
        ObjectNode payload = factory.payload(scan(GateStatus.FAIL, true), List.of(log4shell()));

        assertThat(payload.path("name").asText()).isEqualTo("ChainSentry");
        assertThat(payload.path("head_sha").asText()).isEqualTo("e7b4d1f");
        assertThat(payload.path("conclusion").asText()).isEqualTo("failure");
        assertThat(payload.path("external_id").asText()).isEqualTo(SCAN_ID.toString());

        var annotation = payload.path("output").path("annotations").get(0);
        assertThat(annotation.path("path").asText()).isEqualTo("pom.xml");
        assertThat(annotation.path("start_line").asInt()).isEqualTo(1); // SCA findings anchor to line 1
        assertThat(annotation.path("annotation_level").asText()).isEqualTo("failure");
        assertThat(annotation.path("title").asText()).isEqualTo("CVE-2021-44228");
        assertThat(annotation.path("message").asText()).contains("upgrade to 2.15.0");

        assertThat(payload.path("output").path("summary").asText())
                .contains("CVE-2021-44228")
                .contains("0.96");
    }

    @Test
    void passAndWarnMapToSuccessAndNeutral() {
        assertThat(factory.payload(scan(GateStatus.PASS, true), List.of())
                .path("conclusion").asText()).isEqualTo("success");
        assertThat(factory.payload(scan(GateStatus.WARN, true), List.of())
                .path("conclusion").asText()).isEqualTo("neutral");
    }

    @Test
    void brokenScanIsNeutralNeverBlocking() {
        ObjectNode payload = factory.payload(scan(null, false), List.of());

        assertThat(payload.path("conclusion").asText()).isEqualTo("neutral");
        assertThat(payload.path("output").path("title").asText()).contains("Scan failed");
    }

    @Test
    void annotationsRespectGithubsCapOf50() {
        List<Finding> many = IntStream.range(0, 60)
                .mapToObj(i -> {
                    Finding f = new Finding(SCAN_ID, "fp" + i, FindingType.SAST, Severity.MEDIUM, "rule-" + i);
                    f.locate("src/File" + i + ".java", i + 1);
                    return f;
                })
                .toList();

        ObjectNode payload = factory.payload(scan(GateStatus.WARN, true), many);

        assertThat(payload.path("output").path("annotations")).hasSize(50);
    }
}
