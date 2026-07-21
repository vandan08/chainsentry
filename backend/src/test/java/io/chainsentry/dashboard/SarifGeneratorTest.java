package io.chainsentry.dashboard;

import io.chainsentry.normalization.Finding;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class SarifGeneratorTest {

    private static final UUID SCAN_ID = UUID.randomUUID();

    private final JsonMapper mapper = JsonMapper.builder().build();
    private final SarifGenerator generator = new SarifGenerator(mapper);

    private Finding log4shell() {
        Finding finding = new Finding(SCAN_ID, "fp", FindingType.SCA, Severity.CRITICAL,
                "Apache Log4j2 JNDI RCE (Log4Shell)");
        finding.describePackage("CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "2.14.1", "2.15.0", DependencyScope.TRANSITIVE_RUNTIME);
        finding.locate("pom.xml", null);
        return finding;
    }

    private Finding sqli() {
        Finding finding = new Finding(SCAN_ID, "fp2", FindingType.SAST, Severity.MEDIUM,
                "formatted-sql-string");
        finding.locate("src/main/java/com/acme/A.java", 57);
        return finding;
    }

    @Test
    void rendersValidSarifWithCvssBackedSecuritySeverity() {
        Vulnerability vuln = new Vulnerability("CVE-2021-44228", BigDecimal.valueOf(10.0), null, null);

        JsonNode sarif = mapper.readTree(generator.sarif(List.of(log4shell()),
                Map.of("CVE-2021-44228", vuln)));

        assertThat(sarif.path("version").asText()).isEqualTo("2.1.0");
        JsonNode run = sarif.path("runs").get(0);
        assertThat(run.path("tool").path("driver").path("name").asText()).isEqualTo("ChainSentry");

        JsonNode rule = run.path("tool").path("driver").path("rules").get(0);
        assertThat(rule.path("id").asText()).isEqualTo("CVE-2021-44228");
        assertThat(rule.path("helpUri").asText()).contains("nvd.nist.gov");
        assertThat(rule.path("properties").path("security-severity").asText()).isEqualTo("10.0");

        JsonNode result = run.path("results").get(0);
        assertThat(result.path("ruleId").asText()).isEqualTo("CVE-2021-44228");
        assertThat(result.path("level").asText()).isEqualTo("error");
        assertThat(result.path("message").path("text").asText())
                .contains("Log4Shell").contains("fixed in 2.15.0");
        JsonNode location = result.path("locations").get(0).path("physicalLocation");
        assertThat(location.path("artifactLocation").path("uri").asText()).isEqualTo("pom.xml");
        assertThat(location.path("region").path("startLine").asInt()).isEqualTo(1);
    }

    @Test
    void sastFindingsUseRuleTitleAndRealLineNumbers() {
        JsonNode sarif = mapper.readTree(generator.sarif(List.of(sqli()), Map.of()));
        JsonNode result = sarif.path("runs").get(0).path("results").get(0);

        assertThat(result.path("ruleId").asText()).isEqualTo("formatted-sql-string");
        assertThat(result.path("level").asText()).isEqualTo("warning");
        assertThat(result.path("locations").get(0).path("physicalLocation")
                .path("region").path("startLine").asInt()).isEqualTo(57);
        // No CVSS record → severity-derived stand-in
        assertThat(sarif.path("runs").get(0).path("tool").path("driver").path("rules").get(0)
                .path("properties").path("security-severity").asText()).isEqualTo("5.0");
    }

    @Test
    void twoFindingsOnTheSameRuleShareOneRuleEntry() {
        Finding second = new Finding(SCAN_ID, "fp3", FindingType.SCA, Severity.CRITICAL, "Log4Shell again");
        second.describePackage("CVE-2021-44228", "pkg:maven/other/shaded-log4j@1.0", "1.0", null,
                DependencyScope.DIRECT_RUNTIME);

        JsonNode sarif = mapper.readTree(generator.sarif(List.of(log4shell(), second), Map.of()));
        JsonNode run = sarif.path("runs").get(0);

        assertThat(run.path("tool").path("driver").path("rules")).hasSize(1);
        assertThat(run.path("results")).hasSize(2);
    }
}
