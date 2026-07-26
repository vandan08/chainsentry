package io.chainsentry.remediation;

import io.chainsentry.normalization.Finding;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ExplanationPromptFactoryTest {

    private final ExplanationPromptFactory factory = new ExplanationPromptFactory();

    @Test
    void promptCarriesEverythingTheModelNeedsToExplainTheRanking() {
        Finding finding = new Finding(UUID.randomUUID(), "fp", FindingType.SCA, Severity.CRITICAL,
                "Apache Log4j2 JNDI RCE (Log4Shell)");
        finding.describePackage("CVE-2021-44228",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "2.14.1", "2.15.0", DependencyScope.TRANSITIVE_RUNTIME);
        finding.locate("pom.xml", null);
        finding.applyRiskScore(new BigDecimal("0.9603"));

        Vulnerability vuln = new Vulnerability("CVE-2021-44228", BigDecimal.valueOf(10.0), null,
                "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP");
        vuln.updateEpss(new BigDecimal("0.97580"), Instant.now());
        vuln.markInKev(LocalDate.of(2021, 12, 10), Instant.now());

        String prompt = factory.userPrompt(finding, vuln, "acme/payment-service");

        assertThat(prompt)
                .contains("acme/payment-service")
                .contains("CVE-2021-44228")
                .contains("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
                .contains("fixed in 2.15.0")
                .contains("TRANSITIVE_RUNTIME")
                .contains("0.9603")
                .contains("CVSS: 10.0")
                .contains("0.9758")
                .contains("KEV (known exploited): YES")
                .contains("2021-12-10");
    }

    @Test
    void sastFindingsWithoutCveDataStillProduceAUsablePrompt() {
        Finding sast = new Finding(UUID.randomUUID(), "fp2", FindingType.SAST, Severity.HIGH,
                "formatted-sql-string");
        sast.locate("src/main/java/com/acme/A.java", 57);

        String prompt = factory.userPrompt(sast, null, "acme/payment-service");

        assertThat(prompt)
                .contains("formatted-sql-string")
                .contains("src/main/java/com/acme/A.java:57")
                .doesNotContain("CVSS")
                .doesNotContain("Package:");
    }
}
