package io.chainsentry.policy;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingStatus;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.json.JsonMapper;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SuppressionServiceTest {

    private static final UUID REPO_ID = UUID.randomUUID();
    private static final String LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

    @Mock
    private SuppressionRepository suppressions;
    @Mock
    private VexStatementRepository vexStatements;
    @Mock
    private FindingRepository findings;

    private SuppressionService service() {
        return new SuppressionService(suppressions, vexStatements, findings,
                new OpenVexGenerator(JsonMapper.builder().build()));
    }

    private Finding log4shellFinding() {
        Finding finding = new Finding(UUID.randomUUID(), "fp", FindingType.SCA, Severity.CRITICAL, "Log4Shell");
        finding.describePackage("CVE-2021-44228", LOG4J_PURL, "2.14.1", "2.15.0",
                DependencyScope.TRANSITIVE_RUNTIME);
        return finding;
    }

    @Test
    void suppressMarksTheFindingAndIssuesAVexStatement() {
        when(suppressions.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(vexStatements.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Finding finding = log4shellFinding();

        SuppressionService.SuppressionResult result = service().suppress(REPO_ID, finding,
                SuppressionJustification.NOT_AFFECTED, "JNDI lookups disabled by JVM flag",
                "security-team", LocalDate.now().plusDays(90));

        assertThat(finding.status()).isEqualTo(FindingStatus.SUPPRESSED);
        assertThat(result.suppression().vulnerabilityId()).isEqualTo("CVE-2021-44228");
        assertThat(result.suppression().packagePurl()).isEqualTo(LOG4J_PURL);
        assertThat(result.vexStatement().openvexDocument())
                .contains("\"status\":\"not_affected\"")
                .contains("CVE-2021-44228");
    }

    @Test
    void refusesPastExpiryDates() {
        assertThatThrownBy(() -> service().suppress(REPO_ID, log4shellFinding(),
                SuppressionJustification.ACCEPTED_RISK, "why", "who", LocalDate.now()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("time-boxed");
    }

    @Test
    void refusesSastFindingsWithoutAVulnerabilityId() {
        Finding sast = new Finding(UUID.randomUUID(), "fp", FindingType.SAST, Severity.HIGH, "SQLi");

        assertThatThrownBy(() -> service().suppress(REPO_ID, sast,
                SuppressionJustification.FALSE_POSITIVE, "why", "who", LocalDate.now().plusDays(30)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void scanTimeApplicationSuppressesMatchingFindingsOnly() {
        Suppression active = new Suppression(REPO_ID, "CVE-2021-44228", LOG4J_PURL,
                SuppressionJustification.MITIGATED, "why", "who", LocalDate.now().plusDays(30));
        when(suppressions.findByRepositoryIdAndExpiresOnAfter(eq(REPO_ID), any()))
                .thenReturn(List.of(active));

        Finding suppressed = log4shellFinding();
        Finding untouched = new Finding(UUID.randomUUID(), "fp2", FindingType.SCA, Severity.HIGH, "Other");
        untouched.describePackage("CVE-2020-36518", "pkg:maven/x/y@1", "1", "2", DependencyScope.DIRECT_RUNTIME);

        service().applyTo(REPO_ID, List.of(suppressed, untouched));

        assertThat(suppressed.status()).isEqualTo(FindingStatus.SUPPRESSED);
        assertThat(untouched.status()).isEqualTo(FindingStatus.OPEN);
    }

    @Test
    void repoWideSuppressionWithoutPurlMatchesAnyPackage() {
        Suppression repoWide = new Suppression(REPO_ID, "CVE-2021-44228", null,
                SuppressionJustification.ACCEPTED_RISK, "why", "who", LocalDate.now().plusDays(30));

        assertThat(repoWide.matches("CVE-2021-44228", LOG4J_PURL)).isTrue();
        assertThat(repoWide.matches("CVE-2021-44228", "pkg:maven/other/artifact@1")).isTrue();
        assertThat(repoWide.matches("CVE-2022-1471", LOG4J_PURL)).isFalse();
    }

    @Test
    void expiryIsExclusiveOnTheExpiryDay() {
        Suppression suppression = new Suppression(REPO_ID, "CVE-1", null,
                SuppressionJustification.ACCEPTED_RISK, "why", "who", LocalDate.of(2026, 8, 1));

        assertThat(suppression.activeOn(LocalDate.of(2026, 7, 31))).isTrue();
        assertThat(suppression.activeOn(LocalDate.of(2026, 8, 1))).isFalse();
    }
}
