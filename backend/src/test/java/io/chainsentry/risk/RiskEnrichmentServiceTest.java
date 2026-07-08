package io.chainsentry.risk;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.VulnerabilityMetadata;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RiskEnrichmentServiceTest {

    @Mock
    private VulnerabilityRepository vulnerabilities;

    private RiskEnrichmentService service() {
        return new RiskEnrichmentService(vulnerabilities, new RiskScoreCalculator());
    }

    private Finding log4shellFinding() {
        Finding finding = new Finding(UUID.randomUUID(), "fp", FindingType.SCA, Severity.CRITICAL, "Log4Shell");
        finding.describePackage("CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "2.14.1", "2.15.0", DependencyScope.TRANSITIVE_RUNTIME);
        return finding;
    }

    @Test
    void scoresFromFeedSyncedVulnerabilityData() {
        Vulnerability log4shell = new Vulnerability("CVE-2021-44228", BigDecimal.valueOf(10.0), null, null);
        log4shell.updateEpss(new BigDecimal("0.97580"), Instant.now());
        log4shell.markInKev(LocalDate.of(2021, 12, 10), Instant.now());
        when(vulnerabilities.findById("CVE-2021-44228")).thenReturn(Optional.of(log4shell));

        Finding finding = log4shellFinding();
        service().enrich(List.of(finding), Map.of(), RiskWeights.DEFAULT);

        // 0.25·(10/10) + 0.40·0.9758 + 0.25·1 + 0.10·0.7 = 0.96032 → 0.9603
        assertThat(finding.riskScore()).isEqualByComparingTo(new BigDecimal("0.9603"));
    }

    @Test
    void unknownCveGetsARowFromEngineMetadata() {
        when(vulnerabilities.findById("CVE-2021-44228")).thenReturn(Optional.empty());
        when(vulnerabilities.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        Finding finding = log4shellFinding();
        service().enrich(List.of(finding),
                Map.of("CVE-2021-44228", new VulnerabilityMetadata("CVE-2021-44228", 10.0, null, "JNDI RCE")),
                RiskWeights.DEFAULT);

        ArgumentCaptor<Vulnerability> saved = ArgumentCaptor.forClass(Vulnerability.class);
        verify(vulnerabilities).save(saved.capture());
        assertThat(saved.getValue().id()).isEqualTo("CVE-2021-44228");
        assertThat(saved.getValue().cvssOrZero()).isEqualTo(10.0);
        // No EPSS/KEV yet: 0.25·1 + 0 + 0 + 0.10·0.7 = 0.32
        assertThat(finding.riskScore()).isEqualByComparingTo(new BigDecimal("0.3200"));
    }

    @Test
    void findingWithoutVulnerabilityIdStillGetsScopeOnlyScore() {
        Finding sastFinding = new Finding(UUID.randomUUID(), "fp2", FindingType.SAST, Severity.HIGH, "SQLi");

        service().enrich(List.of(sastFinding), Map.of(), RiskWeights.DEFAULT);

        // No CVE data at all: only the scope term contributes (defaults to DIRECT_RUNTIME).
        assertThat(sastFinding.riskScore()).isEqualByComparingTo(new BigDecimal("0.1000"));
    }
}
