package io.chainsentry.orchestration;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.risk.RiskEnrichmentService;
import io.chainsentry.risk.RiskScoreCalculator;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import io.chainsentry.risk.feed.VulnerabilityFeedsUpdated;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A CVE that lands in KEV overnight must re-rank yesterday's findings —
 * without a re-scan, and through the org's weight overrides.
 */
@ExtendWith(MockitoExtension.class)
class FindingReRankServiceTest {

    @Mock
    private FindingRepository findings;
    @Mock
    private ScanJobRepository scanJobs;
    @Mock
    private TrackedRepositoryRepository repositories;
    @Mock
    private OrganizationRepository organizations;
    @Mock
    private VulnerabilityRepository vulnerabilities;

    private FindingReRankService service() {
        return new FindingReRankService(findings, scanJobs, repositories, organizations,
                new RiskEnrichmentService(vulnerabilities, new RiskScoreCalculator()));
    }

    @Test
    void kevArrivalLiftsThePersistedRiskScore() {
        Organization org = new Organization("acme", 1L);
        TrackedRepository repo = new TrackedRepository(org.id(), 2L, "acme/payment-service", "main");
        ScanJob job = new ScanJob(repo.id(), "abc1234", "main", null, ScanTrigger.PUSH);

        Finding finding = new Finding(job.id(), "fp", FindingType.SCA, Severity.CRITICAL, "Log4Shell");
        finding.describePackage("CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "2.14.1", "2.15.0", DependencyScope.TRANSITIVE_RUNTIME);
        finding.applyRiskScore(new BigDecimal("0.7103")); // pre-KEV score

        Vulnerability vuln = new Vulnerability("CVE-2021-44228", BigDecimal.valueOf(10.0), null, null);
        vuln.updateEpss(new BigDecimal("0.97580"), Instant.now());
        vuln.markInKev(LocalDate.now(), Instant.now()); // the overnight change

        when(findings.findByVulnerabilityIdIn(Set.of("CVE-2021-44228"))).thenReturn(List.of(finding));
        when(scanJobs.findAllById(any())).thenReturn(List.of(job));
        when(repositories.findAllById(anyCollection())).thenReturn(List.of(repo));
        when(organizations.findAllById(anyCollection())).thenReturn(List.of(org));
        when(vulnerabilities.findById("CVE-2021-44228")).thenReturn(Optional.of(vuln));

        service().onFeedsUpdated(new VulnerabilityFeedsUpdated(Set.of("CVE-2021-44228")));

        // 0.25·1 + 0.40·0.9758 + 0.25·1 + 0.10·0.7 = 0.9603 (KEV term now firing)
        assertThat(finding.riskScore()).isEqualByComparingTo(new BigDecimal("0.9603"));
        verify(findings).saveAll(List.of(finding));
    }

    @Test
    void noAffectedFindingsMeansNoWrites() {
        when(findings.findByVulnerabilityIdIn(Set.of("CVE-2099-0001"))).thenReturn(List.of());

        service().onFeedsUpdated(new VulnerabilityFeedsUpdated(Set.of("CVE-2099-0001")));

        verify(findings, never()).saveAll(any());
    }
}
