package io.chainsentry.dashboard;

import io.chainsentry.dashboard.dto.OrgOverviewResponse;
import io.chainsentry.dashboard.dto.TrendPointResponse;
import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.policy.ScanGateService;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.GateStatus;
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
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OrgQueryServiceTest {

    @Mock
    private OrganizationRepository organizations;
    @Mock
    private TrackedRepositoryRepository repositories;
    @Mock
    private ScanJobRepository scanJobs;
    @Mock
    private FindingRepository findings;
    @Mock
    private ScanGateService scanGateService;

    private OrgQueryService service() {
        return new OrgQueryService(organizations, repositories, scanJobs, findings, scanGateService);
    }

    private Finding finding(UUID scanId, String cve, Severity severity, double risk) {
        Finding f = new Finding(scanId, "fp-" + cve, FindingType.SCA, severity, cve);
        f.describePackage(cve, "pkg:maven/x/" + cve.toLowerCase() + "@1", "1", "2",
                DependencyScope.DIRECT_RUNTIME);
        f.applyRiskScore(BigDecimal.valueOf(risk));
        return f;
    }

    @Test
    void overviewAggregatesLatestCompletedScansAndCountsKev() {
        Organization org = new Organization("acme", 1L);
        TrackedRepository scanned = new TrackedRepository(org.id(), 1L, "acme/payment-service", "main");
        TrackedRepository fresh = new TrackedRepository(org.id(), 2L, "acme/new-repo", "main");
        when(organizations.findById(org.id())).thenReturn(Optional.of(org));
        when(repositories.findByOrganizationIdOrderByFullName(org.id()))
                .thenReturn(List.of(fresh, scanned));

        ScanJob completed = new ScanJob(scanned.id(), "abc1234", "main", null, ScanTrigger.PUSH);
        completed.markRunning();
        completed.complete(GateStatus.FAIL);
        when(scanJobs.findByRepositoryIdOrderByCreatedAtDesc(scanned.id()))
                .thenReturn(List.of(completed));
        when(scanJobs.findByRepositoryIdOrderByCreatedAtDesc(fresh.id())).thenReturn(List.of());

        Finding kevCritical = finding(completed.id(), "CVE-2021-44228", Severity.CRITICAL, 0.96);
        Finding medium = finding(completed.id(), "CVE-2023-2976", Severity.MEDIUM, 0.21);
        Finding suppressed = finding(completed.id(), "CVE-2020-36518", Severity.HIGH, 0.5);
        suppressed.suppress();
        when(findings.findByScanJobIdOrderByRiskScoreDesc(completed.id()))
                .thenReturn(List.of(kevCritical, suppressed, medium));

        Vulnerability kev = new Vulnerability("CVE-2021-44228", BigDecimal.TEN, null, null);
        kev.markInKev(LocalDate.of(2021, 12, 10), Instant.now());
        lenient().when(scanGateService.vulnerabilityIndex(anyList())).thenReturn(Map.of(
                "CVE-2021-44228", kev,
                "CVE-2023-2976", new Vulnerability("CVE-2023-2976", BigDecimal.valueOf(5.5), null, null)));

        OrgOverviewResponse overview = service().overview(org.id());

        assertThat(overview.login()).isEqualTo("acme");
        assertThat(overview.repositoryCount()).isEqualTo(2);
        assertThat(overview.openFindings()).isEqualTo(2);   // suppressed excluded
        assertThat(overview.openCriticals()).isEqualTo(1);
        assertThat(overview.kevFindings()).isEqualTo(1);

        OrgOverviewResponse.RepositoryOverview neverScanned = overview.repositories().stream()
                .filter(r -> r.fullName().equals("acme/new-repo")).findFirst().orElseThrow();
        assertThat(neverScanned.latestScanId()).isNull();
        assertThat(neverScanned.openFindings()).isZero();
    }

    @Test
    void trendIsOldestFirstAndOnlyCompletedScans() {
        TrackedRepository repo = new TrackedRepository(UUID.randomUUID(), 1L, "acme/payment-service", "main");
        when(repositories.findById(repo.id())).thenReturn(Optional.of(repo));

        ScanJob older = new ScanJob(repo.id(), "aaa1111", "main", null, ScanTrigger.PUSH);
        older.complete(GateStatus.PASS);
        ScanJob newer = new ScanJob(repo.id(), "bbb2222", "main", null, ScanTrigger.MANUAL);
        newer.complete(GateStatus.FAIL);
        ScanJob broken = new ScanJob(repo.id(), "ccc3333", "main", null, ScanTrigger.PR);
        broken.fail();
        // repository returns newest-first; the chart wants oldest-first
        when(scanJobs.findByRepositoryIdOrderByCreatedAtDesc(repo.id()))
                .thenReturn(List.of(broken, newer, older));
        when(findings.findByScanJobIdOrderByRiskScoreDesc(older.id())).thenReturn(List.of());
        when(findings.findByScanJobIdOrderByRiskScoreDesc(newer.id()))
                .thenReturn(List.of(finding(newer.id(), "CVE-2021-44228", Severity.CRITICAL, 0.96)));

        List<TrendPointResponse> trend = service().trend(repo.id());

        assertThat(trend).hasSize(2); // FAILED scan is not a data point
        assertThat(trend.get(0).commitSha()).isEqualTo("aaa1111");
        assertThat(trend.get(1).commitSha()).isEqualTo("bbb2222");
        assertThat(trend.get(1).criticals()).isEqualTo(1);
        assertThat(trend.get(1).gate()).isEqualTo(GateStatus.FAIL);
    }

    @Test
    void unknownOrgIs404() {
        UUID nowhere = UUID.randomUUID();
        when(organizations.findById(nowhere)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service().overview(nowhere))
                .isInstanceOf(OrganizationNotFoundException.class);
    }
}
