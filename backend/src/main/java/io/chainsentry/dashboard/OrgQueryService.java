package io.chainsentry.dashboard;

import io.chainsentry.dashboard.dto.OrgOverviewResponse;
import io.chainsentry.dashboard.dto.OrgOverviewResponse.RepositoryOverview;
import io.chainsentry.dashboard.dto.TrendPointResponse;
import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.RepositoryNotFoundException;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.policy.ScanGateService;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.FindingStatus;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Read model behind the org overview and the trend chart. Posture is always
 * derived from each repository's <em>latest completed</em> scan — an old red
 * scan doesn't haunt a repo that has since gone green.
 */
@Service
public class OrgQueryService {

    private final OrganizationRepository organizations;
    private final TrackedRepositoryRepository repositories;
    private final ScanJobRepository scanJobs;
    private final FindingRepository findings;
    private final ScanGateService scanGateService;

    OrgQueryService(OrganizationRepository organizations, TrackedRepositoryRepository repositories,
                    ScanJobRepository scanJobs, FindingRepository findings,
                    ScanGateService scanGateService) {
        this.organizations = organizations;
        this.repositories = repositories;
        this.scanJobs = scanJobs;
        this.findings = findings;
        this.scanGateService = scanGateService;
    }

    @Transactional(readOnly = true)
    public OrgOverviewResponse overview(UUID organizationId) {
        Organization org = organizations.findById(organizationId)
                .orElseThrow(() -> new OrganizationNotFoundException(organizationId));
        List<RepositoryOverview> repos = repositories
                .findByOrganizationIdOrderByFullName(organizationId).stream()
                .map(this::repositoryOverview)
                .toList();
        return new OrgOverviewResponse(
                org.id(), org.login(), repos.size(),
                repos.stream().mapToInt(RepositoryOverview::openFindings).sum(),
                repos.stream().mapToInt(RepositoryOverview::openCriticals).sum(),
                repos.stream().mapToInt(RepositoryOverview::kevFindings).sum(),
                repos);
    }

    @Transactional(readOnly = true)
    public List<TrendPointResponse> trend(UUID repositoryId) {
        if (repositories.findById(repositoryId).isEmpty()) {
            throw new RepositoryNotFoundException(repositoryId);
        }
        // The query returns newest-first; the chart wants oldest → newest. Reverse
        // rather than re-sort by createdAt, which ties when scans share a timestamp.
        List<ScanJob> completed = new ArrayList<>(scanJobs
                .findByRepositoryIdOrderByCreatedAtDesc(repositoryId).stream()
                .filter(job -> job.status() == ScanStatus.COMPLETED)
                .toList());
        Collections.reverse(completed);
        return completed.stream().map(this::trendPoint).toList();
    }

    private RepositoryOverview repositoryOverview(TrackedRepository repo) {
        Optional<ScanJob> latest = scanJobs.findByRepositoryIdOrderByCreatedAtDesc(repo.id()).stream()
                .filter(job -> job.status() == ScanStatus.COMPLETED)
                .findFirst();
        if (latest.isEmpty()) {
            return new RepositoryOverview(repo.id(), repo.fullName(), null, null, null, 0, 0, 0, 0.0);
        }
        ScanJob scan = latest.get();
        List<Finding> open = openFindings(scan.id());
        return new RepositoryOverview(repo.id(), repo.fullName(), scan.id(), scan.gateResult(),
                scan.finishedAt(), open.size(), countBySeverity(open, Severity.CRITICAL),
                kevCount(open), topRisk(open));
    }

    private TrendPointResponse trendPoint(ScanJob scan) {
        List<Finding> open = openFindings(scan.id());
        return new TrendPointResponse(scan.id(), scan.commitSha(), scan.finishedAt(),
                scan.gateResult(), open.size(), countBySeverity(open, Severity.CRITICAL),
                countBySeverity(open, Severity.HIGH), topRisk(open));
    }

    private List<Finding> openFindings(UUID scanJobId) {
        return findings.findByScanJobIdOrderByRiskScoreDesc(scanJobId).stream()
                .filter(f -> f.status() == FindingStatus.OPEN)
                .toList();
    }

    private int countBySeverity(List<Finding> open, Severity severity) {
        return (int) open.stream().filter(f -> f.severity() == severity).count();
    }

    private int kevCount(List<Finding> open) {
        Map<String, Vulnerability> vulnById = scanGateService.vulnerabilityIndex(open);
        return (int) open.stream()
                .filter(f -> f.vulnerabilityId() != null)
                .map(f -> vulnById.get(f.vulnerabilityId()))
                .filter(vuln -> vuln != null && vuln.inKev())
                .count();
    }

    private double topRisk(List<Finding> open) {
        return open.stream().mapToDouble(Finding::riskScoreOrZero).max().orElse(0.0);
    }
}
