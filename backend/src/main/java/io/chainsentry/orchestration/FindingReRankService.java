package io.chainsentry.orchestration;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.risk.RiskEnrichmentService;
import io.chainsentry.risk.RiskWeights;
import io.chainsentry.risk.feed.VulnerabilityFeedsUpdated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Re-ranks persisted findings when the EPSS/KEV feeds move — the scan-time
 * verdict ({@code scan_job.gate_result}) stays frozen, but the live risk
 * scores follow today's exploitation data. Lives in orchestration because
 * mapping a finding back to its org's weight overrides needs the
 * scan-job → repository → organization chain.
 */
@Service
public class FindingReRankService {

    private static final Logger log = LoggerFactory.getLogger(FindingReRankService.class);

    private final FindingRepository findings;
    private final ScanJobRepository scanJobs;
    private final TrackedRepositoryRepository repositories;
    private final OrganizationRepository organizations;
    private final RiskEnrichmentService riskEnrichmentService;

    FindingReRankService(FindingRepository findings, ScanJobRepository scanJobs,
                         TrackedRepositoryRepository repositories, OrganizationRepository organizations,
                         RiskEnrichmentService riskEnrichmentService) {
        this.findings = findings;
        this.scanJobs = scanJobs;
        this.repositories = repositories;
        this.organizations = organizations;
        this.riskEnrichmentService = riskEnrichmentService;
    }

    @EventListener
    @Transactional
    public void onFeedsUpdated(VulnerabilityFeedsUpdated event) {
        List<Finding> affected = findings.findByVulnerabilityIdIn(event.vulnerabilityIds());
        if (affected.isEmpty()) {
            return;
        }
        Map<UUID, List<Finding>> byScanJob = affected.stream()
                .collect(Collectors.groupingBy(Finding::scanJobId));
        Map<UUID, RiskWeights> weightsByScanJob = weightsFor(byScanJob.keySet());
        byScanJob.forEach((scanJobId, scanFindings) -> riskEnrichmentService.enrich(
                scanFindings, Map.of(), weightsByScanJob.getOrDefault(scanJobId, RiskWeights.DEFAULT)));
        findings.saveAll(affected);
        log.info("Feed update re-ranked {} findings across {} scans", affected.size(), byScanJob.size());
    }

    private Map<UUID, RiskWeights> weightsFor(Iterable<UUID> scanJobIds) {
        List<ScanJob> jobs = scanJobs.findAllById(scanJobIds);
        Map<UUID, TrackedRepository> reposById = repositories
                .findAllById(jobs.stream().map(ScanJob::repositoryId).distinct().toList()).stream()
                .collect(Collectors.toMap(TrackedRepository::id, Function.identity()));
        Map<UUID, RiskWeights> weightsByOrg = organizations
                .findAllById(reposById.values().stream().map(TrackedRepository::organizationId).distinct().toList())
                .stream()
                .collect(Collectors.toMap(Organization::id, Organization::effectiveRiskWeights));
        return jobs.stream().collect(Collectors.toMap(ScanJob::id, job -> {
            TrackedRepository repo = reposById.get(job.repositoryId());
            return repo != null
                    ? weightsByOrg.getOrDefault(repo.organizationId(), RiskWeights.DEFAULT)
                    : RiskWeights.DEFAULT;
        }));
    }
}
