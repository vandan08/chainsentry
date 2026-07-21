package io.chainsentry.dashboard;

import io.chainsentry.dashboard.dto.EngineRunResponse;
import io.chainsentry.dashboard.dto.FindingResponse;
import io.chainsentry.dashboard.dto.RepositorySummaryResponse;
import io.chainsentry.dashboard.dto.ScanSummaryResponse;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.orchestration.ScanNotFoundException;
import io.chainsentry.orchestration.ScannerRunRepository;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.Severity;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.chainsentry.policy.ScanGateService;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/** Read model behind the dashboard and scan-detail endpoints. */
@Service
public class ScanQueryService {

    private final TrackedRepositoryRepository repositories;
    private final ScanJobRepository scanJobs;
    private final ScannerRunRepository scannerRuns;
    private final FindingRepository findings;
    private final ScanGateService scanGateService;

    private final SarifGenerator sarifGenerator;

    ScanQueryService(TrackedRepositoryRepository repositories, ScanJobRepository scanJobs,
                     ScannerRunRepository scannerRuns, FindingRepository findings,
                     ScanGateService scanGateService, SarifGenerator sarifGenerator) {
        this.repositories = repositories;
        this.scanJobs = scanJobs;
        this.scannerRuns = scannerRuns;
        this.findings = findings;
        this.scanGateService = scanGateService;
        this.sarifGenerator = sarifGenerator;
    }

    @Transactional(readOnly = true)
    public List<RepositorySummaryResponse> repositories() {
        return repositories.findAll(Sort.by("fullName")).stream()
                .map(repo -> new RepositorySummaryResponse(
                        repo.id(), repo.fullName(), repo.defaultBranch(), repo.organizationId()))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ScanSummaryResponse> scansForRepository(UUID repositoryId) {
        return scanJobs.findByRepositoryIdOrderByCreatedAtDesc(repositoryId).stream()
                .map(this::toSummary)
                .toList();
    }

    @Transactional(readOnly = true)
    public ScanSummaryResponse scan(UUID scanJobId) {
        ScanJob job = scanJobs.findById(scanJobId)
                .orElseThrow(() -> new ScanNotFoundException(scanJobId));
        return toSummary(job);
    }

    @Transactional(readOnly = true)
    public List<FindingResponse> findings(UUID scanJobId, Double minRiskScore, Severity severity, int limit) {
        requireScan(scanJobId);
        List<Finding> scanFindings = findings.findByScanJobIdOrderByRiskScoreDesc(scanJobId);
        Map<String, Vulnerability> vulnById = scanGateService.vulnerabilityIndex(scanFindings);
        return scanFindings.stream()
                .filter(f -> minRiskScore == null || f.riskScoreOrZero() >= minRiskScore)
                .filter(f -> severity == null || f.severity() == severity)
                .limit(limit)
                .map(f -> FindingResponse.from(f, vulnById.get(f.vulnerabilityId())))
                .toList();
    }

    @Transactional(readOnly = true)
    public String sarif(UUID scanJobId) {
        requireScan(scanJobId);
        List<Finding> scanFindings = findings.findByScanJobIdOrderByRiskScoreDesc(scanJobId);
        return sarifGenerator.sarif(scanFindings, scanGateService.vulnerabilityIndex(scanFindings));
    }

    void requireScan(UUID scanJobId) {
        if (!scanJobs.existsById(scanJobId)) {
            throw new ScanNotFoundException(scanJobId);
        }
    }

    private ScanSummaryResponse toSummary(ScanJob job) {
        List<Finding> scanFindings = findings.findByScanJobIdOrderByRiskScoreDesc(job.id());
        Map<Severity, Long> counts = scanFindings.stream()
                .collect(Collectors.groupingBy(Finding::severity, Collectors.counting()));
        List<EngineRunResponse> engines = scannerRuns.findByScanJobId(job.id()).stream()
                .map(run -> new EngineRunResponse(run.engine(), run.engineVersion(), run.status(), run.durationMs()))
                .toList();
        double topRisk = scanFindings.stream()
                .map(Finding::riskScoreOrZero)
                .max(Comparator.naturalOrder())
                .orElse(0.0);
        return new ScanSummaryResponse(
                job.id(), job.repositoryId(), job.commitSha(), job.ref(), job.prNumber(), job.trigger(),
                job.status(), job.gateResult(), job.createdAt(), job.finishedAt(),
                scanFindings.size(), counts, topRisk, engines);
    }
}
