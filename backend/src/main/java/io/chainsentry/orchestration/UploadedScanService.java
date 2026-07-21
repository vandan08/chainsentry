package io.chainsentry.orchestration;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.normalization.NormalizationResult;
import io.chainsentry.normalization.NormalizationService;
import io.chainsentry.policy.GateEvaluation;
import io.chainsentry.policy.PolicyRules;
import io.chainsentry.policy.ScanGateService;
import io.chainsentry.policy.SuppressionService;
import io.chainsentry.risk.RiskEnrichmentService;
import io.chainsentry.risk.RiskWeights;
import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.event.ScanCompleted;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.ScannerType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;

/**
 * Action-mode ingestion: the GitHub Action runs the engine in the runner
 * (code never leaves CI) and uploads the raw report here for history,
 * risk-ranking and the dashboard. Same normalization → risk → suppression →
 * gate pipeline as a server-side scan — only the engine execution is remote.
 */
@Service
public class UploadedScanService {

    public record UploadCommand(
            String repositoryFullName,
            Long githubRepoId,
            String commitSha,
            String ref,
            Integer prNumber,
            ScannerType engine,
            String engineVersion,
            String reportJson
    ) {
    }

    private static final Logger log = LoggerFactory.getLogger(UploadedScanService.class);

    private final OrganizationRepository organizations;
    private final TrackedRepositoryRepository repositories;
    private final ScanJobRepository scanJobs;
    private final ScannerRunRepository scannerRuns;
    private final NormalizationService normalizationService;
    private final RiskEnrichmentService riskEnrichmentService;
    private final SuppressionService suppressionService;
    private final FindingRepository findings;
    private final ScanGateService scanGateService;
    private final ApplicationEventPublisher events;

    UploadedScanService(OrganizationRepository organizations, TrackedRepositoryRepository repositories,
                        ScanJobRepository scanJobs, ScannerRunRepository scannerRuns,
                        NormalizationService normalizationService, RiskEnrichmentService riskEnrichmentService,
                        SuppressionService suppressionService, FindingRepository findings,
                        ScanGateService scanGateService, ApplicationEventPublisher events) {
        this.organizations = organizations;
        this.repositories = repositories;
        this.scanJobs = scanJobs;
        this.scannerRuns = scannerRuns;
        this.normalizationService = normalizationService;
        this.riskEnrichmentService = riskEnrichmentService;
        this.suppressionService = suppressionService;
        this.findings = findings;
        this.scanGateService = scanGateService;
        this.events = events;
    }

    /** Idempotent per (repository, commit) — re-run workflows return the existing scan. */
    @Transactional
    public ScanJob ingest(UploadCommand upload) {
        TrackedRepository repo = repositories.findByGithubRepoId(upload.githubRepoId())
                .orElseGet(() -> register(upload));
        return scanJobs
                .findByRepositoryIdAndCommitShaAndTrigger(repo.id(), upload.commitSha(), ScanTrigger.ACTION_UPLOAD)
                .orElseGet(() -> process(repo, upload));
    }

    /** Uploads self-register: Action mode needs no App installation, just the workflow. */
    private TrackedRepository register(UploadCommand upload) {
        String ownerLogin = upload.repositoryFullName().split("/", 2)[0];
        Organization org = organizations.findByLogin(ownerLogin)
                .orElseGet(() -> organizations.save(new Organization(ownerLogin, null)));
        return repositories.save(new TrackedRepository(org.id(), upload.githubRepoId(),
                upload.repositoryFullName(), "main"));
    }

    private ScanJob process(TrackedRepository repo, UploadCommand upload) {
        ScanJob job = scanJobs.save(new ScanJob(repo.id(), upload.commitSha(), upload.ref(),
                upload.prNumber(), ScanTrigger.ACTION_UPLOAD));
        job.markRunning();

        String engineVersion = upload.engineVersion() != null ? upload.engineVersion() : "uploaded";
        RawReport report = new RawReport(upload.engine(), engineVersion, upload.reportJson(), Duration.ZERO);
        ScannerRun run = new ScannerRun(job.id(), upload.engine());
        run.complete(engineVersion, report.payload(), Duration.ZERO);
        scannerRuns.save(run);

        NormalizationResult normalized = normalizationService.normalize(job.id(), List.of(report));
        riskEnrichmentService.enrich(normalized.findings(), normalized.vulnerabilityMetadata(),
                weightsFor(repo));
        suppressionService.applyTo(repo.id(), normalized.findings());
        findings.saveAll(normalized.findings());

        // Uploads carry no workspace, so no repo chainsentry.yml — platform defaults gate them.
        GateEvaluation gate = scanGateService.evaluate(job.id(), PolicyRules.defaults());
        job.complete(gate.status());
        scanJobs.save(job);
        log.info("Uploaded scan {} ingested for {}: {} findings, gate {}", job.id(),
                repo.fullName(), normalized.findings().size(), gate.status());
        events.publishEvent(new ScanCompleted(job.id(), repo.id(), job.commitSha(),
                job.prNumber(), job.trigger(), gate.status(), true));
        return job;
    }

    private RiskWeights weightsFor(TrackedRepository repo) {
        return organizations.findById(repo.organizationId())
                .map(Organization::effectiveRiskWeights)
                .orElse(RiskWeights.DEFAULT);
    }
}
