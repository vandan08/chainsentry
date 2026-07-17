package io.chainsentry.orchestration;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.normalization.NormalizationResult;
import io.chainsentry.normalization.NormalizationService;
import io.chainsentry.policy.EffectivePolicyService;
import io.chainsentry.policy.GateEvaluation;
import io.chainsentry.policy.PolicyRules;
import io.chainsentry.policy.ScanGateService;
import io.chainsentry.policy.SuppressionService;
import io.chainsentry.risk.RiskEnrichmentService;
import io.chainsentry.risk.RiskWeights;
import io.chainsentry.sbom.SbomService;
import io.chainsentry.scanner.RawReport;
import io.chainsentry.scanner.ScanContext;
import io.chainsentry.scanner.ScannerEngine;
import io.chainsentry.scanner.SbomGenerator;
import io.chainsentry.shared.config.ChainSentryProperties;
import io.chainsentry.shared.event.ScanCompleted;
import io.chainsentry.shared.event.ScanRequested;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.ScannerType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Drives one scan end to end:
 * workspace → engine fan-out (one virtual thread each) → normalization/dedup
 * → risk enrichment → persistence → SBOM → policy gate.
 *
 * <p>Each stage persists through its own repository call — a crash mid-scan
 * leaves a RUNNING job that a future reaper can time out, never a
 * half-written finding set presented as complete.
 */
@Service
public class ScanOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrator.class);

    private final ScanJobRepository scanJobs;
    private final ScannerRunRepository scannerRuns;
    private final TrackedRepositoryRepository repositories;
    private final OrganizationRepository organizations;
    private final List<ScannerEngine> engines;
    private final SbomGenerator sbomGenerator;
    private final WorkspaceProvider workspaceProvider;
    private final NormalizationService normalizationService;
    private final RiskEnrichmentService riskEnrichmentService;
    private final FindingRepository findings;
    private final SbomService sbomService;
    private final EffectivePolicyService effectivePolicyService;
    private final ScanGateService scanGateService;
    private final SuppressionService suppressionService;
    private final ChainSentryProperties properties;
    private final ApplicationEventPublisher events;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public ScanOrchestrator(ScanJobRepository scanJobs, ScannerRunRepository scannerRuns,
                            TrackedRepositoryRepository repositories, OrganizationRepository organizations,
                            List<ScannerEngine> engines, SbomGenerator sbomGenerator,
                            WorkspaceProvider workspaceProvider, NormalizationService normalizationService,
                            RiskEnrichmentService riskEnrichmentService, FindingRepository findings,
                            SbomService sbomService, EffectivePolicyService effectivePolicyService,
                            ScanGateService scanGateService, SuppressionService suppressionService,
                            ChainSentryProperties properties, ApplicationEventPublisher events) {
        this.scanJobs = scanJobs;
        this.scannerRuns = scannerRuns;
        this.repositories = repositories;
        this.organizations = organizations;
        this.engines = engines;
        this.sbomGenerator = sbomGenerator;
        this.workspaceProvider = workspaceProvider;
        this.normalizationService = normalizationService;
        this.riskEnrichmentService = riskEnrichmentService;
        this.findings = findings;
        this.sbomService = sbomService;
        this.effectivePolicyService = effectivePolicyService;
        this.scanGateService = scanGateService;
        this.suppressionService = suppressionService;
        this.properties = properties;
        this.events = events;
    }

    /** Ingestion points (GitHub webhooks) request scans via event, not direct dependency. */
    @EventListener
    public void onScanRequested(ScanRequested request) {
        requestScan(request.repositoryId(), request.commitSha(), request.ref(),
                request.prNumber(), request.trigger());
    }

    /**
     * Creates the job and schedules the pipeline on a virtual thread.
     * Idempotent per (repository, commit, trigger) — redeliveries return the
     * existing job instead of scanning twice.
     */
    public ScanJob requestScan(UUID repositoryId, String commitSha, String ref, Integer prNumber,
                               ScanTrigger trigger) {
        TrackedRepository repository = repositories.findById(repositoryId)
                .orElseThrow(() -> new RepositoryNotFoundException(repositoryId));
        return scanJobs.findByRepositoryIdAndCommitShaAndTrigger(repositoryId, commitSha, trigger)
                .orElseGet(() -> {
                    ScanJob job = scanJobs.save(new ScanJob(repository.id(), commitSha, ref, prNumber, trigger));
                    executor.submit(() -> runPipeline(job.id()));
                    return job;
                });
    }

    /** Synchronous variant used by the demo seeder and tests. */
    public void runPipeline(UUID scanJobId) {
        ScanJob job = scanJobs.findById(scanJobId).orElseThrow();
        TrackedRepository repository = repositories.findById(job.repositoryId()).orElseThrow();
        job.markRunning();
        scanJobs.save(job);

        Path workspace = null;
        try {
            workspace = workspaceProvider.prepare(repository.cloneUrl(), job.ref());
            ScanContext context = ScanContext.forWorkspace(
                    job.id(), job.commitSha(), workspace, properties.scanner().defaultTimeout());

            List<RawReport> reports = fanOut(context);
            if (reports.isEmpty()) {
                throw new IllegalStateException("Every scanner engine failed");
            }

            NormalizationResult normalized = normalizationService.normalize(job.id(), reports);
            riskEnrichmentService.enrich(normalized.findings(), normalized.vulnerabilityMetadata(),
                    riskWeightsFor(repository));
            suppressionService.applyTo(repository.id(), normalized.findings());
            findings.saveAll(normalized.findings());

            generateSbom(context);

            PolicyRules policy = effectivePolicyService.forWorkspace(workspace);
            GateEvaluation gate = scanGateService.evaluate(job.id(), policy);
            job.complete(gate.status());
            scanJobs.save(job);
            log.info("Scan {} completed: {} findings, gate {}", job.id(),
                    normalized.findings().size(), gate.status());
            events.publishEvent(new ScanCompleted(job.id(), job.repositoryId(), job.commitSha(),
                    job.prNumber(), job.trigger(), gate.status(), true));
        } catch (Exception e) {
            log.error("Scan {} failed", job.id(), e);
            job.fail();
            scanJobs.save(job);
            events.publishEvent(new ScanCompleted(job.id(), job.repositoryId(), job.commitSha(),
                    job.prNumber(), job.trigger(), null, false));
        } finally {
            if (workspace != null) {
                workspaceProvider.cleanup(workspace);
            }
        }
    }

    /** Every applicable engine on its own virtual thread; one engine failing doesn't kill the scan. */
    private List<RawReport> fanOut(ScanContext context) {
        List<ScannerEngine> applicable = engines.stream()
                .filter(engine -> engine.supports(context))
                .toList();
        List<Future<RawReport>> futures = applicable.stream()
                .map(engine -> executor.submit(() -> runEngine(engine, context)))
                .toList();
        List<RawReport> reports = new ArrayList<>();
        for (int i = 0; i < futures.size(); i++) {
            ScannerType engineType = applicable.get(i).type();
            try {
                reports.add(futures.get(i).get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("Interrupted waiting on {}", engineType);
            } catch (Exception e) {
                log.warn("Engine {} failed for scan {}", engineType, context.scanJobId(), e);
            }
        }
        return reports;
    }

    private RawReport runEngine(ScannerEngine engine, ScanContext context) throws Exception {
        ScannerRun run = scannerRuns.save(new ScannerRun(context.scanJobId(), engine.type()));
        Instant start = Instant.now();
        try {
            RawReport report = engine.scan(context);
            run.complete(report.engineVersion(), report.payload(), report.executionTime());
            scannerRuns.save(run);
            return report;
        } catch (Exception e) {
            run.fail(Duration.between(start, Instant.now()));
            scannerRuns.save(run);
            throw e;
        }
    }

    private void generateSbom(ScanContext context) {
        try {
            sbomService.store(context.scanJobId(), sbomGenerator.generate(context));
        } catch (Exception e) {
            // A scan without an SBOM is degraded, not failed — findings still stand.
            log.warn("SBOM generation failed for scan {}", context.scanJobId(), e);
        }
    }

    private RiskWeights riskWeightsFor(TrackedRepository repository) {
        return organizations.findById(repository.organizationId())
                .map(Organization::effectiveRiskWeights)
                .orElse(RiskWeights.DEFAULT);
    }
}
