package io.chainsentry.orchestration;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.normalization.NormalizationResult;
import io.chainsentry.normalization.NormalizationService;
import io.chainsentry.orchestration.UploadedScanService.UploadCommand;
import io.chainsentry.policy.GateEvaluation;
import io.chainsentry.policy.ScanGateService;
import io.chainsentry.policy.SuppressionService;
import io.chainsentry.risk.RiskEnrichmentService;
import io.chainsentry.shared.event.ScanCompleted;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UploadedScanServiceTest {

    @Mock
    private OrganizationRepository organizations;
    @Mock
    private TrackedRepositoryRepository repositories;
    @Mock
    private ScanJobRepository scanJobs;
    @Mock
    private ScannerRunRepository scannerRuns;
    @Mock
    private NormalizationService normalizationService;
    @Mock
    private RiskEnrichmentService riskEnrichmentService;
    @Mock
    private SuppressionService suppressionService;
    @Mock
    private FindingRepository findings;
    @Mock
    private ScanGateService scanGateService;
    @Mock
    private ApplicationEventPublisher events;

    private UploadedScanService service() {
        return new UploadedScanService(organizations, repositories, scanJobs, scannerRuns,
                normalizationService, riskEnrichmentService, suppressionService, findings,
                scanGateService, events);
    }

    private UploadCommand upload() {
        return new UploadCommand("acme/payment-service", 101L, "e7b4d1f", "main", null,
                ScannerType.TRIVY, "0.63.0", "{\"Results\":[]}");
    }

    @Test
    void firstUploadSelfRegistersAndRunsTheFullPipeline() {
        Organization org = new Organization("acme", null);
        when(repositories.findByGithubRepoId(101L)).thenReturn(Optional.empty());
        when(organizations.findByLogin("acme")).thenReturn(Optional.of(org));
        when(organizations.findById(org.id())).thenReturn(Optional.of(org));
        when(repositories.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(scanJobs.findByRepositoryIdAndCommitShaAndTrigger(any(), eq("e7b4d1f"),
                eq(ScanTrigger.ACTION_UPLOAD))).thenReturn(Optional.empty());
        when(scanJobs.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(scannerRuns.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Finding finding = new Finding(UUID.randomUUID(), "fp", FindingType.SCA, Severity.CRITICAL, "Log4Shell");
        when(normalizationService.normalize(any(), anyList()))
                .thenReturn(new NormalizationResult(List.of(finding), Map.of()));
        when(scanGateService.evaluate(any(), any()))
                .thenReturn(new GateEvaluation(GateStatus.FAIL, List.of()));

        ScanJob job = service().ingest(upload());

        assertThat(job.trigger()).isEqualTo(ScanTrigger.ACTION_UPLOAD);
        assertThat(job.status()).isEqualTo(ScanStatus.COMPLETED);
        assertThat(job.gateResult()).isEqualTo(GateStatus.FAIL);

        verify(riskEnrichmentService).enrich(eq(List.of(finding)), any(), any());
        verify(suppressionService).applyTo(any(), eq(List.of(finding)));
        verify(findings).saveAll(List.of(finding));

        ArgumentCaptor<ScanCompleted> event = ArgumentCaptor.forClass(ScanCompleted.class);
        verify(events).publishEvent(event.capture());
        assertThat(event.getValue().trigger()).isEqualTo(ScanTrigger.ACTION_UPLOAD);
        assertThat(event.getValue().gateStatus()).isEqualTo(GateStatus.FAIL);
    }

    @Test
    void reRunWorkflowsGetTheExistingScanNotASecondIngestion() {
        TrackedRepository repo = new TrackedRepository(UUID.randomUUID(), 101L, "acme/payment-service", "main");
        ScanJob existing = new ScanJob(repo.id(), "e7b4d1f", "main", null, ScanTrigger.ACTION_UPLOAD);
        when(repositories.findByGithubRepoId(101L)).thenReturn(Optional.of(repo));
        when(scanJobs.findByRepositoryIdAndCommitShaAndTrigger(repo.id(), "e7b4d1f",
                ScanTrigger.ACTION_UPLOAD)).thenReturn(Optional.of(existing));

        ScanJob job = service().ingest(upload());

        assertThat(job).isSameAs(existing);
        verifyNoInteractions(normalizationService, findings, events);
    }

    @Test
    void unknownOwnerGetsAnOrganizationWithoutAnInstallation() {
        when(repositories.findByGithubRepoId(101L)).thenReturn(Optional.empty());
        when(organizations.findByLogin("acme")).thenReturn(Optional.empty());
        when(organizations.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(organizations.findById(any())).thenReturn(Optional.empty());
        when(repositories.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(scanJobs.findByRepositoryIdAndCommitShaAndTrigger(any(), any(), any()))
                .thenReturn(Optional.empty());
        when(scanJobs.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(scannerRuns.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(normalizationService.normalize(any(), anyList()))
                .thenReturn(new NormalizationResult(List.of(), Map.of()));
        when(scanGateService.evaluate(any(), any()))
                .thenReturn(new GateEvaluation(GateStatus.PASS, List.of()));

        service().ingest(upload());

        ArgumentCaptor<Organization> org = ArgumentCaptor.forClass(Organization.class);
        verify(organizations).save(org.capture());
        assertThat(org.getValue().login()).isEqualTo("acme");
        assertThat(org.getValue().githubInstallationId()).isNull();
    }
}
