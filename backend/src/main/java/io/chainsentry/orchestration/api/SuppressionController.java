package io.chainsentry.orchestration.api;

import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.FindingNotFoundException;
import io.chainsentry.orchestration.RepositoryNotFoundException;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.policy.SuppressionJustification;
import io.chainsentry.policy.SuppressionService;
import io.chainsentry.policy.SuppressionService.SuppressionResult;
import io.chainsentry.shared.model.FindingStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.UUID;

/**
 * Suppression + VEX endpoints. Lives in the orchestration API because the
 * finding → scan → repository walk crosses modules the policy module must
 * not depend on.
 */
@RestController
@RequestMapping("/api/v1")
class SuppressionController {

    record SuppressRequest(
            @NotNull SuppressionJustification justification,
            @NotBlank String rationale,
            @NotBlank String approvedBy,
            @NotNull LocalDate expiresOn
    ) {
    }

    record SuppressionResponse(UUID suppressionId, UUID vexStatementId, FindingStatus findingStatus,
                               LocalDate expiresOn) {
    }

    private final FindingRepository findings;
    private final ScanJobRepository scanJobs;
    private final TrackedRepositoryRepository repositories;
    private final SuppressionService suppressionService;

    SuppressionController(FindingRepository findings, ScanJobRepository scanJobs,
                          TrackedRepositoryRepository repositories, SuppressionService suppressionService) {
        this.findings = findings;
        this.scanJobs = scanJobs;
        this.repositories = repositories;
        this.suppressionService = suppressionService;
    }

    @PostMapping("/findings/{findingId}/suppress")
    ResponseEntity<SuppressionResponse> suppress(@PathVariable UUID findingId,
                                                 @Valid @RequestBody SuppressRequest request) {
        Finding finding = findings.findById(findingId)
                .orElseThrow(() -> new FindingNotFoundException(findingId));
        ScanJob job = scanJobs.findById(finding.scanJobId()).orElseThrow();
        SuppressionResult result = suppressionService.suppress(job.repositoryId(), finding,
                request.justification(), request.rationale(), request.approvedBy(), request.expiresOn());
        return ResponseEntity.status(HttpStatus.CREATED).body(new SuppressionResponse(
                result.suppression().id(), result.vexStatement().id(),
                finding.status(), result.suppression().expiresOn()));
    }

    @GetMapping("/repos/{repositoryId}/vex")
    ResponseEntity<String> aggregateVex(@PathVariable UUID repositoryId) {
        if (repositories.findById(repositoryId).isEmpty()) {
            throw new RepositoryNotFoundException(repositoryId);
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(suppressionService.aggregateVex(repositoryId));
    }
}
