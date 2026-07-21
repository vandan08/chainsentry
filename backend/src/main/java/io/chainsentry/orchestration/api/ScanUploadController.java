package io.chainsentry.orchestration.api;

import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.UploadedScanService;
import io.chainsentry.orchestration.UploadedScanService.UploadCommand;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScannerType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

import java.net.URI;
import java.util.UUID;

/**
 * Action-mode upload endpoint. Auth note: repo-scoped upload tokens are on
 * the roadmap; until then this endpoint trusts the network boundary (run it
 * private or behind a gateway).
 */
@RestController
@RequestMapping("/api/v1")
class ScanUploadController {

    record UploadScanRequest(
            @NotBlank String repositoryFullName,
            @NotNull Long githubRepoId,
            @NotBlank @Pattern(regexp = "[0-9a-fA-F]{7,40}", message = "commitSha must be a hex SHA")
            String commitSha,
            String ref,
            Integer prNumber,
            @NotNull ScannerType engine,
            String engineVersion,
            @NotNull JsonNode report
    ) {
    }

    record UploadAcceptedResponse(UUID scanId, ScanStatus status, GateStatus gateResult) {
    }

    private final UploadedScanService uploadedScanService;

    ScanUploadController(UploadedScanService uploadedScanService) {
        this.uploadedScanService = uploadedScanService;
    }

    @PostMapping("/scans/upload")
    ResponseEntity<UploadAcceptedResponse> upload(@Valid @RequestBody UploadScanRequest request) {
        ScanJob job = uploadedScanService.ingest(new UploadCommand(
                request.repositoryFullName(), request.githubRepoId(), request.commitSha(),
                request.ref(), request.prNumber(), request.engine(), request.engineVersion(),
                request.report().toString()));
        return ResponseEntity.status(HttpStatus.CREATED)
                .location(URI.create("/api/v1/scans/" + job.id()))
                .body(new UploadAcceptedResponse(job.id(), job.status(), job.gateResult()));
    }
}
