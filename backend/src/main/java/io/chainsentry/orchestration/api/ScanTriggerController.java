package io.chainsentry.orchestration.api;

import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanOrchestrator;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScanTrigger;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.UUID;

/** Write side of the scan API: request a scan, get a job handle back. */
@RestController
@RequestMapping("/api/v1")
class ScanTriggerController {

    record TriggerScanRequest(
            @NotBlank @Pattern(regexp = "[0-9a-fA-F]{7,40}", message = "commitSha must be a hex SHA")
            String commitSha,
            String ref,
            Integer prNumber,
            ScanTrigger trigger
    ) {
    }

    record ScanAcceptedResponse(UUID scanId, ScanStatus status) {
    }

    private final ScanOrchestrator orchestrator;

    ScanTriggerController(ScanOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @PostMapping("/repos/{repositoryId}/scans")
    ResponseEntity<ScanAcceptedResponse> triggerScan(@PathVariable UUID repositoryId,
                                                     @Valid @RequestBody TriggerScanRequest request) {
        ScanTrigger trigger = request.trigger() != null ? request.trigger() : ScanTrigger.MANUAL;
        ScanJob job = orchestrator.requestScan(
                repositoryId, request.commitSha(), request.ref(), request.prNumber(), trigger);
        return ResponseEntity.accepted()
                .location(URI.create("/api/v1/scans/" + job.id()))
                .body(new ScanAcceptedResponse(job.id(), job.status()));
    }
}
