package io.chainsentry.remediation.api;

import io.chainsentry.remediation.FindingExplanationService;
import io.chainsentry.remediation.FindingExplanationService.Explanation;
import io.chainsentry.remediation.RemediationDisabledException;
import io.chainsentry.remediation.UpgradePrService;
import io.chainsentry.remediation.UpgradePrService.DraftedPr;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/** AI remediation endpoints: contextual explanation and draft upgrade PRs. */
@RestController
@RequestMapping("/api/v1")
class RemediationController {

    private final FindingExplanationService explanationService;
    private final UpgradePrService upgradePrService;

    RemediationController(FindingExplanationService explanationService,
                          UpgradePrService upgradePrService) {
        this.explanationService = explanationService;
        this.upgradePrService = upgradePrService;
    }

    @PostMapping("/findings/{findingId}/explain")
    Explanation explain(@PathVariable UUID findingId) {
        return explanationService.explain(findingId);
    }

    @PostMapping("/findings/{findingId}/fix-pr")
    ResponseEntity<DraftedPr> draftFixPr(@PathVariable UUID findingId) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(upgradePrService.draftUpgrade(findingId));
    }

    @ExceptionHandler(RemediationDisabledException.class)
    ProblemDetail remediationDisabled(RemediationDisabledException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, e.getMessage());
    }
}
