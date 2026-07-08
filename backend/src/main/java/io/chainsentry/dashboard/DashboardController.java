package io.chainsentry.dashboard;

import io.chainsentry.dashboard.dto.FindingResponse;
import io.chainsentry.dashboard.dto.RepositorySummaryResponse;
import io.chainsentry.dashboard.dto.ScanSummaryResponse;
import io.chainsentry.policy.GateEvaluation;
import io.chainsentry.policy.PolicyRules;
import io.chainsentry.policy.ScanGateService;
import io.chainsentry.shared.model.Severity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** Read side of the API: repositories, scans, risk-ranked findings, gate detail. */
@RestController
@RequestMapping("/api/v1")
class DashboardController {

    private final ScanQueryService queryService;
    private final ScanGateService gateService;

    DashboardController(ScanQueryService queryService, ScanGateService gateService) {
        this.queryService = queryService;
        this.gateService = gateService;
    }

    @GetMapping("/repos")
    List<RepositorySummaryResponse> repositories() {
        return queryService.repositories();
    }

    @GetMapping("/repos/{repositoryId}/scans")
    List<ScanSummaryResponse> scansForRepository(@PathVariable UUID repositoryId) {
        return queryService.scansForRepository(repositoryId);
    }

    @GetMapping("/scans/{scanId}")
    ScanSummaryResponse scan(@PathVariable UUID scanId) {
        return queryService.scan(scanId);
    }

    @GetMapping("/scans/{scanId}/findings")
    List<FindingResponse> findings(@PathVariable UUID scanId,
                                   @RequestParam(required = false) Double minRiskScore,
                                   @RequestParam(required = false) Severity severity,
                                   @RequestParam(defaultValue = "100") int limit) {
        return queryService.findings(scanId, minRiskScore, severity, limit);
    }

    @GetMapping("/scans/{scanId}/gate")
    GateEvaluation gate(@PathVariable UUID scanId) {
        queryService.requireScan(scanId);
        return gateService.evaluate(scanId, PolicyRules.defaults());
    }
}
