package io.chainsentry.dashboard.dto;

import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.Severity;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ScanSummaryResponse(
        UUID id,
        UUID repositoryId,
        String commitSha,
        String ref,
        Integer prNumber,
        ScanTrigger trigger,
        ScanStatus status,
        GateStatus gateResult,
        Instant createdAt,
        Instant finishedAt,
        int totalFindings,
        Map<Severity, Long> findingsBySeverity,
        double topRiskScore,
        List<EngineRunResponse> engines
) {
}
