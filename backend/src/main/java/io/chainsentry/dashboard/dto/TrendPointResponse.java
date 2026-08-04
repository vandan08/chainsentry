package io.chainsentry.dashboard.dto;

import io.chainsentry.shared.model.GateStatus;

import java.time.Instant;
import java.util.UUID;

/** One completed scan as a point on the findings-over-time chart. */
public record TrendPointResponse(
        UUID scanId,
        String commitSha,
        Instant scannedAt,
        GateStatus gate,
        int totalFindings,
        int criticals,
        int highs,
        double topRiskScore
) {
}
