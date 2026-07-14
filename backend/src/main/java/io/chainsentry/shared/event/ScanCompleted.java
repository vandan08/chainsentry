package io.chainsentry.shared.event;

import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanTrigger;

import java.util.UUID;

/**
 * Published by the orchestrator when a scan finishes (successfully or not).
 * Carries everything downstream consumers (Check Runs, notifications) need,
 * so they never have to reach back into the orchestration module.
 *
 * @param gateStatus the scan-time verdict; null when the scan itself failed
 */
public record ScanCompleted(
        UUID scanJobId,
        UUID repositoryId,
        String commitSha,
        Integer prNumber,
        ScanTrigger trigger,
        GateStatus gateStatus,
        boolean succeeded
) {
}
