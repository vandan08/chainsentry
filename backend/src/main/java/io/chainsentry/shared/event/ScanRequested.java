package io.chainsentry.shared.event;

import io.chainsentry.shared.model.ScanTrigger;

import java.util.UUID;

/**
 * A request for a scan, published by ingestion points (GitHub webhooks) and
 * consumed by the orchestrator. Keeps the github module from depending on
 * orchestration — events flow in, {@link ScanCompleted} flows back out.
 */
public record ScanRequested(
        UUID repositoryId,
        String commitSha,
        String ref,
        Integer prNumber,
        ScanTrigger trigger
) {
}
