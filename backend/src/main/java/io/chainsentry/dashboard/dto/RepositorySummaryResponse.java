package io.chainsentry.dashboard.dto;

import java.util.UUID;

public record RepositorySummaryResponse(
        UUID id,
        String fullName,
        String defaultBranch,
        UUID organizationId
) {
}
