package io.chainsentry.dashboard.dto;

import io.chainsentry.shared.model.GateStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** The org landing view: security posture across every tracked repository. */
public record OrgOverviewResponse(
        UUID organizationId,
        String login,
        int repositoryCount,
        int openFindings,
        int openCriticals,
        int kevFindings,
        List<RepositoryOverview> repositories
) {

    /** One repo's posture, derived from its latest completed scan. */
    public record RepositoryOverview(
            UUID repositoryId,
            String fullName,
            UUID latestScanId,
            GateStatus latestGate,
            Instant lastScannedAt,
            int openFindings,
            int openCriticals,
            int kevFindings,
            double topRiskScore
    ) {
    }
}
