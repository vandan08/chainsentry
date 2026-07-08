package io.chainsentry.sbom;

import io.chainsentry.shared.model.Severity;

import java.util.List;
import java.util.UUID;

/**
 * The supply-chain delta between two scans: what a PR is about to merge.
 * Added and version-changed components carry the head scan's findings so a
 * reviewer sees the risk delta, not just the dependency delta.
 */
public record SbomDiff(
        UUID baseScanJobId,
        UUID headScanJobId,
        List<ComponentChange> added,
        List<ComponentChange> removed,
        List<VersionChange> changed
) {

    public record ComponentChange(
            String purl,
            String name,
            String version,
            Boolean direct,
            List<VulnerabilityAnnotation> vulnerabilities
    ) {
    }

    public record VersionChange(
            String name,
            String baseVersion,
            String headVersion,
            String headPurl,
            List<VulnerabilityAnnotation> vulnerabilities
    ) {
    }

    public record VulnerabilityAnnotation(
            String vulnerabilityId,
            Severity severity,
            double riskScore,
            boolean knownExploited
    ) {
    }
}
