package io.chainsentry.normalization;

import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;

/**
 * One engine-reported issue mapped into the unified shape, before
 * cross-engine dedup. CVSS data is carried along so the risk module can
 * create {@code vulnerability} rows for CVEs the feeds haven't synced yet.
 */
public record NormalizedFinding(
        ScannerType engine,
        String engineRuleId,
        String vulnerabilityId,
        FindingType type,
        Severity severity,
        String title,
        String summary,
        String purl,
        String installedVersion,
        String fixedVersion,
        DependencyScope scope,
        String filePath,
        Integer line,
        Double cvssScore,
        String cvssVector
) {

    /** Dedup identity: same vulnerability on the same artifact at the same location. */
    public String fingerprint() {
        return FindingFingerprint.of(vulnerabilityId, purl, filePath);
    }
}
