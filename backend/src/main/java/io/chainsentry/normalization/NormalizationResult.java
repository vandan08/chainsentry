package io.chainsentry.normalization;

import java.util.List;
import java.util.Map;

/**
 * Output of normalizing one scan's raw reports: deduped findings plus the
 * engine-supplied CVE metadata keyed by vulnerability id.
 */
public record NormalizationResult(
        List<Finding> findings,
        Map<String, VulnerabilityMetadata> vulnerabilityMetadata
) {
}
