package io.chainsentry.normalization;

import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.ScannerType;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The dedup point of the pipeline: every engine's raw report is normalized,
 * then findings with the same fingerprint collapse into one {@link Finding}
 * whose {@code sources} list all engines that reported it.
 */
@Service
public class NormalizationService {

    private final Map<ScannerType, ReportNormalizer> normalizers;

    NormalizationService(List<ReportNormalizer> normalizers) {
        this.normalizers = normalizers.stream()
                .collect(Collectors.toMap(ReportNormalizer::engine, Function.identity()));
    }

    public NormalizationResult normalize(UUID scanJobId, List<RawReport> reports) {
        List<NormalizedFinding> all = new ArrayList<>();
        for (RawReport report : reports) {
            ReportNormalizer normalizer = normalizers.get(report.engine());
            if (normalizer == null) {
                throw new IllegalStateException("No normalizer registered for engine " + report.engine());
            }
            all.addAll(normalizer.normalize(report));
        }
        return new NormalizationResult(dedup(scanJobId, all), metadataByVulnerability(all));
    }

    private List<Finding> dedup(UUID scanJobId, List<NormalizedFinding> normalized) {
        Map<String, Finding> byFingerprint = new LinkedHashMap<>();
        for (NormalizedFinding nf : normalized) {
            Finding finding = byFingerprint.computeIfAbsent(nf.fingerprint(), fp -> {
                Finding f = new Finding(scanJobId, fp, nf.type(), nf.severity(), nf.title());
                f.describePackage(nf.vulnerabilityId(), nf.purl(), nf.installedVersion(),
                        nf.fixedVersion(), nf.scope());
                f.locate(nf.filePath(), nf.line());
                return f;
            });
            finding.addSource(new FindingSource(nf.engine(), nf.engineRuleId()));
        }
        return List.copyOf(byFingerprint.values());
    }

    private Map<String, VulnerabilityMetadata> metadataByVulnerability(List<NormalizedFinding> normalized) {
        Map<String, VulnerabilityMetadata> metadata = new LinkedHashMap<>();
        for (NormalizedFinding nf : normalized) {
            if (nf.vulnerabilityId() == null) {
                continue;
            }
            // Prefer the first entry that actually carries a CVSS score.
            metadata.merge(nf.vulnerabilityId(),
                    new VulnerabilityMetadata(nf.vulnerabilityId(), nf.cvssScore(), nf.cvssVector(), nf.summary()),
                    (existing, candidate) -> existing.cvssScore() != null ? existing : candidate);
        }
        return metadata;
    }
}
