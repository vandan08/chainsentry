package io.chainsentry.risk;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.VulnerabilityMetadata;
import io.chainsentry.shared.model.DependencyScope;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;
import java.util.Map;

/**
 * Attaches the composite risk score to freshly normalized findings. CVE data
 * comes from the {@code vulnerability} table (feed-synced EPSS/KEV); CVEs the
 * feeds haven't seen yet get a row created from the engine-supplied metadata
 * so their CVSS still contributes.
 */
@Service
public class RiskEnrichmentService {

    private final VulnerabilityRepository vulnerabilities;
    private final RiskScoreCalculator calculator;

    RiskEnrichmentService(VulnerabilityRepository vulnerabilities, RiskScoreCalculator calculator) {
        this.vulnerabilities = vulnerabilities;
        this.calculator = calculator;
    }

    @Transactional
    public void enrich(List<Finding> findings, Map<String, VulnerabilityMetadata> metadata, RiskWeights weights) {
        for (Finding finding : findings) {
            Vulnerability vuln = resolveVulnerability(finding.vulnerabilityId(), metadata);
            double cvss = vuln != null ? vuln.cvssOrZero() : 0.0;
            double epss = vuln != null ? vuln.epssOrZero() : 0.0;
            boolean kev = vuln != null && vuln.inKev();
            DependencyScope scope = finding.dependencyScope() != null
                    ? finding.dependencyScope()
                    : DependencyScope.DIRECT_RUNTIME;
            double score = calculator.score(cvss, epss, kev, scope, weights);
            finding.applyRiskScore(BigDecimal.valueOf(score).setScale(4, RoundingMode.HALF_UP));
        }
    }

    private Vulnerability resolveVulnerability(String vulnerabilityId, Map<String, VulnerabilityMetadata> metadata) {
        if (vulnerabilityId == null) {
            return null;
        }
        return vulnerabilities.findById(vulnerabilityId)
                .orElseGet(() -> createFromEngineMetadata(vulnerabilityId, metadata.get(vulnerabilityId)));
    }

    private Vulnerability createFromEngineMetadata(String vulnerabilityId, VulnerabilityMetadata meta) {
        BigDecimal cvss = meta != null && meta.cvssScore() != null
                ? BigDecimal.valueOf(meta.cvssScore()).setScale(1, RoundingMode.HALF_UP)
                : null;
        return vulnerabilities.save(new Vulnerability(
                vulnerabilityId,
                cvss,
                meta != null ? meta.cvssVector() : null,
                meta != null ? meta.summary() : null));
    }
}
