package io.chainsentry.remediation;

import io.chainsentry.normalization.Finding;
import io.chainsentry.risk.Vulnerability;
import org.springframework.stereotype.Component;

/**
 * Builds the explanation prompt from what ChainSentry already knows: the
 * unified finding, the feed-synced exploitation data, and the composite risk
 * score. The point is contextual ranking rationale ("why is this at the
 * top"), not a generic CVE encyclopedia entry.
 */
@Component
class ExplanationPromptFactory {

    static final String SYSTEM = """
            You are a senior application security engineer inside ChainSentry, \
            a supply-chain security platform. Explain one vulnerability finding \
            to the developer who has to act on it. Be concrete and calm — no \
            fear-mongering, no filler. Answer in markdown with exactly these \
            sections: **What it is** (2-3 sentences), **Why it ranks here** \
            (tie the CVSS/EPSS/KEV/scope inputs to the composite score), and \
            **What to do** (the specific upgrade or mitigation, one code or \
            manifest change if applicable).""";

    String userPrompt(Finding finding, Vulnerability vulnerability, String repositoryFullName) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Repository: ").append(repositoryFullName).append('\n');
        prompt.append("Finding: ").append(finding.title()).append('\n');
        prompt.append("Type: ").append(finding.type()).append(" · Severity: ")
                .append(finding.severity()).append('\n');
        if (finding.vulnerabilityId() != null) {
            prompt.append("Vulnerability: ").append(finding.vulnerabilityId()).append('\n');
        }
        if (finding.packageCoordinates() != null) {
            prompt.append("Package: ").append(finding.packageCoordinates())
                    .append(" (installed ").append(orUnknown(finding.installedVersion()))
                    .append(", fixed in ").append(orUnknown(finding.fixedVersion())).append(")\n");
        }
        if (finding.dependencyScope() != null) {
            prompt.append("Dependency scope: ").append(finding.dependencyScope()).append('\n');
        }
        if (finding.filePath() != null) {
            prompt.append("Location: ").append(finding.filePath());
            if (finding.line() != null) {
                prompt.append(':').append(finding.line());
            }
            prompt.append('\n');
        }
        prompt.append("Composite risk score: ")
                .append(String.format("%.4f", finding.riskScoreOrZero())).append(" of 1\n");
        if (vulnerability != null) {
            prompt.append("CVSS: ").append(vulnerability.cvssOrZero()).append('\n');
            prompt.append("EPSS (30-day exploitation probability): ")
                    .append(vulnerability.epssOrZero()).append('\n');
            prompt.append("CISA KEV (known exploited): ").append(vulnerability.inKev() ? "YES" : "no");
            if (vulnerability.kevAdded() != null) {
                prompt.append(" (added ").append(vulnerability.kevAdded()).append(')');
            }
            prompt.append('\n');
            if (vulnerability.summary() != null) {
                prompt.append("Advisory summary: ").append(vulnerability.summary()).append('\n');
            }
        }
        return prompt.toString();
    }

    private String orUnknown(String value) {
        return value != null ? value : "unknown";
    }
}
