package io.chainsentry.dashboard;

import io.chainsentry.normalization.Finding;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Renders a scan's findings as SARIF 2.1.0 for GitHub's code scanning tab.
 * The {@code security-severity} rule property is what GitHub buckets alerts
 * by — real CVSS when the vulnerability record has it, a severity-derived
 * stand-in otherwise.
 */
@Component
class SarifGenerator {

    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

    private final ObjectMapper objectMapper;

    SarifGenerator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    String sarif(List<Finding> findings, Map<String, Vulnerability> vulnerabilitiesById) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("$schema", SCHEMA);
        root.put("version", "2.1.0");
        ObjectNode run = root.putArray("runs").addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "ChainSentry");
        driver.put("informationUri", "https://github.com/chainsentry/chainsentry");
        rules(driver.putArray("rules"), findings, vulnerabilitiesById);
        results(run.putArray("results"), findings);
        return root.toString();
    }

    private void rules(ArrayNode rules, List<Finding> findings, Map<String, Vulnerability> vulnerabilitiesById) {
        Set<String> seen = new LinkedHashSet<>();
        for (Finding finding : findings) {
            String ruleId = ruleId(finding);
            if (!seen.add(ruleId)) {
                continue;
            }
            ObjectNode rule = rules.addObject();
            rule.put("id", ruleId);
            rule.putObject("shortDescription").put("text",
                    finding.title() != null ? finding.title() : ruleId);
            if (finding.vulnerabilityId() != null && finding.vulnerabilityId().startsWith("CVE-")) {
                rule.put("helpUri", "https://nvd.nist.gov/vuln/detail/" + finding.vulnerabilityId());
            }
            Vulnerability vulnerability = finding.vulnerabilityId() != null
                    ? vulnerabilitiesById.get(finding.vulnerabilityId()) : null;
            rule.putObject("properties").put("security-severity", securitySeverity(finding, vulnerability));
        }
    }

    private void results(ArrayNode results, List<Finding> findings) {
        for (Finding finding : findings) {
            ObjectNode result = results.addObject();
            result.put("ruleId", ruleId(finding));
            result.put("level", level(finding.severity()));
            result.putObject("message").put("text", message(finding));
            ObjectNode physical = result.putArray("locations").addObject().putObject("physicalLocation");
            physical.putObject("artifactLocation")
                    .put("uri", finding.filePath() != null ? finding.filePath() : "unknown");
            physical.putObject("region")
                    .put("startLine", finding.line() != null ? finding.line() : 1);
            result.putObject("partialFingerprints").put("chainsentry/fingerprint", finding.fingerprint());
        }
    }

    private String ruleId(Finding finding) {
        return finding.vulnerabilityId() != null ? finding.vulnerabilityId() : finding.title();
    }

    private String message(Finding finding) {
        StringBuilder text = new StringBuilder(finding.title() != null ? finding.title() : ruleId(finding));
        if (finding.packageCoordinates() != null) {
            text.append(" in ").append(finding.packageCoordinates());
        }
        if (finding.fixedVersion() != null) {
            text.append(" — fixed in ").append(finding.fixedVersion());
        }
        return text.toString();
    }

    private String level(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private String securitySeverity(Finding finding, Vulnerability vulnerability) {
        if (vulnerability != null && vulnerability.cvssScore() != null) {
            return vulnerability.cvssScore().toPlainString();
        }
        return switch (finding.severity()) {
            case CRITICAL -> "9.5";
            case HIGH -> "8.0";
            case MEDIUM -> "5.0";
            case LOW -> "3.0";
            case INFO -> "0.0";
        };
    }
}
