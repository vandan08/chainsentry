package io.chainsentry.normalization;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps Trivy JSON (schema v2) into unified findings. Dependency scope comes
 * from the per-result {@code Packages[].Relationship} field when the lockfile
 * gives Trivy a dependency graph; packages without one default to
 * DIRECT_RUNTIME — over-alerting beats under-alerting for scope guesses.
 */
@Component
class TrivyReportNormalizer implements ReportNormalizer {

    private final ObjectMapper objectMapper;

    TrivyReportNormalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public ScannerType engine() {
        return ScannerType.TRIVY;
    }

    @Override
    public List<NormalizedFinding> normalize(RawReport report) {
        JsonNode root = parse(report.payload());
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode result : root.path("Results")) {
            String target = result.path("Target").asText(null);
            FindingType type = findingType(result);
            Map<String, DependencyScope> scopeByPkgId = scopeIndex(result.path("Packages"));
            for (JsonNode vuln : result.path("Vulnerabilities")) {
                findings.add(toFinding(vuln, target, type, scopeByPkgId));
            }
        }
        return findings;
    }

    private NormalizedFinding toFinding(JsonNode vuln, String target, FindingType type,
                                        Map<String, DependencyScope> scopeByPkgId) {
        String vulnId = vuln.path("VulnerabilityID").asText(null);
        JsonNode nvd = vuln.path("CVSS").path("nvd");
        double cvss = nvd.path("V3Score").asDouble(0.0);
        return new NormalizedFinding(
                ScannerType.TRIVY,
                vulnId,
                vulnId,
                type,
                severity(vuln.path("Severity").asText("")),
                vuln.path("Title").asText(null),
                vuln.path("Description").asText(null),
                vuln.path("PkgIdentifier").path("PURL").asText(null),
                vuln.path("InstalledVersion").asText(null),
                vuln.path("FixedVersion").asText(null),
                scopeByPkgId.getOrDefault(vuln.path("PkgID").asText(""), DependencyScope.DIRECT_RUNTIME),
                target,
                null,
                cvss > 0 ? cvss : null,
                nvd.path("V3Vector").asText(null)
        );
    }

    private Map<String, DependencyScope> scopeIndex(JsonNode packages) {
        Map<String, DependencyScope> scopes = new HashMap<>();
        for (JsonNode pkg : packages) {
            String id = pkg.path("ID").asText(null);
            if (id == null) {
                continue;
            }
            switch (pkg.path("Relationship").asText("")) {
                case "direct" -> scopes.put(id, DependencyScope.DIRECT_RUNTIME);
                case "indirect" -> scopes.put(id, DependencyScope.TRANSITIVE_RUNTIME);
                default -> { /* unknown relationship: fall back to default */ }
            }
        }
        return scopes;
    }

    private FindingType findingType(JsonNode result) {
        return switch (result.path("Class").asText("")) {
            case "os-pkgs" -> FindingType.CONTAINER;
            case "secret" -> FindingType.SECRET;
            default -> FindingType.SCA;
        };
    }

    private Severity severity(String trivySeverity) {
        return switch (trivySeverity) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MEDIUM" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    private JsonNode parse(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unparseable Trivy report", e);
        }
    }
}
