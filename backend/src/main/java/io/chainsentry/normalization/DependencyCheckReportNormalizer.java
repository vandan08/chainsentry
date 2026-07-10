package io.chainsentry.normalization;

import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps OWASP Dependency-Check JSON reports into unified SCA findings. The
 * purl (from the dependency's package identifiers) is what lets these
 * findings collapse with Trivy's on the same CVE. Dependency-Check has no
 * dependency-graph view, so scope stays null and the gap-fill during dedup
 * lets Trivy's relationship data win.
 */
@Component
class DependencyCheckReportNormalizer implements ReportNormalizer {

    private static final String MOUNT_PREFIX = "/src/";

    private final ObjectMapper objectMapper;

    DependencyCheckReportNormalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public ScannerType engine() {
        return ScannerType.DEPENDENCY_CHECK;
    }

    @Override
    public List<NormalizedFinding> normalize(RawReport report) {
        JsonNode root = parse(report.payload());
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode dependency : root.path("dependencies")) {
            String purl = purl(dependency);
            String filePath = filePath(dependency);
            String installedVersion = versionFromPurl(purl);
            for (JsonNode vuln : dependency.path("vulnerabilities")) {
                findings.add(toFinding(vuln, purl, installedVersion, filePath));
            }
        }
        return findings;
    }

    private NormalizedFinding toFinding(JsonNode vuln, String purl, String installedVersion, String filePath) {
        String vulnId = vuln.path("name").asText(null);
        return new NormalizedFinding(
                ScannerType.DEPENDENCY_CHECK,
                vulnId,
                vulnId,
                FindingType.SCA,
                severity(vuln.path("severity").asText("")),
                vulnId,
                vuln.path("description").asText(null),
                purl,
                installedVersion,
                fixedVersion(vuln),
                null,                       // no dependency graph — dedup gap-fill supplies scope
                filePath,
                null,
                cvss(vuln),
                null
        );
    }

    private String purl(JsonNode dependency) {
        for (JsonNode pkg : dependency.path("packages")) {
            String id = pkg.path("id").asText(null);
            if (id != null && id.startsWith("pkg:")) {
                return id;
            }
        }
        return null;
    }

    private String versionFromPurl(String purl) {
        if (purl == null) {
            return null;
        }
        int at = purl.lastIndexOf('@');
        return at >= 0 ? purl.substring(at + 1) : null;
    }

    private String filePath(JsonNode dependency) {
        String path = dependency.path("filePath").asText(null);
        if (path == null) {
            return dependency.path("fileName").asText(null);
        }
        return path.startsWith(MOUNT_PREFIX) ? path.substring(MOUNT_PREFIX.length()) : path;
    }

    /** The NVD range's {@code versionEndExcluding} is the closest thing DC has to a fix version. */
    private String fixedVersion(JsonNode vuln) {
        for (JsonNode entry : vuln.path("vulnerableSoftware")) {
            String endExcluding = entry.path("software").path("versionEndExcluding").asText(null);
            if (endExcluding != null) {
                return endExcluding;
            }
        }
        return null;
    }

    private Double cvss(JsonNode vuln) {
        JsonNode baseScore = vuln.path("cvssv3").path("baseScore");
        return baseScore.isNumber() ? baseScore.asDouble() : null;
    }

    private Severity severity(String dcSeverity) {
        return switch (dcSeverity.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MEDIUM", "MODERATE" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    private JsonNode parse(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unparseable Dependency-Check report", e);
        }
    }
}
