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
 * Maps Semgrep JSON output into unified SAST findings. Semgrep results carry
 * no package identity, so findings are keyed by rule + location. Paths are
 * reported relative to the container mount ({@code /src/...}) and stripped
 * back to workspace-relative form here.
 */
@Component
class SemgrepReportNormalizer implements ReportNormalizer {

    private static final String MOUNT_PREFIX = "/src/";

    private final ObjectMapper objectMapper;

    SemgrepReportNormalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public ScannerType engine() {
        return ScannerType.SEMGREP;
    }

    @Override
    public List<NormalizedFinding> normalize(RawReport report) {
        JsonNode root = parse(report.payload());
        List<NormalizedFinding> findings = new ArrayList<>();
        for (JsonNode result : root.path("results")) {
            findings.add(toFinding(result));
        }
        return findings;
    }

    private NormalizedFinding toFinding(JsonNode result) {
        String checkId = result.path("check_id").asText(null);
        JsonNode extra = result.path("extra");
        return new NormalizedFinding(
                ScannerType.SEMGREP,
                checkId,
                null,                       // SAST findings have no CVE identity
                FindingType.SAST,
                severity(extra.path("severity").asText("")),
                title(checkId),
                extra.path("message").asText(null),
                null,
                null,
                null,
                null,                       // dependency scope is meaningless for SAST
                stripMount(result.path("path").asText(null)),
                result.path("start").path("line").isNumber() ? result.path("start").path("line").asInt() : null,
                null,
                null
        );
    }

    /** Last segment of the registry check id: {@code java.lang.security.audit.x.y} → {@code y}. */
    private String title(String checkId) {
        if (checkId == null) {
            return null;
        }
        int lastDot = checkId.lastIndexOf('.');
        return lastDot >= 0 ? checkId.substring(lastDot + 1) : checkId;
    }

    private String stripMount(String path) {
        if (path == null) {
            return null;
        }
        return path.startsWith(MOUNT_PREFIX) ? path.substring(MOUNT_PREFIX.length()) : path;
    }

    private Severity severity(String semgrepSeverity) {
        return switch (semgrepSeverity) {
            case "ERROR" -> Severity.HIGH;
            case "WARNING" -> Severity.MEDIUM;
            default -> Severity.INFO;
        };
    }

    private JsonNode parse(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unparseable Semgrep report", e);
        }
    }
}
