package io.chainsentry.github.checks;

import io.chainsentry.normalization.Finding;
import io.chainsentry.shared.event.ScanCompleted;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Builds the Checks API request body for a finished scan: conclusion from
 * the gate verdict, a markdown summary ranked by risk, and per-finding
 * annotations (GitHub caps annotations at 50 per request — the risk ranking
 * decides who makes the cut).
 */
@Component
public class CheckRunPayloadFactory {

    static final String CHECK_NAME = "ChainSentry";
    private static final int MAX_ANNOTATIONS = 50;
    private static final int MAX_SUMMARY_ROWS = 10;

    private final ObjectMapper objectMapper;

    CheckRunPayloadFactory(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** @param findings the scan's findings, already ordered risk-score descending */
    public ObjectNode payload(ScanCompleted scan, List<Finding> findings) {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("name", CHECK_NAME);
        payload.put("head_sha", scan.commitSha());
        payload.put("status", "completed");
        payload.put("conclusion", conclusion(scan));
        payload.put("external_id", scan.scanJobId().toString());

        ObjectNode output = payload.putObject("output");
        output.put("title", title(scan, findings));
        output.put("summary", summary(scan, findings));
        annotations(output.putArray("annotations"), findings);
        return payload;
    }

    private String conclusion(ScanCompleted scan) {
        if (!scan.succeeded()) {
            return "neutral"; // a broken scan must not block the merge on its own
        }
        return switch (scan.gateStatus()) {
            case PASS -> "success";
            case WARN -> "neutral";
            case FAIL -> "failure";
        };
    }

    private String title(ScanCompleted scan, List<Finding> findings) {
        if (!scan.succeeded()) {
            return "Scan failed — no verdict";
        }
        return "Gate " + scan.gateStatus() + " — " + findings.size() + " finding(s)";
    }

    private String summary(ScanCompleted scan, List<Finding> findings) {
        if (!scan.succeeded()) {
            return "The scan did not complete; see the ChainSentry scan "
                    + scan.scanJobId() + " for engine logs.";
        }
        StringBuilder md = new StringBuilder();
        md.append("### Policy gate: ").append(gateEmoji(scan.gateStatus())).append(' ')
                .append(scan.gateStatus()).append("\n\n");
        md.append(severityLine(findings)).append("\n\n");
        if (!findings.isEmpty()) {
            md.append("| Risk | Finding | Package | Fix |\n|---|---|---|---|\n");
            findings.stream().limit(MAX_SUMMARY_ROWS).forEach(f -> md
                    .append("| ").append(String.format("%.2f", f.riskScoreOrZero()))
                    .append(" | ").append(f.vulnerabilityId() != null ? f.vulnerabilityId() : f.title())
                    .append(" | ").append(f.packageCoordinates() != null ? f.packageCoordinates() : orDash(f.filePath()))
                    .append(" | ").append(orDash(f.fixedVersion()))
                    .append(" |\n"));
        }
        return md.toString();
    }

    private String severityLine(List<Finding> findings) {
        if (findings.isEmpty()) {
            return "No findings.";
        }
        Map<Severity, Long> bySeverity = findings.stream()
                .collect(Collectors.groupingBy(Finding::severity, TreeMap::new, Collectors.counting()));
        return bySeverity.entrySet().stream()
                .map(e -> e.getValue() + " " + e.getKey())
                .collect(Collectors.joining(" · "));
    }

    private void annotations(ArrayNode annotations, List<Finding> findings) {
        findings.stream()
                .filter(f -> f.filePath() != null)
                .limit(MAX_ANNOTATIONS)
                .forEach(f -> {
                    ObjectNode a = annotations.addObject();
                    a.put("path", f.filePath());
                    int line = f.line() != null ? f.line() : 1;
                    a.put("start_line", line);
                    a.put("end_line", line);
                    a.put("annotation_level", level(f.severity()));
                    a.put("title", f.vulnerabilityId() != null ? f.vulnerabilityId() : f.title());
                    a.put("message", annotationMessage(f));
                });
    }

    private String annotationMessage(Finding f) {
        StringBuilder message = new StringBuilder();
        if (f.title() != null) {
            message.append(f.title());
        }
        if (f.packageCoordinates() != null) {
            message.append("\nPackage: ").append(f.packageCoordinates());
        }
        message.append(f.fixedVersion() != null
                ? "\nFix: upgrade to " + f.fixedVersion()
                : "\nNo fixed version available yet");
        return message.toString();
    }

    private String level(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "failure";
            case MEDIUM -> "warning";
            case LOW, INFO -> "notice";
        };
    }

    private String gateEmoji(GateStatus status) {
        return switch (status) {
            case PASS -> "✅";
            case WARN -> "⚠️";
            case FAIL -> "❌";
        };
    }

    private String orDash(String value) {
        return value != null ? value : "—";
    }
}
