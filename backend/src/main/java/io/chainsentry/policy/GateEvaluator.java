package io.chainsentry.policy;

import io.chainsentry.normalization.Finding;
import io.chainsentry.policy.GateEvaluation.RuleResult;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.FindingStatus;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Evaluates policy rules against a scan's findings. Pure function of its
 * inputs — the same evaluation runs server-side and (in spirit) in the
 * GitHub Action's local gate.
 */
@Component
public class GateEvaluator {

    private static final int MAX_OFFENDERS = 5;

    public GateEvaluation evaluate(List<Finding> findings, Map<String, Vulnerability> vulnerabilitiesById,
                                   PolicyRules rules) {
        List<Finding> considered = findings.stream()
                .filter(f -> f.status() == FindingStatus.OPEN)
                .filter(f -> !rules.ignoreUnfixed() || f.fixedVersion() != null)
                .toList();

        List<RuleResult> results = new ArrayList<>();
        if (rules.failOnKev()) {
            results.add(kevRule(considered, vulnerabilitiesById));
        }
        if (rules.failRiskThreshold() != null) {
            results.add(riskRule("fail-risk-threshold", GateStatus.FAIL, rules.failRiskThreshold(), considered));
        }
        rules.maxFindings().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(budget -> results.add(severityBudgetRule(budget.getKey(), budget.getValue(), considered)));
        if (rules.warnRiskThreshold() != null) {
            results.add(riskRule("warn-risk-threshold", GateStatus.WARN, rules.warnRiskThreshold(), considered));
        }
        return new GateEvaluation(overall(results), List.copyOf(results));
    }

    private RuleResult kevRule(List<Finding> considered, Map<String, Vulnerability> vulnerabilitiesById) {
        List<Finding> kevFindings = considered.stream()
                .filter(f -> {
                    Vulnerability vuln = f.vulnerabilityId() != null
                            ? vulnerabilitiesById.get(f.vulnerabilityId()) : null;
                    return vuln != null && vuln.inKev();
                })
                .toList();
        return new RuleResult("fail-on-kev", GateStatus.FAIL, kevFindings.isEmpty(),
                kevFindings.isEmpty()
                        ? "No findings on actively exploited (CISA KEV) vulnerabilities"
                        : kevFindings.size() + " finding(s) on actively exploited (CISA KEV) vulnerabilities",
                offenders(kevFindings));
    }

    private RuleResult riskRule(String ruleId, GateStatus level, double threshold, List<Finding> considered) {
        List<Finding> above = considered.stream()
                .filter(f -> f.riskScoreOrZero() >= threshold)
                .toList();
        return new RuleResult(ruleId, level, above.isEmpty(),
                above.isEmpty()
                        ? "No findings with risk score ≥ " + threshold
                        : above.size() + " finding(s) with risk score ≥ " + threshold,
                offenders(above));
    }

    private RuleResult severityBudgetRule(Severity severity, int max, List<Finding> considered) {
        List<Finding> atSeverity = considered.stream()
                .filter(f -> f.severity() == severity)
                .toList();
        boolean passed = atSeverity.size() <= max;
        return new RuleResult("max-" + severity.name().toLowerCase(), GateStatus.FAIL, passed,
                atSeverity.size() + " " + severity.name() + " finding(s), budget is " + max,
                passed ? List.of() : offenders(atSeverity));
    }

    private List<String> offenders(List<Finding> findings) {
        return findings.stream()
                .sorted(Comparator.comparingDouble(Finding::riskScoreOrZero).reversed())
                .limit(MAX_OFFENDERS)
                .map(f -> {
                    String vuln = f.vulnerabilityId() != null ? f.vulnerabilityId() : f.title();
                    String pkg = f.packageCoordinates() != null
                            ? " · " + f.packageCoordinates()
                            : (f.filePath() != null ? " · " + f.filePath() : "");
                    return vuln + pkg;
                })
                .toList();
    }

    private GateStatus overall(List<RuleResult> results) {
        boolean failed = results.stream().anyMatch(r -> !r.passed() && r.level() == GateStatus.FAIL);
        if (failed) {
            return GateStatus.FAIL;
        }
        boolean warned = results.stream().anyMatch(r -> !r.passed() && r.level() == GateStatus.WARN);
        return warned ? GateStatus.WARN : GateStatus.PASS;
    }
}
