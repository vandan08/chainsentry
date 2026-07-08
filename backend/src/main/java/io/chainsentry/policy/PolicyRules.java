package io.chainsentry.policy;

import io.chainsentry.shared.model.Severity;

import java.util.Map;

/**
 * The effective gate policy for a scan — either parsed from the repo's
 * {@code chainsentry.yml} or the platform defaults.
 *
 * @param failOnKev         any finding on a CISA-KEV vulnerability fails the gate
 * @param failRiskThreshold findings at/above this composite risk score fail the gate (null = disabled)
 * @param maxFindings       per-severity budgets; exceeding one fails the gate
 * @param warnRiskThreshold findings at/above this score warn without failing (null = disabled)
 * @param ignoreUnfixed     skip findings that have no fixed version yet ("can't act on it today")
 */
public record PolicyRules(
        boolean failOnKev,
        Double failRiskThreshold,
        Map<Severity, Integer> maxFindings,
        Double warnRiskThreshold,
        boolean ignoreUnfixed
) {

    /**
     * Platform defaults, deliberately opinionated: actively exploited
     * vulnerabilities and criticals block the merge; risky-but-unproven
     * findings warn.
     */
    public static PolicyRules defaults() {
        return new PolicyRules(true, 0.75, Map.of(Severity.CRITICAL, 0), 0.50, false);
    }
}
