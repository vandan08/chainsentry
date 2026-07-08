package io.chainsentry.policy;

import io.chainsentry.shared.model.GateStatus;

import java.util.List;

/**
 * Full gate verdict: the overall status plus one entry per evaluated rule so
 * a developer can see exactly which rule fired and on which findings.
 */
public record GateEvaluation(GateStatus status, List<RuleResult> rules) {

    /**
     * @param rule      stable rule id, e.g. {@code fail-on-kev}
     * @param level     what a breach of this rule means (FAIL or WARN)
     * @param passed    whether the rule held
     * @param message   human-readable outcome ("2 findings on KEV-listed CVEs")
     * @param offenders up to five worst offending findings, "CVE · package@version"
     */
    public record RuleResult(
            String rule,
            GateStatus level,
            boolean passed,
            String message,
            List<String> offenders
    ) {
    }
}
