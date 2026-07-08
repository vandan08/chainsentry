package io.chainsentry.policy;

import io.chainsentry.normalization.Finding;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class GateEvaluatorTest {

    private final GateEvaluator evaluator = new GateEvaluator();
    private final UUID scanId = UUID.randomUUID();

    private Finding finding(String cveId, Severity severity, double riskScore, String fixedVersion) {
        Finding finding = new Finding(scanId, cveId + "-fp", FindingType.SCA, severity, cveId + " title");
        finding.describePackage(cveId, "pkg:maven/acme/lib@1.0", "1.0", fixedVersion,
                DependencyScope.DIRECT_RUNTIME);
        finding.applyRiskScore(BigDecimal.valueOf(riskScore));
        return finding;
    }

    private Vulnerability kevVulnerability(String cveId) {
        Vulnerability vuln = new Vulnerability(cveId, BigDecimal.valueOf(9.8), null, null);
        vuln.markInKev(LocalDate.of(2021, 12, 10), Instant.now());
        return vuln;
    }

    @Test
    void cleanScanPasses() {
        Finding medium = finding("CVE-1", Severity.MEDIUM, 0.21, "2.0");

        GateEvaluation gate = evaluator.evaluate(List.of(medium), Map.of(), PolicyRules.defaults());

        assertThat(gate.status()).isEqualTo(GateStatus.PASS);
        assertThat(gate.rules()).allMatch(GateEvaluation.RuleResult::passed);
    }

    @Test
    void kevFindingFailsTheGateAndNamesTheOffender() {
        Finding log4shell = finding("CVE-2021-44228", Severity.CRITICAL, 0.96, "2.15.0");

        GateEvaluation gate = evaluator.evaluate(List.of(log4shell),
                Map.of("CVE-2021-44228", kevVulnerability("CVE-2021-44228")), PolicyRules.defaults());

        assertThat(gate.status()).isEqualTo(GateStatus.FAIL);
        GateEvaluation.RuleResult kevRule = ruleById(gate, "fail-on-kev");
        assertThat(kevRule.passed()).isFalse();
        assertThat(kevRule.offenders()).anySatisfy(o -> assertThat(o).contains("CVE-2021-44228"));
    }

    @Test
    void criticalBudgetOfZeroFailsOnFirstCritical() {
        Finding critical = finding("CVE-2022-1471", Severity.CRITICAL, 0.38, "2.0");

        GateEvaluation gate = evaluator.evaluate(List.of(critical), Map.of(), PolicyRules.defaults());

        assertThat(gate.status()).isEqualTo(GateStatus.FAIL);
        assertThat(ruleById(gate, "max-critical").passed()).isFalse();
        // Same finding stays under both risk thresholds — only the budget fires.
        assertThat(ruleById(gate, "fail-risk-threshold").passed()).isTrue();
    }

    @Test
    void riskAboveWarnButBelowFailYieldsWarn() {
        Finding risky = finding("CVE-2", Severity.HIGH, 0.60, "3.1");

        GateEvaluation gate = evaluator.evaluate(List.of(risky), Map.of(), PolicyRules.defaults());

        assertThat(gate.status()).isEqualTo(GateStatus.WARN);
        assertThat(ruleById(gate, "warn-risk-threshold").passed()).isFalse();
        assertThat(ruleById(gate, "fail-risk-threshold").passed()).isTrue();
    }

    @Test
    void ignoreUnfixedSkipsFindingsWithoutAFix() {
        Finding unfixedCritical = finding("CVE-3", Severity.CRITICAL, 0.9, null);
        PolicyRules rules = new PolicyRules(true, 0.75, Map.of(Severity.CRITICAL, 0), 0.5, true);

        GateEvaluation gate = evaluator.evaluate(List.of(unfixedCritical), Map.of(), rules);

        assertThat(gate.status()).isEqualTo(GateStatus.PASS);
    }

    @Test
    void everyRuleReportsItsEvaluation() {
        GateEvaluation gate = evaluator.evaluate(List.of(), Map.of(), PolicyRules.defaults());

        assertThat(gate.rules()).extracting(GateEvaluation.RuleResult::rule)
                .containsExactlyInAnyOrder("fail-on-kev", "fail-risk-threshold", "max-critical",
                        "warn-risk-threshold");
    }

    private GateEvaluation.RuleResult ruleById(GateEvaluation gate, String ruleId) {
        return gate.rules().stream().filter(r -> r.rule().equals(ruleId)).findFirst().orElseThrow();
    }
}
