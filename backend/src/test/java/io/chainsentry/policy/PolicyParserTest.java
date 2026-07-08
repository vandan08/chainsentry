package io.chainsentry.policy;

import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyParserTest {

    private final PolicyParser parser = new PolicyParser();

    @Test
    void minimalFileGetsPlatformDefaults() {
        PolicyRules rules = parser.parse("version: 1");

        assertThat(rules).isEqualTo(PolicyRules.defaults());
    }

    @Test
    void fullFileOverridesEverything() {
        PolicyRules rules = parser.parse("""
                version: 1
                gate:
                  fail-on-kev: false
                  fail-risk-threshold: 0.9
                  warn-risk-threshold: 0.3
                  max-findings:
                    critical: 2
                    high: 20
                ignore:
                  unfixed: true
                """);

        assertThat(rules.failOnKev()).isFalse();
        assertThat(rules.failRiskThreshold()).isEqualTo(0.9);
        assertThat(rules.warnRiskThreshold()).isEqualTo(0.3);
        assertThat(rules.maxFindings()).isEqualTo(Map.of(Severity.CRITICAL, 2, Severity.HIGH, 20));
        assertThat(rules.ignoreUnfixed()).isTrue();
    }

    @Test
    void explicitFalseDisablesARiskThreshold() {
        PolicyRules rules = parser.parse("""
                gate:
                  fail-risk-threshold: false
                """);

        assertThat(rules.failRiskThreshold()).isNull();
        assertThat(rules.warnRiskThreshold()).isEqualTo(PolicyRules.defaults().warnRiskThreshold());
    }

    @Test
    void rejectsOutOfRangeThreshold() {
        assertThatThrownBy(() -> parser.parse("gate:\n  fail-risk-threshold: 1.5"))
                .isInstanceOf(PolicyValidationException.class)
                .hasMessageContaining("fail-risk-threshold");
    }

    @Test
    void rejectsUnknownSeverityBudget() {
        assertThatThrownBy(() -> parser.parse("gate:\n  max-findings:\n    catastrophic: 0"))
                .isInstanceOf(PolicyValidationException.class);
    }

    @Test
    void rejectsNegativeBudget() {
        assertThatThrownBy(() -> parser.parse("gate:\n  max-findings:\n    critical: -1"))
                .isInstanceOf(PolicyValidationException.class);
    }
}
