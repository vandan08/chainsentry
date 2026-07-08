package io.chainsentry.risk;

import io.chainsentry.shared.model.DependencyScope;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

class RiskScoreCalculatorTest {

    private final RiskScoreCalculator calculator = new RiskScoreCalculator();

    @Test
    void log4shellScoresNearMaximum() {
        // CVE-2021-44228: CVSS 10.0, EPSS ~0.975, in KEV, typical transitive runtime dep
        double risk = calculator.score(10.0, 0.975, true, DependencyScope.TRANSITIVE_RUNTIME);

        assertThat(risk).isCloseTo(0.25 + 0.40 * 0.975 + 0.25 + 0.10 * 0.7, within(1e-9));
        assertThat(risk).isGreaterThan(0.9);
    }

    @Test
    void kevMembershipOutranksHigherCvssWithoutExploitation() {
        // "Critical on paper" — CVSS 9.8 but essentially never exploited, test-only dep
        double paperCritical = calculator.score(9.8, 0.01, false, DependencyScope.TRANSITIVE_TEST);
        // "Actually dangerous" — lower CVSS but actively exploited in a runtime dep
        double activelyExploited = calculator.score(7.5, 0.60, true, DependencyScope.DIRECT_RUNTIME);

        assertThat(activelyExploited)
                .as("actively exploited HIGH must outrank never-exploited paper CRITICAL")
                .isGreaterThan(paperCritical);
    }

    @Test
    void testScopedDependencyScoresLowerThanRuntime() {
        double runtime = calculator.score(7.0, 0.2, false, DependencyScope.DIRECT_RUNTIME);
        double testOnly = calculator.score(7.0, 0.2, false, DependencyScope.TRANSITIVE_TEST);

        assertThat(testOnly).isLessThan(runtime);
    }

    @Test
    void scoreStaysWithinUnitInterval() {
        assertThat(calculator.score(10.0, 1.0, true, DependencyScope.DIRECT_RUNTIME))
                .isLessThanOrEqualTo(1.0);
        assertThat(calculator.score(0.0, 0.0, false, DependencyScope.TRANSITIVE_TEST))
                .isGreaterThanOrEqualTo(0.0);
    }

    @Test
    void rejectsOutOfRangeInputs() {
        assertThatThrownBy(() -> calculator.score(11.0, 0.5, false, DependencyScope.DIRECT_RUNTIME))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> calculator.score(5.0, 1.5, false, DependencyScope.DIRECT_RUNTIME))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void customWeightsMustSumToOne() {
        assertThatThrownBy(() -> new RiskWeights(0.5, 0.5, 0.5, 0.5))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
