package io.chainsentry.risk;

/**
 * Weights for the composite risk score. Organizations can override the
 * defaults; weights must sum to 1 so scores stay comparable across orgs.
 */
public record RiskWeights(double cvss, double epss, double kev, double scope) {

    public static final RiskWeights DEFAULT = new RiskWeights(0.25, 0.40, 0.25, 0.10);

    public RiskWeights {
        double sum = cvss + epss + kev + scope;
        if (Math.abs(sum - 1.0) > 1e-9) {
            throw new IllegalArgumentException("Risk weights must sum to 1.0, got " + sum);
        }
        if (cvss < 0 || epss < 0 || kev < 0 || scope < 0) {
            throw new IllegalArgumentException("Risk weights must be non-negative");
        }
    }
}
