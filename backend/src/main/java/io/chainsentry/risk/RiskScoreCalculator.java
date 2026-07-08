package io.chainsentry.risk;

import io.chainsentry.shared.model.DependencyScope;
import org.springframework.stereotype.Component;

/**
 * The prioritization core of ChainSentry.
 *
 * <p>CVSS alone measures severity <em>if exploited</em>, not the likelihood of
 * exploitation — which is why CVSS-sorted finding lists are ~95% noise. This
 * calculator blends:
 * <ul>
 *   <li><b>CVSS</b> base score (normalized 0..1) — impact if exploited</li>
 *   <li><b>EPSS</b> — modeled probability of exploitation in the next 30 days</li>
 *   <li><b>KEV</b> — CISA Known Exploited Vulnerabilities membership (step
 *       function: confirmed exploitation should dominate)</li>
 *   <li><b>scope</b> — where the dependency sits (direct runtime vs transitive test)</li>
 * </ul>
 * into a single 0..1 score used to rank findings and drive policy gates.
 */
@Component
public class RiskScoreCalculator {

    /**
     * @param cvssScore CVSS base score, 0..10 (0 if unknown)
     * @param epssScore EPSS probability, 0..1 (0 if unknown)
     * @param inKev     whether the CVE is in the CISA KEV catalog
     * @param scope     dependency-graph position of the vulnerable component
     * @return composite risk score in [0, 1]
     */
    public double score(double cvssScore, double epssScore, boolean inKev, DependencyScope scope) {
        return score(cvssScore, epssScore, inKev, scope, RiskWeights.DEFAULT);
    }

    public double score(double cvssScore, double epssScore, boolean inKev,
                        DependencyScope scope, RiskWeights weights) {
        if (cvssScore < 0 || cvssScore > 10) {
            throw new IllegalArgumentException("CVSS score must be in [0,10]: " + cvssScore);
        }
        if (epssScore < 0 || epssScore > 1) {
            throw new IllegalArgumentException("EPSS score must be in [0,1]: " + epssScore);
        }
        double kevFactor = inKev ? 1.0 : 0.0;
        return weights.cvss() * (cvssScore / 10.0)
                + weights.epss() * epssScore
                + weights.kev() * kevFactor
                + weights.scope() * scope.scopeFactor();
    }
}
