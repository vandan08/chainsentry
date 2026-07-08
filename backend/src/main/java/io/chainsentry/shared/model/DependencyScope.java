package io.chainsentry.shared.model;

/**
 * Where a vulnerable dependency sits in the dependency graph. Feeds the
 * risk-score scope factor: a CVE in a direct runtime dependency is a far
 * bigger deal than the same CVE in a transitive test-only one.
 */
public enum DependencyScope {
    DIRECT_RUNTIME(1.0),
    TRANSITIVE_RUNTIME(0.7),
    DIRECT_TEST(0.3),
    TRANSITIVE_TEST(0.15);

    private final double scopeFactor;

    DependencyScope(double scopeFactor) {
        this.scopeFactor = scopeFactor;
    }

    public double scopeFactor() {
        return scopeFactor;
    }
}
