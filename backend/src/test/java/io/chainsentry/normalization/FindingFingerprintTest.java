package io.chainsentry.normalization;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FindingFingerprintTest {

    @Test
    void identicalInputsProduceIdenticalFingerprints() {
        String a = FindingFingerprint.forPackage("CVE-2021-44228", "pkg:maven/log4j-core@2.14.1");
        String b = FindingFingerprint.forPackage("CVE-2021-44228", "pkg:maven/log4j-core@2.14.1");

        assertThat(a).isEqualTo(b).hasSize(64); // sha-256 hex
    }

    @Test
    void isCaseAndWhitespaceInsensitive() {
        String canonical = FindingFingerprint.forPackage("CVE-2021-44228", "pkg:maven/x@1");
        String shouty = FindingFingerprint.forPackage(" CVE-2021-44228 ", "PKG:MAVEN/X@1");

        assertThat(shouty).isEqualTo(canonical);
    }

    @Test
    void anyFieldChangeChangesThePackageFingerprint() {
        String base = FindingFingerprint.forPackage("CVE-1", "pkg:maven/a@1");

        assertThat(FindingFingerprint.forPackage("CVE-2", "pkg:maven/a@1")).isNotEqualTo(base);
        assertThat(FindingFingerprint.forPackage("CVE-1", "pkg:maven/a@2")).isNotEqualTo(base);
    }

    @Test
    void locationFingerprintKeysOnRulePathAndLine() {
        String base = FindingFingerprint.forLocation("rule.sqli", "src/A.java", 42);

        assertThat(FindingFingerprint.forLocation("rule.sqli", "src/A.java", 42)).isEqualTo(base);
        assertThat(FindingFingerprint.forLocation("rule.xss", "src/A.java", 42)).isNotEqualTo(base);
        assertThat(FindingFingerprint.forLocation("rule.sqli", "src/B.java", 42)).isNotEqualTo(base);
        assertThat(FindingFingerprint.forLocation("rule.sqli", "src/A.java", 43)).isNotEqualTo(base);
    }

    @Test
    void packageAndLocationKeysNeverCollide() {
        // Same raw text through both flavors must not produce the same identity.
        assertThat(FindingFingerprint.forPackage("a", "b"))
                .isNotEqualTo(FindingFingerprint.forLocation("a", "b", null));
    }

    @Test
    void toleratesNulls() {
        assertThat(FindingFingerprint.forPackage(null, null)).hasSize(64);
        assertThat(FindingFingerprint.forLocation(null, null, null)).hasSize(64);
    }
}
