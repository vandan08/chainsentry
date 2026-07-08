package io.chainsentry.normalization;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FindingFingerprintTest {

    @Test
    void identicalInputsProduceIdenticalFingerprints() {
        String a = FindingFingerprint.of("CVE-2021-44228", "pkg:maven/log4j-core@2.14.1", "pom.xml");
        String b = FindingFingerprint.of("CVE-2021-44228", "pkg:maven/log4j-core@2.14.1", "pom.xml");

        assertThat(a).isEqualTo(b).hasSize(64); // sha-256 hex
    }

    @Test
    void isCaseAndWhitespaceInsensitive() {
        String canonical = FindingFingerprint.of("CVE-2021-44228", "pkg:maven/x@1", "pom.xml");
        String shouty = FindingFingerprint.of(" CVE-2021-44228 ", "PKG:MAVEN/X@1", "POM.XML");

        assertThat(shouty).isEqualTo(canonical);
    }

    @Test
    void anyFieldChangeChangesTheFingerprint() {
        String base = FindingFingerprint.of("CVE-1", "pkg:maven/a@1", "pom.xml");

        assertThat(FindingFingerprint.of("CVE-2", "pkg:maven/a@1", "pom.xml")).isNotEqualTo(base);
        assertThat(FindingFingerprint.of("CVE-1", "pkg:maven/a@2", "pom.xml")).isNotEqualTo(base);
        assertThat(FindingFingerprint.of("CVE-1", "pkg:maven/a@1", "build.gradle")).isNotEqualTo(base);
    }

    @Test
    void toleratesNulls() {
        assertThat(FindingFingerprint.of(null, null, null)).hasSize(64);
    }
}
