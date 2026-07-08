package io.chainsentry.normalization;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Stable cross-scanner identity for a finding:
 * {@code sha256(vulnId | purl | path)}. Trivy and Dependency-Check reporting
 * the same CVE on the same artifact produce the same fingerprint and collapse
 * into one finding.
 */
public final class FindingFingerprint {

    private FindingFingerprint() {
    }

    public static String of(String vulnerabilityId, String purl, String filePath) {
        String canonical = nullSafe(vulnerabilityId) + "|" + nullSafe(purl) + "|" + nullSafe(filePath);
        return HexFormat.of().formatHex(sha256(canonical));
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value.strip().toLowerCase();
    }

    private static byte[] sha256(String input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM without SHA-256", e);
        }
    }
}
