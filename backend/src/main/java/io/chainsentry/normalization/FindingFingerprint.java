package io.chainsentry.normalization;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Stable cross-scanner identity for a finding. Two flavors:
 * <ul>
 *   <li><b>Package-keyed</b> ({@code sha256(vulnId | purl)}) — SCA/container
 *       findings. The purl already pins the exact artifact; the file path is
 *       deliberately excluded because engines disagree on it (Trivy reports
 *       the lockfile, Dependency-Check the resolved jar) and that disagreement
 *       must not break dedup.</li>
 *   <li><b>Location-keyed</b> ({@code sha256(ruleId | path | line)}) — SAST and
 *       secret findings, which have no package identity.</li>
 * </ul>
 */
public final class FindingFingerprint {

    private FindingFingerprint() {
    }

    /** Identity for findings on a package artifact (SCA, container). */
    public static String forPackage(String vulnerabilityId, String purl) {
        return hash(nullSafe(vulnerabilityId) + "|" + nullSafe(purl));
    }

    /** Identity for findings at a source location (SAST, secrets). */
    public static String forLocation(String engineRuleId, String filePath, Integer line) {
        return hash(nullSafe(engineRuleId) + "|" + nullSafe(filePath) + "|" + (line == null ? "" : line));
    }

    private static String hash(String canonical) {
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
