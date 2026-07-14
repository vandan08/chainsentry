package io.chainsentry.github.app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;

/**
 * Builds the short-lived RS256 JWT that authenticates as the GitHub App
 * (iss = App id). Plain JDK crypto — no JWT library needed for one
 * fixed-header token.
 *
 * <p>Expects a PKCS#8 PEM ({@code BEGIN PRIVATE KEY}). GitHub downloads keys
 * in PKCS#1 ({@code BEGIN RSA PRIVATE KEY}); convert once with
 * {@code openssl pkcs8 -topk8 -nocrypt -in app.pem -out app-pkcs8.pem}.
 */
class GitHubAppJwtSigner {

    private static final String HEADER = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    /** GitHub caps App JWT lifetime at 10 min; stay under it and backdate iat for clock drift. */
    private static final long BACKDATE_SECONDS = 60;
    private static final long LIFETIME_SECONDS = 540;

    private final long appId;
    private final PrivateKey privateKey;
    private final Clock clock;

    GitHubAppJwtSigner(long appId, Path privateKeyPath, Clock clock) {
        this.appId = appId;
        this.privateKey = loadKey(privateKeyPath);
        this.clock = clock;
    }

    String sign() {
        long now = clock.instant().getEpochSecond();
        String payload = "{\"iat\":" + (now - BACKDATE_SECONDS)
                + ",\"exp\":" + (now + LIFETIME_SECONDS)
                + ",\"iss\":\"" + appId + "\"}";
        String signingInput = base64Url(HEADER.getBytes(StandardCharsets.UTF_8))
                + "." + base64Url(payload.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + base64Url(rs256(signingInput));
    }

    private byte[] rs256(String signingInput) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not sign GitHub App JWT", e);
        }
    }

    private static PrivateKey loadKey(Path pemPath) {
        String pem = readPem(pemPath);
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            throw new IllegalStateException(pemPath + " is PKCS#1 — convert it once with: "
                    + "openssl pkcs8 -topk8 -nocrypt -in app.pem -out app-pkcs8.pem");
        }
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Unreadable GitHub App private key: " + pemPath, e);
        }
    }

    private static String readPem(Path pemPath) {
        try {
            return Files.readString(pemPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read GitHub App private key: " + pemPath, e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
