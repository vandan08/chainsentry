package io.chainsentry.github.webhook;

import io.chainsentry.shared.config.ChainSentryProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Verifies GitHub's {@code X-Hub-Signature-256} header: HMAC-SHA256 of the
 * raw request body with the webhook secret, constant-time compared — before
 * any JSON parsing happens.
 */
@Component
public class WebhookSignatureVerifier {

    private static final String SIGNATURE_PREFIX = "sha256=";

    private final ChainSentryProperties properties;

    WebhookSignatureVerifier(ChainSentryProperties properties) {
        this.properties = properties;
    }

    public boolean matches(String rawBody, String signatureHeader) {
        String secret = properties.github() != null ? properties.github().webhookSecret() : null;
        if (secret == null) {
            throw new IllegalStateException(
                    "chainsentry.github.webhook-secret is not configured — rejecting all webhook deliveries");
        }
        if (signatureHeader == null || !signatureHeader.startsWith(SIGNATURE_PREFIX)) {
            return false;
        }
        byte[] expected = hmacSha256(secret, rawBody);
        byte[] provided = decodeHex(signatureHeader.substring(SIGNATURE_PREFIX.length()));
        return provided != null && MessageDigest.isEqual(expected, provided);
    }

    private byte[] hmacSha256(String secret, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("JVM without HmacSHA256", e);
        }
    }

    private byte[] decodeHex(String hex) {
        try {
            return HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            return null; // malformed hex is just an invalid signature
        }
    }
}
