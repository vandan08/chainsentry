package io.chainsentry.github.webhook;

import io.chainsentry.shared.config.ChainSentryProperties;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WebhookSignatureVerifierTest {

    private static final String SECRET = "0123456789abcdef";
    private static final String BODY = "{\"action\":\"opened\"}";

    private WebhookSignatureVerifier verifier(String secret) {
        return new WebhookSignatureVerifier(new ChainSentryProperties(null, null,
                new ChainSentryProperties.GitHub(null, null, secret, null), null));
    }

    private String githubSignature(String secret, String body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return "sha256=" + HexFormat.of().formatHex(mac.doFinal(body.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void acceptsGithubsOwnSignatureScheme() throws Exception {
        assertThat(verifier(SECRET).matches(BODY, githubSignature(SECRET, BODY))).isTrue();
    }

    @Test
    void rejectsSignatureFromWrongSecret() throws Exception {
        assertThat(verifier(SECRET).matches(BODY, githubSignature("attacker-secret", BODY))).isFalse();
    }

    @Test
    void rejectsTamperedBody() throws Exception {
        assertThat(verifier(SECRET).matches(BODY + " ", githubSignature(SECRET, BODY))).isFalse();
    }

    @Test
    void rejectsMissingOrMalformedHeader() {
        assertThat(verifier(SECRET).matches(BODY, null)).isFalse();
        assertThat(verifier(SECRET).matches(BODY, "sha1=abcd")).isFalse();
        assertThat(verifier(SECRET).matches(BODY, "sha256=not-hex!")).isFalse();
    }

    @Test
    void refusesToRunWithoutConfiguredSecret() {
        assertThatThrownBy(() -> verifier(null).matches(BODY, "sha256=00"))
                .isInstanceOf(IllegalStateException.class);
    }
}
