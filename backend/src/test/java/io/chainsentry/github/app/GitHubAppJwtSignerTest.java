package io.chainsentry.github.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitHubAppJwtSignerTest {

    private static final Instant NOW = Instant.parse("2026-07-14T12:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);

    @TempDir
    Path tempDir;

    private KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private Path writePkcs8Pem(KeyPair keyPair) throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                        .encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Path file = tempDir.resolve("app.pem");
        Files.writeString(file, pem);
        return file;
    }

    @Test
    void producesAVerifiableRs256JwtWithGithubsClaims() throws Exception {
        KeyPair keyPair = keyPair();
        GitHubAppJwtSigner signer = new GitHubAppJwtSigner(123456L, writePkcs8Pem(keyPair), FIXED);

        String jwt = signer.sign();
        String[] parts = jwt.split("\\.");
        assertThat(parts).hasSize(3);

        Base64.Decoder decoder = Base64.getUrlDecoder();
        JsonNode header = JsonMapper.builder().build().readTree(decoder.decode(parts[0]));
        JsonNode claims = JsonMapper.builder().build().readTree(decoder.decode(parts[1]));
        assertThat(header.path("alg").asText()).isEqualTo("RS256");
        assertThat(claims.path("iss").asText()).isEqualTo("123456");
        assertThat(claims.path("iat").asLong()).isEqualTo(NOW.getEpochSecond() - 60);   // clock-drift backdate
        assertThat(claims.path("exp").asLong()).isEqualTo(NOW.getEpochSecond() + 540); // under GitHub's 10 min cap

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        assertThat(verifier.verify(decoder.decode(parts[2]))).isTrue();
    }

    @Test
    void rejectsPkcs1KeysWithAConversionHint() throws Exception {
        Path pkcs1 = tempDir.resolve("pkcs1.pem");
        Files.writeString(pkcs1, "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n");

        assertThatThrownBy(() -> new GitHubAppJwtSigner(1L, pkcs1, FIXED))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("openssl pkcs8");
    }

    @Test
    void failsClearlyWhenKeyFileIsMissing() {
        assertThatThrownBy(() -> new GitHubAppJwtSigner(1L, tempDir.resolve("nope.pem"), FIXED))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot read");
    }
}
