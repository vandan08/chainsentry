package io.chainsentry.github.app;

import io.chainsentry.shared.config.ChainSentryProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * App JWT → installation token exchange, cached per installation until
 * shortly before the token's one-hour expiry. Tokens are never logged.
 */
@Service
public class InstallationTokenService {

    /** Refresh margin so a token handed out is never seconds from dying mid-request. */
    private static final Duration EXPIRY_MARGIN = Duration.ofMinutes(5);

    private record CachedToken(String token, Instant expiresAt) {

        boolean fresh(Instant now) {
            return now.isBefore(expiresAt.minus(EXPIRY_MARGIN));
        }
    }

    private final ChainSentryProperties properties;
    private final RestClient restClient;
    private final Clock clock;
    private final Map<Long, CachedToken> cache = new ConcurrentHashMap<>();
    private volatile GitHubAppJwtSigner signer;

    @Autowired
    InstallationTokenService(ChainSentryProperties properties, RestClient.Builder restClientBuilder) {
        this(properties, restClientBuilder, Clock.systemUTC());
    }

    InstallationTokenService(ChainSentryProperties properties, RestClient.Builder restClientBuilder, Clock clock) {
        this.properties = properties;
        this.restClient = restClientBuilder.baseUrl(apiBaseUrl(properties)).build();
        this.clock = clock;
    }

    private static String apiBaseUrl(ChainSentryProperties properties) {
        return properties.github() != null && properties.github().apiBaseUrl() != null
                ? properties.github().apiBaseUrl()
                : "https://api.github.com";
    }

    public String tokenFor(long installationId) {
        CachedToken cached = cache.compute(installationId, (id, existing) ->
                existing != null && existing.fresh(clock.instant()) ? existing : fetchToken(id));
        return cached.token();
    }

    private CachedToken fetchToken(long installationId) {
        JsonNode response = restClient.post()
                .uri("/app/installations/{id}/access_tokens", installationId)
                .header("Authorization", "Bearer " + appJwt())
                .header("Accept", "application/vnd.github+json")
                .retrieve()
                .body(JsonNode.class);
        return new CachedToken(response.path("token").asText(),
                Instant.parse(response.path("expires_at").asText()));
    }

    /** Lazily built so a missing key file fails the first GitHub call, not application boot. */
    private String appJwt() {
        GitHubAppJwtSigner local = signer;
        if (local == null) {
            ChainSentryProperties.GitHub github = properties.github();
            if (github == null || !github.appConfigured()) {
                throw new IllegalStateException(
                        "GitHub App is not configured (chainsentry.github.app-id / private-key-path)");
            }
            local = new GitHubAppJwtSigner(github.appId(), Path.of(github.privateKeyPath()), clock);
            signer = local;
        }
        return local.sign();
    }
}
