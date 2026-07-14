package io.chainsentry.shared.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

/** Typed view of the {@code chainsentry.*} configuration tree. */
@ConfigurationProperties(prefix = "chainsentry")
public record ChainSentryProperties(Scanner scanner, Feeds feeds, GitHub github) {

    public record Scanner(Duration defaultTimeout, Map<String, String> images) {
    }

    public record Feeds(String epssUrl, String kevUrl, boolean syncEnabled) {
    }

    /**
     * GitHub App credentials (see docs/07-GITHUB-APP-SETUP.md). App id, key
     * path and webhook secret live in application-local.yml — null here means
     * "App not configured", and GitHub-facing features quietly disable.
     */
    public record GitHub(Long appId, String privateKeyPath, String webhookSecret, String apiBaseUrl) {

        public boolean appConfigured() {
            return appId != null && privateKeyPath != null;
        }
    }
}
