package io.chainsentry.shared.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

/** Typed view of the {@code chainsentry.*} configuration tree. */
@ConfigurationProperties(prefix = "chainsentry")
public record ChainSentryProperties(Scanner scanner, Feeds feeds, GitHub github, Remediation remediation,
                                    Demo demo) {

    public record Scanner(Duration defaultTimeout, Map<String, String> images) {
    }

    /**
     * Public demo deployment. {@code readOnly} rejects every state-changing API
     * call so a link that anyone on the internet can open cannot have its
     * seeded world edited out from under the next visitor.
     */
    public record Demo(boolean readOnly) {
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

    /**
     * AI remediation (Claude API). The key lives in application-local.yml —
     * null means the explain/fix-PR endpoints answer 503.
     */
    public record Remediation(String anthropicApiKey, String model, String apiBaseUrl, Integer maxTokens) {

        public boolean configured() {
            return anthropicApiKey != null && !anthropicApiKey.isBlank();
        }
    }
}
