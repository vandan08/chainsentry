package io.chainsentry.shared.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

/** Typed view of the {@code chainsentry.*} configuration tree. */
@ConfigurationProperties(prefix = "chainsentry")
public record ChainSentryProperties(Scanner scanner, Feeds feeds) {

    public record Scanner(Duration defaultTimeout, Map<String, String> images) {
    }

    public record Feeds(String epssUrl, String kevUrl, boolean syncEnabled) {
    }
}
