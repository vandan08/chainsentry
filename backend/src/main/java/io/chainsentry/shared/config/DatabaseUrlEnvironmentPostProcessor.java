package io.chainsentry.shared.config;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.StandardEnvironment;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Most managed platforms (Render, Railway, Fly, Heroku) hand the database over
 * as a single {@code DATABASE_URL} in libpq form —
 * {@code postgres://user:pass@host:5432/db} — which JDBC cannot parse. Rather
 * than making every deployment split it into three env vars by hand, translate
 * it here into the {@code spring.datasource.*} triple.
 *
 * <p>Slotted directly below the system environment, which puts it above
 * {@code application.yml} but below anything explicitly supplied to the
 * process: a deployment that sets {@code SPRING_DATASOURCE_URL} (or passes
 * {@code --spring.datasource.url}) still overrides the translation, while the
 * localhost default in {@code application.yml} does not. Appending it last
 * instead would let that default win and quietly send production at
 * localhost:5432.
 *
 * <p>Registered through {@code META-INF/spring.factories} under
 * {@code org.springframework.boot.EnvironmentPostProcessor}. Boot 4 moved the
 * interface out of {@code ...boot.env} and deprecated the old one — registering
 * against the old package name fails <em>silently</em>: the app boots and
 * quietly falls back to the localhost datasource in application.yml, which
 * only shows up as a connection-refused on the deployment platform.
 */
public class DatabaseUrlEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String SOURCE_NAME = "chainsentry-database-url";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String databaseUrl = environment.getProperty("DATABASE_URL");
        if (databaseUrl == null || databaseUrl.isBlank() || databaseUrl.startsWith("jdbc:")) {
            return;
        }
        Map<String, Object> properties = translate(databaseUrl);
        if (properties.isEmpty()) {
            return;
        }
        MapPropertySource translated = new MapPropertySource(SOURCE_NAME, properties);
        MutablePropertySources sources = environment.getPropertySources();
        if (sources.contains(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME)) {
            sources.addAfter(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, translated);
        } else {
            sources.addFirst(translated);
        }
    }

    /** Package-private so the translation is unit-testable without an environment. */
    static Map<String, Object> translate(String databaseUrl) {
        URI uri;
        try {
            uri = URI.create(databaseUrl);
        } catch (IllegalArgumentException e) {
            return Map.of();   // not a URL we understand; let the datasource fail loudly on its own terms
        }
        if (uri.getHost() == null) {
            return Map.of();
        }
        int port = uri.getPort() == -1 ? 5432 : uri.getPort();
        String database = uri.getPath() == null ? "" : uri.getPath();
        String query = uri.getQuery() == null ? "" : "?" + uri.getQuery();

        Map<String, Object> properties = new HashMap<>();
        properties.put("spring.datasource.url",
                "jdbc:postgresql://" + uri.getHost() + ":" + port + database + query);

        String userInfo = uri.getUserInfo();
        if (userInfo != null && !userInfo.isBlank()) {
            int separator = userInfo.indexOf(':');
            properties.put("spring.datasource.username",
                    separator < 0 ? userInfo : userInfo.substring(0, separator));
            if (separator >= 0) {
                properties.put("spring.datasource.password", userInfo.substring(separator + 1));
            }
        }
        return properties;
    }
}
