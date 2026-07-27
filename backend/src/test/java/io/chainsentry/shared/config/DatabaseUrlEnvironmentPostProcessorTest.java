package io.chainsentry.shared.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The translation is the one thing standing between a correct DATABASE_URL and
 * a deployment that can't reach its database, and it only ever runs on a
 * platform — so it's pinned here rather than discovered in a build log.
 */
class DatabaseUrlEnvironmentPostProcessorTest {

    @Test
    @DisplayName("libpq URL becomes a JDBC url plus credentials")
    void translatesFullUrl() {
        Map<String, Object> properties =
                DatabaseUrlEnvironmentPostProcessor.translate("postgres://alice:s3cret@db.internal:5432/chainsentry");

        assertThat(properties)
                .containsEntry("spring.datasource.url", "jdbc:postgresql://db.internal:5432/chainsentry")
                .containsEntry("spring.datasource.username", "alice")
                .containsEntry("spring.datasource.password", "s3cret");
    }

    @Test
    @DisplayName("postgresql:// scheme is accepted alongside postgres://")
    void translatesAlternateScheme() {
        assertThat(DatabaseUrlEnvironmentPostProcessor.translate("postgresql://u:p@host:6543/db"))
                .containsEntry("spring.datasource.url", "jdbc:postgresql://host:6543/db");
    }

    @Test
    @DisplayName("missing port falls back to the Postgres default")
    void defaultsPort() {
        assertThat(DatabaseUrlEnvironmentPostProcessor.translate("postgres://u:p@host/db"))
                .containsEntry("spring.datasource.url", "jdbc:postgresql://host:5432/db");
    }

    @Test
    @DisplayName("query parameters survive — sslmode=require matters on hosted Postgres")
    void preservesQueryParameters() {
        assertThat(DatabaseUrlEnvironmentPostProcessor.translate("postgres://u:p@host:5432/db?sslmode=require"))
                .containsEntry("spring.datasource.url", "jdbc:postgresql://host:5432/db?sslmode=require");
    }

    @Test
    @DisplayName("a password-less URL sets a username and no password")
    void handlesUsernameOnly() {
        Map<String, Object> properties =
                DatabaseUrlEnvironmentPostProcessor.translate("postgres://alice@host:5432/db");

        assertThat(properties).containsEntry("spring.datasource.username", "alice");
        assertThat(properties).doesNotContainKey("spring.datasource.password");
    }

    @Test
    @DisplayName("the translated URL outranks application.yml's localhost default")
    void outranksApplicationYaml() {
        // The original bug: appending the source last put it *below* application.yml,
        // so a correct DATABASE_URL was translated and then ignored, and the container
        // dialled localhost:5432 in production.
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new MapPropertySource("application.yml",
                Map.of("spring.datasource.url", "jdbc:postgresql://localhost:5432/chainsentry")));
        environment.getPropertySources().addLast(new MapPropertySource("fake-system-env",
                Map.of("DATABASE_URL", "postgres://alice:s3cret@db.internal:5432/chainsentry")));

        new DatabaseUrlEnvironmentPostProcessor().postProcessEnvironment(environment, null);

        assertThat(environment.getProperty("spring.datasource.url"))
                .isEqualTo("jdbc:postgresql://db.internal:5432/chainsentry");
        assertThat(environment.getProperty("spring.datasource.username")).isEqualTo("alice");
    }

    @Test
    @DisplayName("an explicit spring.datasource.url in the environment still wins")
    void yieldsToExplicitConfiguration() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicit",
                Map.of("spring.datasource.url", "jdbc:postgresql://chosen:5432/db")));
        environment.getPropertySources().addLast(new MapPropertySource("fake-system-env",
                Map.of("DATABASE_URL", "postgres://alice:s3cret@db.internal:5432/chainsentry")));

        new DatabaseUrlEnvironmentPostProcessor().postProcessEnvironment(environment, null);

        assertThat(environment.getProperty("spring.datasource.url"))
                .isEqualTo("jdbc:postgresql://chosen:5432/db");
    }

    @Test
    @DisplayName("it is actually registered — against Boot 4's interface, not the deprecated one")
    void isRegisteredWithSpringFactories() throws Exception {
        // Boot 4 moved EnvironmentPostProcessor out of `...boot.env` and deprecated the old
        // interface. Registering against the old name fails *silently*: the app boots and
        // falls back to the localhost datasource, surfacing only as a connection-refused on
        // the deployment platform. Naming the interface here means a future move breaks the
        // build instead of the deploy.
        Properties registrations = new Properties();
        Enumeration<URL> resources = getClass().getClassLoader().getResources("META-INF/spring.factories");
        while (resources.hasMoreElements()) {
            try (InputStream stream = resources.nextElement().openStream()) {
                Properties file = new Properties();
                file.load(stream);
                file.forEach((key, value) -> registrations.merge(key, value, (a, b) -> a + "," + b));
            }
        }

        assertThat(registrations.getProperty(EnvironmentPostProcessor.class.getName()))
                .as("registered under the non-deprecated interface")
                .contains(DatabaseUrlEnvironmentPostProcessor.class.getName());
    }

    @Test
    @DisplayName("garbage yields nothing rather than a half-built datasource")
    void ignoresUnparseableValues() {
        assertThat(DatabaseUrlEnvironmentPostProcessor.translate("not a url")).isEmpty();
        assertThat(DatabaseUrlEnvironmentPostProcessor.translate("postgres:///no-host")).isEmpty();
    }
}
