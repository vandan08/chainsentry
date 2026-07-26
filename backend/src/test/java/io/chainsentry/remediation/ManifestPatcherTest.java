package io.chainsentry.remediation;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestPatcherTest {

    private static final String LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

    private static final String POM = """
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <version>2.14.1</version>
                </dependency>
                <dependency>
                  <groupId>com.google.guava</groupId>
                  <artifactId>guava</artifactId>
                  <version>31.0-jre</version>
                </dependency>
              </dependencies>
            </project>
            """;

    private final ManifestPatcher patcher = new ManifestPatcher();

    @Test
    void bumpsExactlyTheAffectedDependencyInAPom() {
        Optional<String> patched = patcher.patch("pom.xml", POM, LOG4J_PURL, "2.14.1", "2.15.0");

        assertThat(patched).isPresent();
        assertThat(patched.get())
                .contains("<version>2.15.0</version>")
                .doesNotContain("2.14.1")
                .contains("<version>31.0-jre</version>"); // neighbors untouched
    }

    @Test
    void neverTouchesThePomWhenTheArtifactIsMissing() {
        assertThat(patcher.patch("pom.xml", POM,
                "pkg:maven/org.yaml/snakeyaml@1.30", "1.30", "2.0")).isEmpty();
    }

    @Test
    void refusesAmbiguousDoubleDeclarations() {
        String pomWithTwoDeclarations = POM + POM;

        assertThat(patcher.patch("pom.xml", pomWithTwoDeclarations, LOG4J_PURL,
                "2.14.1", "2.15.0")).isEmpty();
    }

    @Test
    void bumpsPackageJsonPreservingTheRangePrefix() {
        String packageJson = """
                {
                  "dependencies": {
                    "lodash": "^4.17.20",
                    "express": "^4.18.0"
                  }
                }
                """;

        Optional<String> patched = patcher.patch("package.json", packageJson,
                "pkg:npm/lodash@4.17.20", "4.17.20", "4.17.21");

        assertThat(patched).isPresent();
        assertThat(patched.get())
                .contains("\"lodash\": \"^4.17.21\"")
                .contains("\"express\": \"^4.18.0\"");
    }

    @Test
    void handlesScopedNpmPackages() {
        String packageJson = "{ \"dependencies\": { \"@babel/traverse\": \"7.22.0\" } }";

        Optional<String> patched = patcher.patch("package.json", packageJson,
                "pkg:npm/%40babel/traverse@7.22.0", "7.22.0", "7.23.2");

        assertThat(patched).isPresent();
        assertThat(patched.get()).contains("\"@babel/traverse\": \"7.23.2\"");
    }

    @Test
    void unsupportedManifestsAreNeverPatched() {
        assertThat(patcher.patch("build.gradle", "version '2.14.1'", LOG4J_PURL,
                "2.14.1", "2.15.0")).isEmpty();
        assertThat(patcher.patch("Main.java", "// 2.14.1", LOG4J_PURL,
                "2.14.1", "2.15.0")).isEmpty();
    }
}
