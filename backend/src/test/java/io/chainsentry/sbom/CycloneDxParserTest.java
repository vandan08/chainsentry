package io.chainsentry.sbom;

import io.chainsentry.TestFixtures;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class CycloneDxParserTest {

    private final CycloneDxParser parser = new CycloneDxParser(JsonMapper.builder().build());

    @Test
    void parsesTheHeadSbomCompletely() {
        CycloneDxParser.ParsedSbom sbom = parser.parse(TestFixtures.read("demo/sbom-head.json"));

        assertThat(sbom.specVersion()).isEqualTo("1.6");
        assertThat(sbom.serialNumber()).startsWith("urn:uuid:");
        assertThat(sbom.components()).hasSize(7);
    }

    @Test
    void derivesDirectnessFromTheDependencyGraph() {
        CycloneDxParser.ParsedSbom sbom = parser.parse(TestFixtures.read("demo/sbom-head.json"));

        CycloneDxParser.ParsedComponent starter = byName(sbom, "audit-logging-starter");
        CycloneDxParser.ParsedComponent log4j = byName(sbom, "log4j-core");

        assertThat(starter.direct()).isTrue();   // declared in the app's pom
        assertThat(log4j.direct()).isFalse();    // pulled in by the starter
    }

    @Test
    void extractsLicenses() {
        CycloneDxParser.ParsedSbom sbom = parser.parse(TestFixtures.read("demo/sbom-head.json"));

        assertThat(byName(sbom, "log4j-core").license()).isEqualTo("Apache-2.0");
    }

    @Test
    void directnessIsUnknownWithoutADependencyGraph() {
        CycloneDxParser.ParsedSbom sbom = parser.parse("""
                {"bomFormat": "CycloneDX", "specVersion": "1.6",
                 "components": [{"name": "lib", "version": "1.0", "purl": "pkg:maven/a/lib@1.0"}]}
                """);

        assertThat(sbom.components().getFirst().direct()).isNull();
    }

    private CycloneDxParser.ParsedComponent byName(CycloneDxParser.ParsedSbom sbom, String name) {
        return sbom.components().stream().filter(c -> name.equals(c.name())).findFirst().orElseThrow();
    }
}
