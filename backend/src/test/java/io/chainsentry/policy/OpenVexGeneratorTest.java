package io.chainsentry.policy;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class OpenVexGeneratorTest {

    private static final Instant ISSUED = Instant.parse("2026-07-17T10:00:00Z");
    private static final String PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

    private final JsonMapper mapper = JsonMapper.builder().build();
    private final OpenVexGenerator generator = new OpenVexGenerator(mapper);

    private Suppression suppression(SuppressionJustification justification, String purl) {
        return new Suppression(UUID.randomUUID(), "CVE-2021-44228", purl, justification,
                "JNDI lookups disabled via LOG4J_FORMAT_MSG_NO_LOOKUPS", "security-team",
                LocalDate.of(2026, 10, 1));
    }

    @Test
    void notAffectedSuppressionsMapToOpenVexNotAffected() {
        String doc = generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.NOT_AFFECTED, PURL), ISSUED);
        JsonNode parsed = mapper.readTree(doc);

        assertThat(parsed.path("@context").asText()).isEqualTo("https://openvex.dev/ns/v0.2.0");
        assertThat(parsed.path("author").asText()).contains("security-team");
        JsonNode statement = parsed.path("statements").get(0);
        assertThat(statement.path("vulnerability").path("name").asText()).isEqualTo("CVE-2021-44228");
        assertThat(statement.path("products").get(0).path("@id").asText()).isEqualTo(PURL);
        assertThat(statement.path("status").asText()).isEqualTo("not_affected");
        assertThat(statement.path("justification").asText()).isEqualTo("vulnerable_code_not_in_execute_path");
        assertThat(statement.path("impact_statement").asText()).contains("JNDI lookups disabled");
    }

    @Test
    void acceptedRiskIsAffectedWithAnActionStatementNeverASilentPass() {
        String doc = generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.ACCEPTED_RISK, PURL), ISSUED);
        JsonNode statement = mapper.readTree(doc).path("statements").get(0);

        assertThat(statement.path("status").asText()).isEqualTo("affected");
        assertThat(statement.path("action_statement").asText()).contains("risk accepted until 2026-10-01");
        assertThat(statement.has("justification")).isFalse();
    }

    @Test
    void falsePositiveAndMitigatedUseTheMatchingOpenVexJustifications() {
        JsonNode falsePositive = mapper.readTree(generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.FALSE_POSITIVE, PURL), ISSUED))
                .path("statements").get(0);
        JsonNode mitigated = mapper.readTree(generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.MITIGATED, PURL), ISSUED))
                .path("statements").get(0);

        assertThat(falsePositive.path("justification").asText()).isEqualTo("component_not_present");
        assertThat(mitigated.path("justification").asText()).isEqualTo("inline_mitigations_already_exist");
    }

    @Test
    void aggregateMergesEveryStatementIntoOneDocument() {
        UUID repoId = UUID.randomUUID();
        String first = generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.NOT_AFFECTED, PURL), ISSUED);
        String second = generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.ACCEPTED_RISK, "pkg:maven/org.yaml/snakeyaml@1.30"), ISSUED);

        JsonNode merged = mapper.readTree(generator.aggregate(repoId, List.of(first, second), ISSUED));

        assertThat(merged.path("statements")).hasSize(2);
        assertThat(merged.path("@context").asText()).isEqualTo("https://openvex.dev/ns/v0.2.0");
    }

    @Test
    void repoWideSuppressionOmitsProducts() {
        String doc = generator.document(UUID.randomUUID(),
                suppression(SuppressionJustification.NOT_AFFECTED, null), ISSUED);

        assertThat(mapper.readTree(doc).path("statements").get(0).has("products")).isFalse();
    }
}
