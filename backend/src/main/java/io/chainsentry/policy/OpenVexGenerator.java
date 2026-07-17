package io.chainsentry.policy;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Emits OpenVEX (v0.2.0) documents from suppressions. The mapping encodes
 * the semantic difference the spec insists on: NOT_AFFECTED-style
 * justifications say "this doesn't apply here", ACCEPTED_RISK says "it
 * applies and we're shipping anyway" — status {@code affected} with an
 * action statement, never a silent pass.
 */
@Component
public class OpenVexGenerator {

    private static final String CONTEXT = "https://openvex.dev/ns/v0.2.0";
    private static final String ID_NAMESPACE = "https://chainsentry.dev/vex/";

    private final ObjectMapper objectMapper;

    OpenVexGenerator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String document(UUID documentId, Suppression suppression, Instant issuedAt) {
        ObjectNode doc = envelope(documentId, suppression.approvedBy(), issuedAt);
        doc.putArray("statements").add(statement(suppression));
        return doc.toString();
    }

    /** One merged document for a repository — every statement from the given per-suppression docs. */
    public String aggregate(UUID repositoryId, List<String> documents, Instant issuedAt) {
        ObjectNode doc = envelope(UUID.nameUUIDFromBytes(repositoryId.toString().getBytes()),
                "ChainSentry", issuedAt);
        ArrayNode statements = doc.putArray("statements");
        for (String document : documents) {
            JsonNode parsed = objectMapper.readTree(document);
            parsed.path("statements").forEach(statements::add);
        }
        return doc.toString();
    }

    private ObjectNode envelope(UUID documentId, String author, Instant issuedAt) {
        ObjectNode doc = objectMapper.createObjectNode();
        doc.put("@context", CONTEXT);
        doc.put("@id", ID_NAMESPACE + documentId);
        doc.put("author", author);
        doc.put("timestamp", issuedAt.toString());
        doc.put("version", 1);
        return doc;
    }

    private ObjectNode statement(Suppression suppression) {
        ObjectNode statement = objectMapper.createObjectNode();
        statement.putObject("vulnerability").put("name", suppression.vulnerabilityId());
        if (suppression.packagePurl() != null) {
            statement.putArray("products").addObject().put("@id", suppression.packagePurl());
        }
        switch (suppression.justification()) {
            case NOT_AFFECTED -> notAffected(statement, "vulnerable_code_not_in_execute_path", suppression);
            case FALSE_POSITIVE -> notAffected(statement, "component_not_present", suppression);
            case MITIGATED -> notAffected(statement, "inline_mitigations_already_exist", suppression);
            case ACCEPTED_RISK -> {
                statement.put("status", "affected");
                statement.put("action_statement",
                        suppression.rationale() + " (risk accepted until " + suppression.expiresOn() + ")");
            }
        }
        return statement;
    }

    private void notAffected(ObjectNode statement, String openVexJustification, Suppression suppression) {
        statement.put("status", "not_affected");
        statement.put("justification", openVexJustification);
        statement.put("impact_statement", suppression.rationale());
    }
}
