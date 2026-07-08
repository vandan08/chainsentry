package io.chainsentry.sbom;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extracts the component inventory from a CycloneDX 1.x JSON document.
 * Directness comes from the dependency graph: a component the root
 * {@code metadata.component} directly depends on is direct; without a
 * {@code dependencies} section, directness is unknown (null).
 */
@Component
public class CycloneDxParser {

    public record ParsedSbom(String serialNumber, String specVersion, List<ParsedComponent> components) {
    }

    public record ParsedComponent(String purl, String name, String version, String license, Boolean direct) {
    }

    private final ObjectMapper objectMapper;

    CycloneDxParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ParsedSbom parse(String cycloneDxJson) {
        JsonNode root = read(cycloneDxJson);
        Set<String> directRefs = directRefs(root);
        boolean hasGraph = !root.path("dependencies").isMissingNode();

        List<ParsedComponent> components = new ArrayList<>();
        for (JsonNode component : root.path("components")) {
            String purl = component.path("purl").asText(null);
            if (purl == null) {
                continue; // nothing to key on; skip metadata-only entries
            }
            Boolean direct = hasGraph ? directRefs.contains(component.path("bom-ref").asText("")) : null;
            components.add(new ParsedComponent(
                    purl,
                    component.path("name").asText(null),
                    component.path("version").asText(null),
                    license(component),
                    direct));
        }
        return new ParsedSbom(
                root.path("serialNumber").asText(null),
                root.path("specVersion").asText(null),
                List.copyOf(components));
    }

    private Set<String> directRefs(JsonNode root) {
        String rootRef = root.path("metadata").path("component").path("bom-ref").asText(null);
        if (rootRef == null) {
            return Set.of();
        }
        Set<String> refs = new HashSet<>();
        for (JsonNode dependency : root.path("dependencies")) {
            if (rootRef.equals(dependency.path("ref").asText(""))) {
                for (JsonNode dependsOn : dependency.path("dependsOn")) {
                    refs.add(dependsOn.asText());
                }
            }
        }
        return refs;
    }

    private String license(JsonNode component) {
        JsonNode license = component.path("licenses").path(0).path("license");
        String id = license.path("id").asText(null);
        return id != null ? id : license.path("name").asText(null);
    }

    private JsonNode read(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unparseable CycloneDX document", e);
        }
    }
}
