package io.chainsentry.policy;

import io.chainsentry.shared.model.Severity;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;

/**
 * Parses {@code chainsentry.yml}. Every key is optional; anything omitted
 * falls back to the platform default so a two-line policy file is valid:
 *
 * <pre>{@code
 * version: 1
 * gate:
 *   fail-on-kev: true
 *   fail-risk-threshold: 0.75
 *   warn-risk-threshold: 0.50
 *   max-findings:
 *     critical: 0
 *     high: 10
 * ignore:
 *   unfixed: false
 * }</pre>
 */
@Component
public class PolicyParser {

    private final ObjectMapper yaml = YAMLMapper.builder().build();

    public PolicyRules parse(String yamlContent) {
        JsonNode root = read(yamlContent);
        PolicyRules defaults = PolicyRules.defaults();
        JsonNode gate = root.path("gate");
        return new PolicyRules(
                gate.path("fail-on-kev").asBoolean(defaults.failOnKev()),
                threshold(gate, "fail-risk-threshold", defaults.failRiskThreshold()),
                maxFindings(gate.path("max-findings"), defaults.maxFindings()),
                threshold(gate, "warn-risk-threshold", defaults.warnRiskThreshold()),
                root.path("ignore").path("unfixed").asBoolean(defaults.ignoreUnfixed())
        );
    }

    private Double threshold(JsonNode gate, String key, Double fallback) {
        JsonNode node = gate.path(key);
        if (node.isMissingNode()) {
            return fallback;
        }
        if (node.isNull() || (node.isBoolean() && !node.asBoolean(false))) {
            return null; // explicit "off"
        }
        double value = node.asDouble(-1);
        if (value < 0 || value > 1) {
            throw new PolicyValidationException(key + " must be in [0,1]: " + node.asString(""));
        }
        return value;
    }

    private Map<Severity, Integer> maxFindings(JsonNode node, Map<Severity, Integer> fallback) {
        if (node.isMissingNode()) {
            return fallback;
        }
        Map<Severity, Integer> budgets = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            JsonNode budget = node.path(severity.name().toLowerCase(Locale.ROOT));
            if (budget.isMissingNode()) {
                continue;
            }
            int max = budget.asInt(-1);
            if (max < 0) {
                throw new PolicyValidationException(
                        "max-findings." + severity.name().toLowerCase(Locale.ROOT)
                                + " must be a non-negative integer");
            }
            budgets.put(severity, max);
        }
        if (budgets.size() != node.size()) {
            throw new PolicyValidationException("max-findings contains an unknown severity key");
        }
        return Map.copyOf(budgets);
    }

    private JsonNode read(String yamlContent) {
        try {
            return yaml.readTree(yamlContent);
        } catch (Exception e) {
            throw new PolicyValidationException("chainsentry.yml is not valid YAML: " + e.getMessage());
        }
    }
}
