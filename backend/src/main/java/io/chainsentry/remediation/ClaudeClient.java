package io.chainsentry.remediation;

import io.chainsentry.shared.config.ChainSentryProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.StringJoiner;

/**
 * Thin Messages API client (plain {@code RestClient}, matching how this
 * codebase talks to every other external API). One fixed call shape: a
 * system prompt plus a single user turn, short non-streaming completion.
 * No sampling parameters — current Claude models reject them.
 */
@Component
class ClaudeClient {

    private static final String ANTHROPIC_VERSION = "2023-06-01";
    private static final int DEFAULT_MAX_TOKENS = 1024;

    private final ChainSentryProperties properties;
    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    ClaudeClient(ChainSentryProperties properties, RestClient.Builder restClientBuilder,
                 ObjectMapper objectMapper) {
        this.properties = properties;
        this.restClient = restClientBuilder
                .baseUrl(properties.remediation() != null && properties.remediation().apiBaseUrl() != null
                        ? properties.remediation().apiBaseUrl() : "https://api.anthropic.com")
                .build();
        this.objectMapper = objectMapper;
    }

    String model() {
        ChainSentryProperties.Remediation config = properties.remediation();
        return config != null && config.model() != null ? config.model() : "claude-opus-4-8";
    }

    String complete(String system, String userPrompt) {
        ChainSentryProperties.Remediation config = properties.remediation();
        if (config == null || !config.configured()) {
            throw new RemediationDisabledException();
        }
        ObjectNode body = objectMapper.createObjectNode();
        body.put("model", model());
        body.put("max_tokens", config.maxTokens() != null ? config.maxTokens() : DEFAULT_MAX_TOKENS);
        body.put("system", system);
        body.putArray("messages").addObject()
                .put("role", "user")
                .put("content", userPrompt);

        JsonNode response = restClient.post()
                .uri("/v1/messages")
                .header("x-api-key", config.anthropicApiKey())
                .header("anthropic-version", ANTHROPIC_VERSION)
                .header("Content-Type", "application/json")
                .body(body)
                .retrieve()
                .body(JsonNode.class);
        return textOf(response);
    }

    /** Check stop_reason before reading content — refused requests carry none. */
    private String textOf(JsonNode response) {
        if ("refusal".equals(response.path("stop_reason").asText(""))) {
            throw new IllegalStateException("The model declined this request");
        }
        StringJoiner text = new StringJoiner("\n");
        for (JsonNode block : response.path("content")) {
            if ("text".equals(block.path("type").asText(""))) {
                text.add(block.path("text").asText(""));
            }
        }
        if (text.length() == 0) {
            throw new IllegalStateException("Empty completion from the Messages API");
        }
        return text.toString();
    }
}
