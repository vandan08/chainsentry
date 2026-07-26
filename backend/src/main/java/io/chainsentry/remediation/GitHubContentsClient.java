package io.chainsentry.remediation;

import io.chainsentry.github.app.InstallationTokenService;
import io.chainsentry.shared.config.ChainSentryProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** RestClient implementation of {@link GitHubContentsPort} using installation tokens. */
@Component
class GitHubContentsClient implements GitHubContentsPort {

    private final InstallationTokenService tokens;
    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    GitHubContentsClient(InstallationTokenService tokens, ChainSentryProperties properties,
                         RestClient.Builder restClientBuilder, ObjectMapper objectMapper) {
        this.tokens = tokens;
        this.restClient = restClientBuilder
                .baseUrl(properties.github() != null && properties.github().apiBaseUrl() != null
                        ? properties.github().apiBaseUrl() : "https://api.github.com")
                .build();
        this.objectMapper = objectMapper;
    }

    @Override
    public RepoFile fetchFile(long installationId, String repoFullName, String path, String ref) {
        JsonNode response = get(installationId,
                "/repos/" + repoFullName + "/contents/" + path + "?ref=" + ref);
        String base64 = response.path("content").asText("").replaceAll("\\s", "");
        return new RepoFile(new String(Base64.getDecoder().decode(base64), StandardCharsets.UTF_8),
                response.path("sha").asText(null));
    }

    @Override
    public String branchHeadSha(long installationId, String repoFullName, String branch) {
        return get(installationId, "/repos/" + repoFullName + "/git/ref/heads/" + branch)
                .path("object").path("sha").asText(null);
    }

    @Override
    public void createBranch(long installationId, String repoFullName, String branchName, String fromSha) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("ref", "refs/heads/" + branchName);
        body.put("sha", fromSha);
        post(installationId, "/repos/" + repoFullName + "/git/refs", body);
    }

    @Override
    public void updateFile(long installationId, String repoFullName, String path, String branch,
                           String commitMessage, String newContent, String previousSha) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("message", commitMessage);
        body.put("content", Base64.getEncoder()
                .encodeToString(newContent.getBytes(StandardCharsets.UTF_8)));
        body.put("sha", previousSha);
        body.put("branch", branch);
        restClient.put()
                .uri("/repos/" + repoFullName + "/contents/" + path)
                .headers(headers -> auth(headers::set, installationId))
                .body(body)
                .retrieve()
                .toBodilessEntity();
    }

    @Override
    public String openDraftPullRequest(long installationId, String repoFullName, String title,
                                       String body, String headBranch, String baseBranch) {
        ObjectNode request = objectMapper.createObjectNode();
        request.put("title", title);
        request.put("body", body);
        request.put("head", headBranch);
        request.put("base", baseBranch);
        request.put("draft", true); // guardrail: never an auto-mergeable PR
        return post(installationId, "/repos/" + repoFullName + "/pulls", request)
                .path("html_url").asText(null);
    }

    private JsonNode get(long installationId, String uri) {
        return restClient.get()
                .uri(uri)
                .headers(headers -> auth(headers::set, installationId))
                .retrieve()
                .body(JsonNode.class);
    }

    private JsonNode post(long installationId, String uri, ObjectNode body) {
        return restClient.post()
                .uri(uri)
                .headers(headers -> auth(headers::set, installationId))
                .body(body)
                .retrieve()
                .body(JsonNode.class);
    }

    private void auth(java.util.function.BiConsumer<String, String> setHeader, long installationId) {
        setHeader.accept("Authorization", "Bearer " + tokens.tokenFor(installationId));
        setHeader.accept("Accept", "application/vnd.github+json");
    }
}
