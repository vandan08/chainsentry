package io.chainsentry.github.webhook;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.shared.event.ScanRequested;
import io.chainsentry.shared.model.ScanTrigger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Optional;
import java.util.Set;

/**
 * Maps verified GitHub App events onto the domain: installations create
 * organizations, repository events register tracked repos, PR/push events
 * publish {@link ScanRequested}. Unknown events are acknowledged and ignored
 * — GitHub must always get its 2xx.
 */
@Service
public class WebhookEventHandler {

    private static final Logger log = LoggerFactory.getLogger(WebhookEventHandler.class);
    private static final Set<String> SCANNED_PR_ACTIONS = Set.of("opened", "synchronize", "reopened");
    private static final String DELETED_BRANCH_SHA = "0000000000000000000000000000000000000000";

    private final OrganizationRepository organizations;
    private final TrackedRepositoryRepository repositories;
    private final ApplicationEventPublisher events;
    private final ObjectMapper objectMapper;

    WebhookEventHandler(OrganizationRepository organizations, TrackedRepositoryRepository repositories,
                        ApplicationEventPublisher events, ObjectMapper objectMapper) {
        this.organizations = organizations;
        this.repositories = repositories;
        this.events = events;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void handle(String event, String rawPayload) {
        JsonNode payload = objectMapper.readTree(rawPayload);
        switch (event) {
            case "installation" -> onInstallation(payload);
            case "installation_repositories" -> onInstallationRepositories(payload);
            case "pull_request" -> onPullRequest(payload);
            case "push" -> onPush(payload);
            default -> log.debug("Ignoring GitHub event '{}'", event);
        }
    }

    private void onInstallation(JsonNode payload) {
        if (!"created".equals(payload.path("action").asText(""))) {
            return;
        }
        Organization org = organizationFor(payload.path("installation"));
        for (JsonNode repo : payload.path("repositories")) {
            trackRepository(org, repo);
        }
        log.info("Installation {} registered org '{}'", org.githubInstallationId(), org.login());
    }

    private void onInstallationRepositories(JsonNode payload) {
        Organization org = organizationFor(payload.path("installation"));
        for (JsonNode repo : payload.path("repositories_added")) {
            trackRepository(org, repo);
        }
    }

    private void onPullRequest(JsonNode payload) {
        if (!SCANNED_PR_ACTIONS.contains(payload.path("action").asText(""))) {
            return;
        }
        TrackedRepository repo = resolveRepository(payload);
        JsonNode head = payload.path("pull_request").path("head");
        events.publishEvent(new ScanRequested(repo.id(), head.path("sha").asText(null),
                head.path("ref").asText(null), payload.path("number").asInt(), ScanTrigger.PR));
    }

    private void onPush(JsonNode payload) {
        String after = payload.path("after").asText("");
        if (after.isEmpty() || DELETED_BRANCH_SHA.equals(after)) {
            return; // branch deletion
        }
        TrackedRepository repo = resolveRepository(payload);
        events.publishEvent(new ScanRequested(repo.id(), after,
                payload.path("ref").asText(null), null, ScanTrigger.PUSH));
    }

    /** Installations are upserted — a redelivered installation event must not duplicate the org. */
    private Organization organizationFor(JsonNode installation) {
        long installationId = installation.path("id").asLong();
        return organizations.findByGithubInstallationId(installationId)
                .orElseGet(() -> organizations.save(new Organization(
                        installation.path("account").path("login").asText("unknown"), installationId)));
    }

    private void trackRepository(Organization org, JsonNode repo) {
        long githubRepoId = repo.path("id").asLong();
        if (repositories.findByGithubRepoId(githubRepoId).isEmpty()) {
            repositories.save(new TrackedRepository(org.id(), githubRepoId,
                    repo.path("full_name").asText(null),
                    repo.path("default_branch").asText("main")));
        }
    }

    /**
     * PR/push payloads carry the full repository object, so a repo that was
     * somehow missed at installation time is registered on first contact.
     */
    private TrackedRepository resolveRepository(JsonNode payload) {
        JsonNode repo = payload.path("repository");
        long githubRepoId = repo.path("id").asLong();
        Optional<TrackedRepository> existing = repositories.findByGithubRepoId(githubRepoId);
        if (existing.isPresent()) {
            return existing.get();
        }
        Organization org = organizationFor(payload.path("installation"));
        return repositories.save(new TrackedRepository(org.id(), githubRepoId,
                repo.path("full_name").asText(null),
                repo.path("default_branch").asText("main")));
    }
}
