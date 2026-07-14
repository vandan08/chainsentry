package io.chainsentry.github.checks;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.github.app.InstallationTokenService;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.shared.config.ChainSentryProperties;
import io.chainsentry.shared.event.ScanCompleted;
import io.chainsentry.shared.model.ScanTrigger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Set;

/**
 * Posts a Check Run when a GitHub-triggered scan finishes. Failures here are
 * logged and swallowed — a hiccup on the Checks API must never mark the scan
 * itself failed. Skips silently when the App isn't configured (demo/local).
 */
@Component
class CheckRunPublisher {

    private static final Logger log = LoggerFactory.getLogger(CheckRunPublisher.class);
    private static final Set<ScanTrigger> GITHUB_TRIGGERS = Set.of(ScanTrigger.PR, ScanTrigger.PUSH);

    private final ChainSentryProperties properties;
    private final TrackedRepositoryRepository repositories;
    private final OrganizationRepository organizations;
    private final FindingRepository findings;
    private final InstallationTokenService tokens;
    private final CheckRunPayloadFactory payloadFactory;
    private final RestClient restClient;

    CheckRunPublisher(ChainSentryProperties properties, TrackedRepositoryRepository repositories,
                      OrganizationRepository organizations, FindingRepository findings,
                      InstallationTokenService tokens, CheckRunPayloadFactory payloadFactory,
                      RestClient.Builder restClientBuilder) {
        this.properties = properties;
        this.repositories = repositories;
        this.organizations = organizations;
        this.findings = findings;
        this.tokens = tokens;
        this.payloadFactory = payloadFactory;
        this.restClient = restClientBuilder
                .baseUrl(properties.github() != null && properties.github().apiBaseUrl() != null
                        ? properties.github().apiBaseUrl() : "https://api.github.com")
                .build();
    }

    @EventListener
    public void onScanCompleted(ScanCompleted event) {
        if (properties.github() == null || !properties.github().appConfigured()
                || !GITHUB_TRIGGERS.contains(event.trigger())) {
            return;
        }
        try {
            publish(event);
        } catch (Exception e) {
            log.warn("Check Run for scan {} could not be published", event.scanJobId(), e);
        }
    }

    private void publish(ScanCompleted event) {
        TrackedRepository repo = repositories.findById(event.repositoryId()).orElseThrow();
        Long installationId = organizations.findById(repo.organizationId())
                .map(Organization::githubInstallationId)
                .orElse(null);
        if (installationId == null) {
            log.debug("Repo {} has no App installation — skipping Check Run", repo.fullName());
            return;
        }
        restClient.post()
                .uri("/repos/" + repo.fullName() + "/check-runs")
                .header("Authorization", "Bearer " + tokens.tokenFor(installationId))
                .header("Accept", "application/vnd.github+json")
                .body(payloadFactory.payload(event,
                        findings.findByScanJobIdOrderByRiskScoreDesc(event.scanJobId())))
                .retrieve()
                .toBodilessEntity();
        log.info("Check Run published for scan {} on {}", event.scanJobId(), repo.fullName());
    }
}
