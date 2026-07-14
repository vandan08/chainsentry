package io.chainsentry.github.webhook;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.shared.event.ScanRequested;
import io.chainsentry.shared.model.ScanTrigger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import tools.jackson.databind.json.JsonMapper;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WebhookEventHandlerTest {

    @Mock
    private OrganizationRepository organizations;
    @Mock
    private TrackedRepositoryRepository repositories;
    @Mock
    private ApplicationEventPublisher events;

    private WebhookEventHandler handler() {
        return new WebhookEventHandler(organizations, repositories, events, JsonMapper.builder().build());
    }

    @Test
    void installationCreatedRegistersOrgAndRepos() {
        when(organizations.findByGithubInstallationId(77L)).thenReturn(Optional.empty());
        when(organizations.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(repositories.findByGithubRepoId(anyLong())).thenReturn(Optional.empty());
        when(repositories.save(any())).thenAnswer(inv -> inv.getArgument(0));

        handler().handle("installation", """
                {"action":"created",
                 "installation":{"id":77,"account":{"login":"acme"}},
                 "repositories":[{"id":101,"full_name":"acme/payment-service","default_branch":"main"}]}""");

        ArgumentCaptor<Organization> org = ArgumentCaptor.forClass(Organization.class);
        verify(organizations).save(org.capture());
        assertThat(org.getValue().login()).isEqualTo("acme");
        assertThat(org.getValue().githubInstallationId()).isEqualTo(77L);

        ArgumentCaptor<TrackedRepository> repo = ArgumentCaptor.forClass(TrackedRepository.class);
        verify(repositories).save(repo.capture());
        assertThat(repo.getValue().fullName()).isEqualTo("acme/payment-service");
    }

    @Test
    void pullRequestOpenedRequestsAScanOfTheHeadCommit() {
        TrackedRepository repo = new TrackedRepository(UUID.randomUUID(), 101L, "acme/payment-service", "main");
        when(repositories.findByGithubRepoId(101L)).thenReturn(Optional.of(repo));

        handler().handle("pull_request", """
                {"action":"opened","number":42,
                 "repository":{"id":101,"full_name":"acme/payment-service"},
                 "pull_request":{"head":{"sha":"e7b4d1f","ref":"feat/audit-logging"}}}""");

        ArgumentCaptor<ScanRequested> event = ArgumentCaptor.forClass(ScanRequested.class);
        verify(events).publishEvent(event.capture());
        assertThat(event.getValue().repositoryId()).isEqualTo(repo.id());
        assertThat(event.getValue().commitSha()).isEqualTo("e7b4d1f");
        assertThat(event.getValue().ref()).isEqualTo("feat/audit-logging");
        assertThat(event.getValue().prNumber()).isEqualTo(42);
        assertThat(event.getValue().trigger()).isEqualTo(ScanTrigger.PR);
    }

    @Test
    void ignoredPullRequestActionsDoNotScan() {
        handler().handle("pull_request", "{\"action\":\"labeled\",\"number\":42}");

        verifyNoInteractions(events);
    }

    @Test
    void pushRequestsAScan() {
        TrackedRepository repo = new TrackedRepository(UUID.randomUUID(), 101L, "acme/payment-service", "main");
        when(repositories.findByGithubRepoId(101L)).thenReturn(Optional.of(repo));

        handler().handle("push", """
                {"ref":"refs/heads/main","after":"a3f8c2d",
                 "repository":{"id":101,"full_name":"acme/payment-service"}}""");

        ArgumentCaptor<ScanRequested> event = ArgumentCaptor.forClass(ScanRequested.class);
        verify(events).publishEvent(event.capture());
        assertThat(event.getValue().commitSha()).isEqualTo("a3f8c2d");
        assertThat(event.getValue().trigger()).isEqualTo(ScanTrigger.PUSH);
        assertThat(event.getValue().prNumber()).isNull();
    }

    @Test
    void branchDeletionPushIsIgnored() {
        handler().handle("push", """
                {"ref":"refs/heads/gone","after":"0000000000000000000000000000000000000000",
                 "repository":{"id":101}}""");

        verifyNoInteractions(events);
    }

    @Test
    void unknownEventsAreAcknowledgedQuietly() {
        handler().handle("star", "{\"action\":\"created\"}");

        verifyNoInteractions(events, organizations, repositories);
    }

    @Test
    void prOnUntrackedRepoRegistersItUnderTheInstallationsOrg() {
        Organization org = new Organization("acme", 77L);
        when(repositories.findByGithubRepoId(101L)).thenReturn(Optional.empty());
        when(organizations.findByGithubInstallationId(77L)).thenReturn(Optional.of(org));
        when(repositories.save(any())).thenAnswer(inv -> inv.getArgument(0));

        handler().handle("pull_request", """
                {"action":"opened","number":7,
                 "installation":{"id":77},
                 "repository":{"id":101,"full_name":"acme/new-service","default_branch":"main"},
                 "pull_request":{"head":{"sha":"abc1234","ref":"feat/x"}}}""");

        ArgumentCaptor<TrackedRepository> repo = ArgumentCaptor.forClass(TrackedRepository.class);
        verify(repositories).save(repo.capture());
        assertThat(repo.getValue().organizationId()).isEqualTo(org.id());
        verify(events).publishEvent(any(ScanRequested.class));
    }
}
