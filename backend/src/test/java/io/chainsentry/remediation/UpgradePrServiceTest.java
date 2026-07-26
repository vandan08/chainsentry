package io.chainsentry.remediation;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScanTrigger;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class UpgradePrServiceTest {

    private static final String POM = """
            <dependency>
              <artifactId>log4j-core</artifactId>
              <version>2.14.1</version>
            </dependency>
            """;

    /** In-memory GitHub double that records the write sequence. */
    static class FakeGitHub implements GitHubContentsPort {
        final List<String> calls = new ArrayList<>();
        String pushedContent;
        boolean draft = true;

        @Override
        public RepoFile fetchFile(long installationId, String repo, String path, String ref) {
            calls.add("fetch:" + path + "@" + ref);
            return new RepoFile(POM, "abc123sha");
        }

        @Override
        public String branchHeadSha(long installationId, String repo, String branch) {
            return "headsha";
        }

        @Override
        public void createBranch(long installationId, String repo, String branchName, String fromSha) {
            calls.add("branch:" + branchName);
        }

        @Override
        public void updateFile(long installationId, String repo, String path, String branch,
                               String message, String newContent, String previousSha) {
            calls.add("push:" + path + "→" + branch);
            pushedContent = newContent;
        }

        @Override
        public String openDraftPullRequest(long installationId, String repo, String title,
                                           String body, String head, String base) {
            calls.add("pr:" + head + "→" + base);
            return "https://github.com/acme/payment-service/pull/43";
        }
    }

    @Mock
    private FindingRepository findings;
    @Mock
    private ScanJobRepository scanJobs;
    @Mock
    private TrackedRepositoryRepository repositories;
    @Mock
    private OrganizationRepository organizations;

    private final FakeGitHub github = new FakeGitHub();

    private Organization org;
    private TrackedRepository repo;
    private ScanJob job;
    private Finding finding;

    @BeforeEach
    void wireHappyPath() {
        org = new Organization("acme", 77L);
        repo = new TrackedRepository(org.id(), 101L, "acme/payment-service", "main");
        job = new ScanJob(repo.id(), "e7b4d1f", "main", 42, ScanTrigger.PR);
        finding = new Finding(job.id(), "fp", FindingType.SCA, Severity.CRITICAL, "Log4Shell");
        finding.describePackage("CVE-2021-44228",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "2.14.1", "2.15.0, 2.3.1, 2.12.2", DependencyScope.TRANSITIVE_RUNTIME);
        finding.locate("pom.xml", null);

        lenient().when(findings.findById(finding.id())).thenReturn(Optional.of(finding));
        lenient().when(scanJobs.findById(job.id())).thenReturn(Optional.of(job));
        lenient().when(repositories.findById(repo.id())).thenReturn(Optional.of(repo));
        lenient().when(organizations.findById(org.id())).thenReturn(Optional.of(org));
    }

    private UpgradePrService service() {
        return new UpgradePrService(findings, scanJobs, repositories, organizations,
                new ManifestPatcher(), github);
    }

    @Test
    void draftsABranchCommitAndDraftPrForAFixableFinding() {
        UpgradePrService.DraftedPr pr = service().draftUpgrade(finding.id());

        assertThat(pr.pullRequestUrl()).contains("/pull/43");
        assertThat(pr.branch()).startsWith("chainsentry/fix-cve-2021-44228-");
        assertThat(github.pushedContent)
                .contains("<version>2.15.0</version>") // first of Trivy's comma-separated fixes
                .doesNotContain("2.14.1");
        assertThat(github.calls).containsExactly(
                "fetch:pom.xml@main",
                "branch:" + pr.branch(),
                "push:pom.xml→" + pr.branch(),
                "pr:" + pr.branch() + "→main");
    }

    @Test
    void refusesFindingsWithoutAFixedVersion() {
        Finding unfixable = new Finding(job.id(), "fp2", FindingType.SCA, Severity.HIGH, "No fix yet");
        unfixable.describePackage("CVE-2099-1", "pkg:maven/x/y@1", "1", null, DependencyScope.DIRECT_RUNTIME);
        lenient().when(findings.findById(unfixable.id())).thenReturn(Optional.of(unfixable));

        assertThatThrownBy(() -> service().draftUpgrade(unfixable.id()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fixed version");
    }

    @Test
    void refusesNonManifestFiles() {
        Finding sourceFile = new Finding(job.id(), "fp3", FindingType.SCA, Severity.HIGH, "Odd location");
        sourceFile.describePackage("CVE-2099-2", "pkg:maven/x/y@1", "1", "2", DependencyScope.DIRECT_RUNTIME);
        sourceFile.locate("src/main/java/App.java", 10);
        lenient().when(findings.findById(sourceFile.id())).thenReturn(Optional.of(sourceFile));

        assertThatThrownBy(() -> service().draftUpgrade(sourceFile.id()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported manifest");
    }

    @Test
    void requiresAGitHubAppInstallation() {
        Organization orgWithoutApp = new Organization("acme", null);
        lenient().when(organizations.findById(org.id())).thenReturn(Optional.of(orgWithoutApp));
        lenient().when(repositories.findById(repo.id())).thenReturn(Optional.of(
                new TrackedRepository(org.id(), 101L, "acme/payment-service", "main")));

        assertThatThrownBy(() -> service().draftUpgrade(finding.id()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("installation");
    }

    @Test
    void nothingIsPushedWhenThePatcherCannotActUnambiguously() {
        Finding wrongPackage = new Finding(job.id(), "fp4", FindingType.SCA, Severity.HIGH, "Ghost");
        wrongPackage.describePackage("CVE-2099-3", "pkg:maven/org.yaml/snakeyaml@1.30",
                "1.30", "2.0", DependencyScope.DIRECT_RUNTIME);
        wrongPackage.locate("pom.xml", null);
        lenient().when(findings.findById(wrongPackage.id())).thenReturn(Optional.of(wrongPackage));

        assertThatThrownBy(() -> service().draftUpgrade(wrongPackage.id()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(github.calls).noneMatch(call -> call.startsWith("push:") || call.startsWith("pr:"));
    }
}
