package io.chainsentry.remediation;

import io.chainsentry.github.Organization;
import io.chainsentry.github.OrganizationRepository;
import io.chainsentry.github.TrackedRepository;
import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.FindingNotFoundException;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.UUID;

/**
 * Drafts an upgrade PR for a fixable SCA finding. Guardrails are structural,
 * not prompt-based:
 * <ul>
 *   <li>only whitelisted manifests are ever written ({@link ManifestPatcher#SUPPORTED_MANIFESTS})</li>
 *   <li>the change is a single deterministic version-string replacement —
 *       refused when ambiguous, size-checked before pushing</li>
 *   <li>the PR is always a draft on a fresh branch; a human merges</li>
 * </ul>
 */
@Service
public class UpgradePrService {

    public record DraftedPr(UUID findingId, String branch, String pullRequestUrl) {
    }

    /** A version bump only ever grows the file by the version-string delta. */
    private static final int MAX_SIZE_DELTA = 64;

    private static final Logger log = LoggerFactory.getLogger(UpgradePrService.class);

    private final FindingRepository findings;
    private final ScanJobRepository scanJobs;
    private final TrackedRepositoryRepository repositories;
    private final OrganizationRepository organizations;
    private final ManifestPatcher patcher;
    private final GitHubContentsPort github;

    UpgradePrService(FindingRepository findings, ScanJobRepository scanJobs,
                     TrackedRepositoryRepository repositories, OrganizationRepository organizations,
                     ManifestPatcher patcher, GitHubContentsPort github) {
        this.findings = findings;
        this.scanJobs = scanJobs;
        this.repositories = repositories;
        this.organizations = organizations;
        this.patcher = patcher;
        this.github = github;
    }

    @Transactional(readOnly = true)
    public DraftedPr draftUpgrade(UUID findingId) {
        Finding finding = findings.findById(findingId)
                .orElseThrow(() -> new FindingNotFoundException(findingId));
        requireFixable(finding);

        TrackedRepository repo = scanJobs.findById(finding.scanJobId())
                .map(ScanJob::repositoryId)
                .flatMap(repositories::findById)
                .orElseThrow(() -> new IllegalStateException("Finding has no resolvable repository"));
        long installationId = organizations.findById(repo.organizationId())
                .map(Organization::githubInstallationId)
                .orElseThrow(() -> new IllegalStateException(
                        "Repository " + repo.fullName() + " has no GitHub App installation"));

        String manifest = finding.filePath();
        String fixedVersion = firstFixedVersion(finding);
        GitHubContentsPort.RepoFile file = github.fetchFile(installationId, repo.fullName(),
                manifest, repo.defaultBranch());
        String patched = patcher.patch(manifest, file.content(), finding.packageCoordinates(),
                finding.installedVersion(), fixedVersion)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Could not locate " + finding.packageCoordinates() + '@'
                                + finding.installedVersion() + " unambiguously in " + manifest));
        requireBoundedChange(file.content(), patched);

        String branch = branchName(finding);
        github.createBranch(installationId, repo.fullName(), branch,
                github.branchHeadSha(installationId, repo.fullName(), repo.defaultBranch()));
        github.updateFile(installationId, repo.fullName(), manifest, branch,
                commitMessage(finding, fixedVersion), patched, file.sha());
        String prUrl = github.openDraftPullRequest(installationId, repo.fullName(),
                prTitle(finding, fixedVersion), prBody(finding, fixedVersion), branch,
                repo.defaultBranch());
        log.info("Drafted upgrade PR for finding {} on {}: {}", findingId, repo.fullName(), prUrl);
        return new DraftedPr(findingId, branch, prUrl);
    }

    private void requireFixable(Finding finding) {
        if (finding.fixedVersion() == null || finding.packageCoordinates() == null) {
            throw new IllegalArgumentException(
                    "Only SCA findings with a known fixed version can get an upgrade PR");
        }
        if (finding.filePath() == null
                || !ManifestPatcher.SUPPORTED_MANIFESTS.contains(finding.filePath())) {
            throw new IllegalArgumentException("Unsupported manifest for automated upgrade: "
                    + finding.filePath() + " (supported: " + ManifestPatcher.SUPPORTED_MANIFESTS + ")");
        }
    }

    /** A version bump must never rewrite the file — a large delta means the patcher misbehaved. */
    private void requireBoundedChange(String original, String patched) {
        if (Math.abs(patched.length() - original.length()) > MAX_SIZE_DELTA) {
            throw new IllegalStateException("Refusing to push: patched manifest diverges too much");
        }
    }

    /** Trivy lists fix versions comma-separated ("2.15.0, 2.3.1"); take the first. */
    private String firstFixedVersion(Finding finding) {
        return finding.fixedVersion().split(",")[0].strip();
    }

    private String branchName(Finding finding) {
        String slug = (finding.vulnerabilityId() != null ? finding.vulnerabilityId() : "finding")
                .toLowerCase(Locale.ROOT);
        return "chainsentry/fix-" + slug + "-" + finding.id().toString().substring(0, 8);
    }

    private String commitMessage(Finding finding, String fixedVersion) {
        return "fix(deps): bump " + artifactLabel(finding) + " to " + fixedVersion
                + "\n\nResolves " + finding.vulnerabilityId() + " (" + finding.severity() + ").\n"
                + "Drafted by ChainSentry — review before merging.";
    }

    private String prTitle(Finding finding, String fixedVersion) {
        return "fix(deps): bump " + artifactLabel(finding) + " to " + fixedVersion
                + " (" + finding.vulnerabilityId() + ")";
    }

    private String prBody(Finding finding, String fixedVersion) {
        return "ChainSentry drafted this upgrade for **" + finding.vulnerabilityId() + "** ("
                + finding.severity() + ", risk score "
                + String.format("%.2f", finding.riskScoreOrZero()) + ").\n\n"
                + "| | |\n|---|---|\n"
                + "| Package | `" + finding.packageCoordinates() + "` |\n"
                + "| Installed | `" + finding.installedVersion() + "` |\n"
                + "| Fixed in | `" + fixedVersion + "` |\n\n"
                + "The change is a single version bump in `" + finding.filePath() + "` — "
                + "run your build and review before merging. This PR was opened as a draft "
                + "on purpose; ChainSentry never merges.";
    }

    private String artifactLabel(Finding finding) {
        String purl = finding.packageCoordinates();
        int at = purl.lastIndexOf('@');
        String withoutVersion = at > 0 ? purl.substring(0, at) : purl;
        int slash = withoutVersion.lastIndexOf('/');
        return slash >= 0 ? withoutVersion.substring(slash + 1) : withoutVersion;
    }
}
