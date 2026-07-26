package io.chainsentry.remediation;

/**
 * The narrow slice of the GitHub API the upgrade-PR drafter needs. A port so
 * the drafting logic (and its guardrails) is testable without HTTP.
 */
interface GitHubContentsPort {

    record RepoFile(String content, String sha) {
    }

    RepoFile fetchFile(long installationId, String repoFullName, String path, String ref);

    String branchHeadSha(long installationId, String repoFullName, String branch);

    void createBranch(long installationId, String repoFullName, String branchName, String fromSha);

    void updateFile(long installationId, String repoFullName, String path, String branch,
                    String commitMessage, String newContent, String previousSha);

    /** Always opens the PR as a draft — the guardrail lives in the signature. */
    String openDraftPullRequest(long installationId, String repoFullName, String title, String body,
                                String headBranch, String baseBranch);
}
