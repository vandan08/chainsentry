package io.chainsentry.remediation;

import io.chainsentry.github.TrackedRepositoryRepository;
import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.orchestration.FindingNotFoundException;
import io.chainsentry.orchestration.ScanJob;
import io.chainsentry.orchestration.ScanJobRepository;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * "Explain this finding": assembles the context ChainSentry already has
 * (finding, exploitation feeds, repo) and asks Claude for the contextual
 * explanation a security engineer would give. On-demand, nothing persisted —
 * the data it summarizes is already in the database.
 */
@Service
public class FindingExplanationService {

    public record Explanation(UUID findingId, String explanation, String model) {
    }

    private final FindingRepository findings;
    private final ScanJobRepository scanJobs;
    private final TrackedRepositoryRepository repositories;
    private final VulnerabilityRepository vulnerabilities;
    private final ExplanationPromptFactory promptFactory;
    private final ClaudeClient claude;

    FindingExplanationService(FindingRepository findings, ScanJobRepository scanJobs,
                              TrackedRepositoryRepository repositories,
                              VulnerabilityRepository vulnerabilities,
                              ExplanationPromptFactory promptFactory, ClaudeClient claude) {
        this.findings = findings;
        this.scanJobs = scanJobs;
        this.repositories = repositories;
        this.vulnerabilities = vulnerabilities;
        this.promptFactory = promptFactory;
        this.claude = claude;
    }

    @Transactional(readOnly = true)
    public Explanation explain(UUID findingId) {
        Finding finding = findings.findById(findingId)
                .orElseThrow(() -> new FindingNotFoundException(findingId));
        String repoFullName = scanJobs.findById(finding.scanJobId())
                .map(ScanJob::repositoryId)
                .flatMap(repositories::findById)
                .map(repo -> repo.fullName())
                .orElse("unknown repository");
        Vulnerability vulnerability = finding.vulnerabilityId() != null
                ? vulnerabilities.findById(finding.vulnerabilityId()).orElse(null)
                : null;
        String explanation = claude.complete(ExplanationPromptFactory.SYSTEM,
                promptFactory.userPrompt(finding, vulnerability, repoFullName));
        return new Explanation(findingId, explanation, claude.model());
    }
}
