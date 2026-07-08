package io.chainsentry.github;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A repository ChainSentry watches. Named {@code TrackedRepository} to avoid
 * the inevitable collision with Spring Data's {@code Repository}. Foreign keys
 * are plain UUIDs (no JPA associations) so modules stay decoupled and each
 * aggregate loads independently.
 */
@Entity
@Table(name = "repository")
public class TrackedRepository {

    @Id
    private UUID id;

    @Column(name = "organization_id", nullable = false)
    private UUID organizationId;

    @Column(name = "github_repo_id", nullable = false, unique = true)
    private Long githubRepoId;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "default_branch", nullable = false)
    private String defaultBranch;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected TrackedRepository() {
        // JPA
    }

    public TrackedRepository(UUID organizationId, Long githubRepoId, String fullName, String defaultBranch) {
        this.id = UUID.randomUUID();
        this.organizationId = organizationId;
        this.githubRepoId = githubRepoId;
        this.fullName = fullName;
        this.defaultBranch = defaultBranch;
        this.createdAt = Instant.now();
    }

    public UUID id() {
        return id;
    }

    public UUID organizationId() {
        return organizationId;
    }

    public Long githubRepoId() {
        return githubRepoId;
    }

    public String fullName() {
        return fullName;
    }

    public String defaultBranch() {
        return defaultBranch;
    }

    /** HTTPS clone URL derived from the full name — no credentials, public repos only for now. */
    public String cloneUrl() {
        return "https://github.com/" + fullName + ".git";
    }
}
