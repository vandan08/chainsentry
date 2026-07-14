package io.chainsentry.github;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface TrackedRepositoryRepository extends JpaRepository<TrackedRepository, UUID> {

    Optional<TrackedRepository> findByFullName(String fullName);

    Optional<TrackedRepository> findByGithubRepoId(Long githubRepoId);
}
