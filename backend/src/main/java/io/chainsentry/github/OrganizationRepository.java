package io.chainsentry.github;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface OrganizationRepository extends JpaRepository<Organization, UUID> {

    Optional<Organization> findByLogin(String login);

    Optional<Organization> findByGithubInstallationId(Long githubInstallationId);
}
