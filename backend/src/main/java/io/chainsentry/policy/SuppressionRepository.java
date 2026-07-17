package io.chainsentry.policy;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public interface SuppressionRepository extends JpaRepository<Suppression, UUID> {

    /** Unexpired suppressions: {@code expiresOn} strictly after the given day. */
    List<Suppression> findByRepositoryIdAndExpiresOnAfter(UUID repositoryId, LocalDate date);
}
