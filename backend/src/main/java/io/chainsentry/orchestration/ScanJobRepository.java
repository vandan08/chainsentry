package io.chainsentry.orchestration;

import io.chainsentry.shared.model.ScanTrigger;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ScanJobRepository extends JpaRepository<ScanJob, UUID> {

    Optional<ScanJob> findByRepositoryIdAndCommitShaAndTrigger(UUID repositoryId, String commitSha, ScanTrigger trigger);

    List<ScanJob> findByRepositoryIdOrderByCreatedAtDesc(UUID repositoryId);
}
