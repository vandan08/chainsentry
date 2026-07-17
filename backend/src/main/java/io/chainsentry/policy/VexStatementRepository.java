package io.chainsentry.policy;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface VexStatementRepository extends JpaRepository<VexStatement, UUID> {

    List<VexStatement> findBySuppressionIdIn(Collection<UUID> suppressionIds);
}
