package io.chainsentry.normalization;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findByScanJobIdOrderByRiskScoreDesc(UUID scanJobId);
}
