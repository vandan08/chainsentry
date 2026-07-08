package io.chainsentry.orchestration;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ScannerRunRepository extends JpaRepository<ScannerRun, UUID> {

    List<ScannerRun> findByScanJobId(UUID scanJobId);
}
