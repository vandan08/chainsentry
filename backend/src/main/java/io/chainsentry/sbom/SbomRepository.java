package io.chainsentry.sbom;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface SbomRepository extends JpaRepository<Sbom, UUID> {

    Optional<Sbom> findByScanJobId(UUID scanJobId);
}
