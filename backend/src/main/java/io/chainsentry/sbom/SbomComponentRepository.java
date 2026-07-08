package io.chainsentry.sbom;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SbomComponentRepository extends JpaRepository<SbomComponent, UUID> {

    List<SbomComponent> findBySbomId(UUID sbomId);
}
