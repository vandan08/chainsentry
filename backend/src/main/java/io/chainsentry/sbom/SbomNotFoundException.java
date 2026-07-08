package io.chainsentry.sbom;

import io.chainsentry.shared.web.ResourceNotFoundException;

import java.util.UUID;

/** No SBOM stored for the given scan (scan may have failed before SBOM generation). */
public class SbomNotFoundException extends ResourceNotFoundException {

    public SbomNotFoundException(UUID scanJobId) {
        super("No SBOM stored for scan " + scanJobId);
    }
}
