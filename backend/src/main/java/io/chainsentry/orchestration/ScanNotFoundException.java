package io.chainsentry.orchestration;

import io.chainsentry.shared.web.ResourceNotFoundException;

import java.util.UUID;

public class ScanNotFoundException extends ResourceNotFoundException {

    public ScanNotFoundException(UUID scanJobId) {
        super("Unknown scan: " + scanJobId);
    }
}
