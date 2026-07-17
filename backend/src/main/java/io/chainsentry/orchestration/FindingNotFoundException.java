package io.chainsentry.orchestration;

import io.chainsentry.shared.web.ResourceNotFoundException;

import java.util.UUID;

public class FindingNotFoundException extends ResourceNotFoundException {

    public FindingNotFoundException(UUID findingId) {
        super("Unknown finding: " + findingId);
    }
}
