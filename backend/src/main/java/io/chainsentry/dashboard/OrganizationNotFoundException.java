package io.chainsentry.dashboard;

import io.chainsentry.shared.web.ResourceNotFoundException;

import java.util.UUID;

public class OrganizationNotFoundException extends ResourceNotFoundException {

    public OrganizationNotFoundException(UUID organizationId) {
        super("Unknown organization: " + organizationId);
    }
}
