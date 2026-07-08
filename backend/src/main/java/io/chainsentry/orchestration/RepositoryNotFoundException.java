package io.chainsentry.orchestration;

import io.chainsentry.shared.web.ResourceNotFoundException;

import java.util.UUID;

public class RepositoryNotFoundException extends ResourceNotFoundException {

    public RepositoryNotFoundException(UUID repositoryId) {
        super("Unknown repository: " + repositoryId);
    }
}
