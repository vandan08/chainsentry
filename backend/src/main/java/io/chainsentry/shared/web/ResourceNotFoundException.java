package io.chainsentry.shared.web;

/** Base for module-specific not-found exceptions; mapped to 404 problem detail. */
public abstract class ResourceNotFoundException extends RuntimeException {

    protected ResourceNotFoundException(String message) {
        super(message);
    }
}
