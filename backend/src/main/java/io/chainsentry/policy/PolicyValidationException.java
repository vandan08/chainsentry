package io.chainsentry.policy;

/** A chainsentry.yml that cannot be turned into rules; surfaces as 400 via the shared advice. */
public class PolicyValidationException extends IllegalArgumentException {

    public PolicyValidationException(String message) {
        super(message);
    }
}
