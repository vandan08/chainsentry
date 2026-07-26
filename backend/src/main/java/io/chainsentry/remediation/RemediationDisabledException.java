package io.chainsentry.remediation;

/** Thrown when AI remediation is invoked without an Anthropic API key configured; maps to 503. */
public class RemediationDisabledException extends RuntimeException {

    public RemediationDisabledException() {
        super("AI remediation is not configured (chainsentry.remediation.anthropic-api-key "
                + "in application-local.yml)");
    }
}
