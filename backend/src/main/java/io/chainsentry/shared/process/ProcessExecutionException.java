package io.chainsentry.shared.process;

/** A child process failed to start, timed out, or was interrupted. */
public class ProcessExecutionException extends Exception {

    public ProcessExecutionException(String message) {
        super(message);
    }

    public ProcessExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
