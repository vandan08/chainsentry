package io.chainsentry.orchestration;

/** Workspace preparation failed (clone error, disk, permissions). */
public class WorkspaceException extends Exception {

    public WorkspaceException(String message) {
        super(message);
    }

    public WorkspaceException(String message, Throwable cause) {
        super(message, cause);
    }
}
