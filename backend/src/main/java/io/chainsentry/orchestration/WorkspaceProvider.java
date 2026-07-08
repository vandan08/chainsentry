package io.chainsentry.orchestration;

import java.nio.file.Path;

/** Provides the ephemeral directory a scan runs against, and disposes of it afterwards. */
public interface WorkspaceProvider {

    /**
     * @param cloneUrl  where the code lives
     * @param reference branch/tag to check out; null means the remote default
     */
    Path prepare(String cloneUrl, String reference) throws WorkspaceException;

    void cleanup(Path workspace);
}
