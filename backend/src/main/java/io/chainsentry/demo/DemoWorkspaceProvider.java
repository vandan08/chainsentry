package io.chainsentry.demo;

import io.chainsentry.orchestration.WorkspaceException;
import io.chainsentry.orchestration.WorkspaceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** No clone in demo mode — engines are fixture-backed, so an empty dir suffices. */
@Component
@Profile("demo")
class DemoWorkspaceProvider implements WorkspaceProvider {

    private static final Logger log = LoggerFactory.getLogger(DemoWorkspaceProvider.class);

    @Override
    public Path prepare(String cloneUrl, String reference) throws WorkspaceException {
        try {
            return Files.createTempDirectory("chainsentry-demo-");
        } catch (IOException e) {
            throw new WorkspaceException("Could not create demo workspace", e);
        }
    }

    @Override
    public void cleanup(Path workspace) {
        try {
            Files.deleteIfExists(workspace);
        } catch (IOException e) {
            log.warn("Could not delete demo workspace {}", workspace);
        }
    }
}
