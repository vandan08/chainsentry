package io.chainsentry.orchestration;

import io.chainsentry.shared.process.ProcessExecutionException;
import io.chainsentry.shared.process.ProcessRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Shallow-clones the repository into a fresh temp directory. Depth 1 — the
 * scanners only need the tree, not the history.
 */
@Component
@Profile("!demo")
class GitWorkspaceProvider implements WorkspaceProvider {

    private static final Logger log = LoggerFactory.getLogger(GitWorkspaceProvider.class);
    private static final Duration CLONE_TIMEOUT = Duration.ofMinutes(5);

    private final ProcessRunner processRunner;

    GitWorkspaceProvider(ProcessRunner processRunner) {
        this.processRunner = processRunner;
    }

    @Override
    public Path prepare(String cloneUrl, String reference) throws WorkspaceException {
        Path workspace = createTempDirectory();
        List<String> command = new ArrayList<>(List.of("git", "clone", "--depth", "1"));
        if (reference != null && !reference.isBlank()) {
            command.addAll(List.of("--branch", reference));
        }
        command.addAll(List.of(cloneUrl, workspace.toString()));
        try {
            ProcessRunner.ProcessResult result = processRunner.run(command, null, CLONE_TIMEOUT);
            if (!result.succeeded()) {
                cleanup(workspace);
                throw new WorkspaceException("git clone failed: " + result.stderr().strip());
            }
        } catch (ProcessExecutionException e) {
            cleanup(workspace);
            throw new WorkspaceException("git clone failed", e);
        }
        return workspace;
    }

    @Override
    public void cleanup(Path workspace) {
        try (Stream<Path> tree = Files.walk(workspace)) {
            tree.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    // best effort — leaked temp dirs are logged, not fatal
                    log.warn("Could not delete {}", path);
                }
            });
        } catch (IOException e) {
            log.warn("Workspace cleanup failed for {}", workspace, e);
        }
    }

    private Path createTempDirectory() throws WorkspaceException {
        try {
            return Files.createTempDirectory("chainsentry-scan-");
        } catch (IOException e) {
            throw new WorkspaceException("Could not create scan workspace", e);
        }
    }
}
