package io.chainsentry.shared.process;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Small wrapper around ProcessBuilder used for engine containers and git.
 * Streams are drained on virtual threads while the process runs — engine
 * reports are megabytes, and a full pipe buffer would deadlock the child.
 */
@Component
public class ProcessRunner {

    public record ProcessResult(int exitCode, String stdout, String stderr) {

        public boolean succeeded() {
            return exitCode == 0;
        }
    }

    public ProcessResult run(List<String> command, Path workingDirectory, Duration timeout)
            throws ProcessExecutionException {
        ProcessBuilder builder = new ProcessBuilder(command);
        if (workingDirectory != null) {
            builder.directory(workingDirectory.toFile());
        }
        try {
            Process process = builder.start();
            AtomicReference<String> stdout = new AtomicReference<>("");
            AtomicReference<String> stderr = new AtomicReference<>("");
            Thread stdoutDrain = Thread.startVirtualThread(() -> stdout.set(readFully(process.getInputStream())));
            Thread stderrDrain = Thread.startVirtualThread(() -> stderr.set(readFully(process.getErrorStream())));

            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new ProcessExecutionException(
                        "Timed out after " + timeout + ": " + String.join(" ", command));
            }
            stdoutDrain.join();
            stderrDrain.join();
            return new ProcessResult(process.exitValue(), stdout.get(), stderr.get());
        } catch (IOException e) {
            throw new ProcessExecutionException("Failed to start: " + String.join(" ", command), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ProcessExecutionException("Interrupted while running: " + String.join(" ", command), e);
        }
    }

    private String readFully(InputStream stream) {
        try (stream) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
