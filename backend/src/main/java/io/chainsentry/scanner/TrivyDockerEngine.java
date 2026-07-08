package io.chainsentry.scanner;

import io.chainsentry.shared.config.ChainSentryProperties;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.process.ProcessExecutionException;
import io.chainsentry.shared.process.ProcessRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Runs the official Trivy image against the workspace (read-only mount,
 * filesystem mode, vulnerability scanners only). Requires a Docker daemon;
 * the demo profile swaps in a fixture engine instead.
 */
@Component
@Profile("!demo")
class TrivyDockerEngine implements ScannerEngine {

    private final ProcessRunner processRunner;
    private final ChainSentryProperties properties;

    TrivyDockerEngine(ProcessRunner processRunner, ChainSentryProperties properties) {
        this.processRunner = processRunner;
        this.properties = properties;
    }

    @Override
    public ScannerType type() {
        return ScannerType.TRIVY;
    }

    @Override
    public boolean supports(ScanContext context) {
        return true; // filesystem scan applies to every workspace
    }

    @Override
    public RawReport scan(ScanContext context) throws ScannerExecutionException {
        String image = properties.scanner().images().get("trivy");
        List<String> command = List.of(
                "docker", "run", "--rm",
                "-v", context.workspace().toAbsolutePath() + ":/workspace:ro",
                image,
                "fs", "--format", "json", "--quiet", "--scanners", "vuln", "--list-all-pkgs",
                "/workspace");
        Instant start = Instant.now();
        ProcessRunner.ProcessResult result = execute(command, context.timeout());
        if (!result.succeeded()) {
            throw new ScannerExecutionException(ScannerType.TRIVY,
                    "exit " + result.exitCode() + ": " + tail(result.stderr()), null);
        }
        return new RawReport(ScannerType.TRIVY, image, result.stdout(), Duration.between(start, Instant.now()));
    }

    private ProcessRunner.ProcessResult execute(List<String> command, Duration timeout)
            throws ScannerExecutionException {
        try {
            return processRunner.run(command, null, timeout);
        } catch (ProcessExecutionException e) {
            throw new ScannerExecutionException(ScannerType.TRIVY, e.getMessage(), e);
        }
    }

    private String tail(String stderr) {
        String stripped = stderr.strip();
        return stripped.length() <= 500 ? stripped : stripped.substring(stripped.length() - 500);
    }
}
