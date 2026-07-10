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
 * Runs the official Semgrep image against the workspace (read-only mount,
 * registry rules via {@code --config auto}, metrics off). Exit code 1 means
 * "findings exist", not failure — only 2+ signals a broken run.
 */
@Component
@Profile("!demo")
class SemgrepDockerEngine implements ScannerEngine {

    private final ProcessRunner processRunner;
    private final ChainSentryProperties properties;

    SemgrepDockerEngine(ProcessRunner processRunner, ChainSentryProperties properties) {
        this.processRunner = processRunner;
        this.properties = properties;
    }

    @Override
    public ScannerType type() {
        return ScannerType.SEMGREP;
    }

    @Override
    public boolean supports(ScanContext context) {
        return true; // every cloned workspace has source files to lint
    }

    @Override
    public RawReport scan(ScanContext context) throws ScannerExecutionException {
        String image = properties.scanner().images().get("semgrep");
        List<String> command = List.of(
                "docker", "run", "--rm",
                "-v", context.workspace().toAbsolutePath() + ":/src:ro",
                image,
                "semgrep", "scan", "--config", "auto", "--json", "--quiet", "--metrics", "off",
                "/src");
        Instant start = Instant.now();
        ProcessRunner.ProcessResult result = execute(command, context.timeout());
        if (result.exitCode() > 1) {
            throw new ScannerExecutionException(ScannerType.SEMGREP,
                    "exit " + result.exitCode() + ": " + tail(result.stderr()), null);
        }
        return new RawReport(ScannerType.SEMGREP, image, result.stdout(), Duration.between(start, Instant.now()));
    }

    private ProcessRunner.ProcessResult execute(List<String> command, Duration timeout)
            throws ScannerExecutionException {
        try {
            return processRunner.run(command, null, timeout);
        } catch (ProcessExecutionException e) {
            throw new ScannerExecutionException(ScannerType.SEMGREP, e.getMessage(), e);
        }
    }

    private String tail(String stderr) {
        String stripped = stderr.strip();
        return stripped.length() <= 500 ? stripped : stripped.substring(stripped.length() - 500);
    }
}
