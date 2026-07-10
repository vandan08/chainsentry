package io.chainsentry.scanner;

import io.chainsentry.shared.config.ChainSentryProperties;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.process.ProcessExecutionException;
import io.chainsentry.shared.process.ProcessRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Runs OWASP Dependency-Check against the workspace. Unlike Trivy/Semgrep,
 * DC writes its report to a directory instead of stdout, so a temp dir is
 * mounted read-write at {@code /report} and the JSON read back afterwards.
 *
 * <p>Operational note: DC keeps its NVD database in {@code /usr/share/dependency-check/data};
 * production deployments should mount a named volume there and configure an
 * NVD API key, or the first run spends ~20 min downloading the CVE corpus.
 */
@Component
@Profile("!demo")
class DependencyCheckDockerEngine implements ScannerEngine {

    private static final String REPORT_FILE = "dependency-check-report.json";

    private final ProcessRunner processRunner;
    private final ChainSentryProperties properties;

    DependencyCheckDockerEngine(ProcessRunner processRunner, ChainSentryProperties properties) {
        this.processRunner = processRunner;
        this.properties = properties;
    }

    @Override
    public ScannerType type() {
        return ScannerType.DEPENDENCY_CHECK;
    }

    @Override
    public boolean supports(ScanContext context) {
        return true; // manifest discovery is DC's own job
    }

    @Override
    public RawReport scan(ScanContext context) throws ScannerExecutionException {
        String image = properties.scanner().images().get("dependency-check");
        Path reportDir = createReportDir();
        try {
            List<String> command = List.of(
                    "docker", "run", "--rm",
                    "-v", context.workspace().toAbsolutePath() + ":/src:ro",
                    "-v", reportDir.toAbsolutePath() + ":/report",
                    image,
                    "--scan", "/src", "--format", "JSON", "--out", "/report",
                    "--project", context.scanJobId().toString());
            Instant start = Instant.now();
            ProcessRunner.ProcessResult result = execute(command, context.timeout());
            if (!result.succeeded()) {
                throw new ScannerExecutionException(ScannerType.DEPENDENCY_CHECK,
                        "exit " + result.exitCode() + ": " + tail(result.stderr()), null);
            }
            return new RawReport(ScannerType.DEPENDENCY_CHECK, image, readReport(reportDir),
                    Duration.between(start, Instant.now()));
        } finally {
            deleteRecursively(reportDir);
        }
    }

    private Path createReportDir() throws ScannerExecutionException {
        try {
            return Files.createTempDirectory("chainsentry-depcheck-");
        } catch (IOException e) {
            throw new ScannerExecutionException(ScannerType.DEPENDENCY_CHECK,
                    "Could not create report directory", e);
        }
    }

    private String readReport(Path reportDir) throws ScannerExecutionException {
        try {
            return Files.readString(reportDir.resolve(REPORT_FILE));
        } catch (IOException e) {
            throw new ScannerExecutionException(ScannerType.DEPENDENCY_CHECK,
                    "Engine exited 0 but wrote no " + REPORT_FILE, e);
        }
    }

    private ProcessRunner.ProcessResult execute(List<String> command, Duration timeout)
            throws ScannerExecutionException {
        try {
            return processRunner.run(command, null, timeout);
        } catch (ProcessExecutionException e) {
            throw new ScannerExecutionException(ScannerType.DEPENDENCY_CHECK, e.getMessage(), e);
        }
    }

    private void deleteRecursively(Path dir) {
        try (Stream<Path> tree = Files.walk(dir)) {
            tree.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException e) {
            // best effort — temp dirs are reaped by the OS eventually
        }
    }

    private String tail(String stderr) {
        String stripped = stderr.strip();
        return stripped.length() <= 500 ? stripped : stripped.substring(stripped.length() - 500);
    }
}
