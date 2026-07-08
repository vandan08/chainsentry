package io.chainsentry.scanner;

import io.chainsentry.shared.config.ChainSentryProperties;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.process.ProcessExecutionException;
import io.chainsentry.shared.process.ProcessRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

/** Second Trivy invocation per scan: same workspace, CycloneDX output. */
@Component
@Profile("!demo")
class TrivyDockerSbomGenerator implements SbomGenerator {

    private final ProcessRunner processRunner;
    private final ChainSentryProperties properties;

    TrivyDockerSbomGenerator(ProcessRunner processRunner, ChainSentryProperties properties) {
        this.processRunner = processRunner;
        this.properties = properties;
    }

    @Override
    public String generate(ScanContext context) throws ScannerExecutionException {
        String image = properties.scanner().images().get("trivy");
        List<String> command = List.of(
                "docker", "run", "--rm",
                "-v", context.workspace().toAbsolutePath() + ":/workspace:ro",
                image,
                "fs", "--format", "cyclonedx", "--quiet",
                "/workspace");
        try {
            ProcessRunner.ProcessResult result = processRunner.run(command, null, context.timeout());
            if (!result.succeeded()) {
                throw new ScannerExecutionException(ScannerType.TRIVY,
                        "SBOM generation exit " + result.exitCode(), null);
            }
            return result.stdout();
        } catch (ProcessExecutionException e) {
            throw new ScannerExecutionException(ScannerType.TRIVY, e.getMessage(), e);
        }
    }
}
