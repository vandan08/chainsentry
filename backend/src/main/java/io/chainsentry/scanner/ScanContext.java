package io.chainsentry.scanner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;

/**
 * Everything an engine adapter needs to run one scan.
 *
 * @param scanJobId      owning scan job
 * @param workspace      checked-out repository (mounted read-only into the engine container)
 * @param containerImage optional container image reference to scan (Trivy image mode), may be null
 * @param timeout        hard per-engine timeout enforced by the adapter
 */
public record ScanContext(
        UUID scanJobId,
        Path workspace,
        String containerImage,
        Duration timeout
) {
    public static ScanContext forWorkspace(UUID scanJobId, Path workspace) {
        return new ScanContext(scanJobId, workspace, null, Duration.ofMinutes(10));
    }
}
