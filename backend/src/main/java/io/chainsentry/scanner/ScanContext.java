package io.chainsentry.scanner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;

/**
 * Everything an engine adapter needs to run one scan.
 *
 * @param scanJobId      owning scan job
 * @param commitSha      commit under scan (fixture engines key on it; container engines ignore it)
 * @param workspace      checked-out repository (mounted read-only into the engine container)
 * @param containerImage optional container image reference to scan (Trivy image mode), may be null
 * @param timeout        hard per-engine timeout enforced by the adapter
 */
public record ScanContext(
        UUID scanJobId,
        String commitSha,
        Path workspace,
        String containerImage,
        Duration timeout
) {
    public static ScanContext forWorkspace(UUID scanJobId, String commitSha, Path workspace, Duration timeout) {
        return new ScanContext(scanJobId, commitSha, workspace, null, timeout);
    }
}
