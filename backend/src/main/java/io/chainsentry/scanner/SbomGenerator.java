package io.chainsentry.scanner;

/**
 * Produces the CycloneDX SBOM for a workspace — a separate engine invocation
 * from vulnerability scanning, kept behind its own seam so demo mode and
 * future generators (Syft, native Maven plugin) swap in cleanly.
 */
public interface SbomGenerator {

    /** @return CycloneDX JSON document */
    String generate(ScanContext context) throws ScannerExecutionException;
}
