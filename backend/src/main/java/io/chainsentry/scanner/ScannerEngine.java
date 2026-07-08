package io.chainsentry.scanner;

import io.chainsentry.shared.model.ScannerType;

/**
 * SPI implemented by every scanner engine adapter (Trivy, Semgrep,
 * Dependency-Check). Adapters launch the official engine container against a
 * read-only workspace mount with CPU/memory limits and a hard timeout, and
 * hand the raw report to the normalization module untouched — parsing raw
 * output is deliberately not the adapter's job.
 */
public interface ScannerEngine {

    ScannerType type();

    /** Whether this engine applies to the given workspace (e.g. Semgrep needs source files). */
    boolean supports(ScanContext context);

    /**
     * Run the engine. Blocking by design — the orchestrator invokes each
     * engine on its own virtual thread.
     *
     * @throws ScannerExecutionException on non-zero exit, timeout, or container failure
     */
    RawReport scan(ScanContext context) throws ScannerExecutionException;
}
