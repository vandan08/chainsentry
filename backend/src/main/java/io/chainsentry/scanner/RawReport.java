package io.chainsentry.scanner;

import io.chainsentry.shared.model.ScannerType;

import java.time.Duration;

/**
 * Unparsed engine output plus execution metadata. The normalization module
 * turns this into unified findings; the raw payload is also persisted
 * (JSONB) for auditability and normalization regression tests.
 */
public record RawReport(
        ScannerType engine,
        String engineVersion,
        String payload,
        Duration executionTime
) {
}
