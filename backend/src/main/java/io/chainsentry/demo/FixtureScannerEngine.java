package io.chainsentry.demo;

import io.chainsentry.scanner.RawReport;
import io.chainsentry.scanner.ScanContext;
import io.chainsentry.scanner.ScannerEngine;
import io.chainsentry.shared.model.ScannerType;

import java.time.Duration;
import java.time.Instant;

/**
 * Replays recorded engine reports keyed by commit SHA — one instance per
 * engine (see {@link DemoScannerConfig}). The rest of the pipeline —
 * normalization, cross-engine dedup, risk scoring, gate — runs exactly as in
 * production; only the container execution is canned.
 */
class FixtureScannerEngine implements ScannerEngine {

    private final ScannerType type;
    private final String recordedVersion;
    private final DemoFixtures fixtures;

    FixtureScannerEngine(ScannerType type, String recordedVersion, DemoFixtures fixtures) {
        this.type = type;
        this.recordedVersion = recordedVersion;
        this.fixtures = fixtures;
    }

    @Override
    public ScannerType type() {
        return type;
    }

    @Override
    public boolean supports(ScanContext context) {
        return true;
    }

    @Override
    public RawReport scan(ScanContext context) {
        Instant start = Instant.now();
        String payload = fixtures.report(type, context.commitSha());
        return new RawReport(type, recordedVersion + " (recorded)", payload,
                Duration.between(start, Instant.now()));
    }
}
