package io.chainsentry.demo;

import io.chainsentry.scanner.RawReport;
import io.chainsentry.scanner.ScanContext;
import io.chainsentry.scanner.ScannerEngine;
import io.chainsentry.shared.model.ScannerType;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Replays recorded Trivy reports keyed by commit SHA. The rest of the
 * pipeline — normalization, dedup, risk scoring, gate — runs exactly as in
 * production; only the container execution is canned.
 */
@Component
@Profile("demo")
class FixtureScannerEngine implements ScannerEngine {

    private final DemoFixtures fixtures;

    FixtureScannerEngine(DemoFixtures fixtures) {
        this.fixtures = fixtures;
    }

    @Override
    public ScannerType type() {
        return ScannerType.TRIVY;
    }

    @Override
    public boolean supports(ScanContext context) {
        return true;
    }

    @Override
    public RawReport scan(ScanContext context) {
        Instant start = Instant.now();
        String payload = fixtures.trivyReport(context.commitSha());
        return new RawReport(ScannerType.TRIVY, "0.63.0 (recorded)", payload,
                Duration.between(start, Instant.now()));
    }
}
