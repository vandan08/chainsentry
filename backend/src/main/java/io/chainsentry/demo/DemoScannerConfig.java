package io.chainsentry.demo;

import io.chainsentry.scanner.ScannerEngine;
import io.chainsentry.shared.model.ScannerType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * The demo profile's engine fleet: all three engines replay recorded
 * reports, so the dashboard shows the same CVE arriving from Trivy and
 * Dependency-Check collapsing into one finding — the Phase 2 demo.
 */
@Configuration
@Profile("demo")
class DemoScannerConfig {

    @Bean
    ScannerEngine fixtureTrivyEngine(DemoFixtures fixtures) {
        return new FixtureScannerEngine(ScannerType.TRIVY, "0.63.0", fixtures);
    }

    @Bean
    ScannerEngine fixtureSemgrepEngine(DemoFixtures fixtures) {
        return new FixtureScannerEngine(ScannerType.SEMGREP, "1.99.0", fixtures);
    }

    @Bean
    ScannerEngine fixtureDependencyCheckEngine(DemoFixtures fixtures) {
        return new FixtureScannerEngine(ScannerType.DEPENDENCY_CHECK, "12.1.0", fixtures);
    }
}
