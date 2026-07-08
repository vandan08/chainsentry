package io.chainsentry.demo;

import io.chainsentry.scanner.ScanContext;
import io.chainsentry.scanner.SbomGenerator;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Recorded CycloneDX documents for the two demo commits. */
@Component
@Profile("demo")
class FixtureSbomGenerator implements SbomGenerator {

    private final DemoFixtures fixtures;

    FixtureSbomGenerator(DemoFixtures fixtures) {
        this.fixtures = fixtures;
    }

    @Override
    public String generate(ScanContext context) {
        return fixtures.sbom(context.commitSha());
    }
}
