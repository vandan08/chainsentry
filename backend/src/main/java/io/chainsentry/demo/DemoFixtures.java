package io.chainsentry.demo;

import io.chainsentry.shared.model.ScannerType;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The demo profile's canned world: two commits of {@code acme/payment-service}.
 * The base commit carries a couple of unexciting findings; the head commit is
 * a PR that pulls in log4j-core 2.14.1 — the money demo.
 */
@Component
@Profile("demo")
public class DemoFixtures {

    /** main before the PR. */
    public static final String BASE_COMMIT = "a3f8c2d94b7e1a5c8f2b6d0e9a4c7b3f5d8e1a2c";
    /** head of PR #42 ("add audit logging" — and, accidentally, Log4Shell). */
    public static final String HEAD_COMMIT = "e7b4d1f82c9a6e3b5d0f8c2a7e4b9d1c6f3a8e5b";

    private static final Map<ScannerType, Map<String, String>> REPORTS = Map.of(
            ScannerType.TRIVY, Map.of(
                    BASE_COMMIT, "demo/trivy-report-base.json",
                    HEAD_COMMIT, "demo/trivy-report-head.json"),
            ScannerType.SEMGREP, Map.of(
                    BASE_COMMIT, "demo/semgrep-report-base.json",
                    HEAD_COMMIT, "demo/semgrep-report-head.json"),
            ScannerType.DEPENDENCY_CHECK, Map.of(
                    BASE_COMMIT, "demo/dependency-check-report-base.json",
                    HEAD_COMMIT, "demo/dependency-check-report-head.json"));

    private static final Map<String, String> SBOMS = Map.of(
            BASE_COMMIT, "demo/sbom-base.json",
            HEAD_COMMIT, "demo/sbom-head.json");

    public String report(ScannerType engine, String commitSha) {
        return load(REPORTS.get(engine), commitSha);
    }

    public String sbom(String commitSha) {
        return load(SBOMS, commitSha);
    }

    public String vulnerabilitySnapshot() {
        return read("demo/vulnerability-snapshot.json");
    }

    private String load(Map<String, String> byCommit, String commitSha) {
        String resource = byCommit.get(commitSha);
        if (resource == null) {
            throw new IllegalArgumentException(
                    "Demo mode only knows commits " + BASE_COMMIT + " and " + HEAD_COMMIT + ", got " + commitSha);
        }
        return read(resource);
    }

    private String read(String resource) {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing demo fixture on classpath: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read demo fixture " + resource, e);
        }
    }
}
