package io.chainsentry.demo;

import io.chainsentry.shared.model.ScannerType;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The demo profile's canned world. Two recorded report sets exist — a
 * {@link Flavor#CLEAN} commit carrying a couple of unexciting findings, and a
 * {@link Flavor#VULNERABLE} one that pulls in log4j-core 2.14.1 (the money
 * demo) — and every seeded commit is mapped onto one of them.
 *
 * <p>{@link #BASE_COMMIT} and {@link #HEAD_COMMIT} are the two canonical
 * commits of {@code acme/payment-service}; {@link DemoDataLoader} registers
 * further commits so repositories can have a scan history rather than a single
 * before/after pair.
 */
@Component
@Profile("demo")
public class DemoFixtures {

    /** Which recorded report set a commit replays. */
    public enum Flavor { CLEAN, VULNERABLE }

    /** main before the PR. */
    public static final String BASE_COMMIT = "a3f8c2d94b7e1a5c8f2b6d0e9a4c7b3f5d8e1a2c";
    /** head of PR #42 ("add audit logging" — and, accidentally, Log4Shell). */
    public static final String HEAD_COMMIT = "e7b4d1f82c9a6e3b5d0f8c2a7e4b9d1c6f3a8e5b";

    private static final Map<ScannerType, Map<Flavor, String>> REPORTS = Map.of(
            ScannerType.TRIVY, Map.of(
                    Flavor.CLEAN, "demo/trivy-report-base.json",
                    Flavor.VULNERABLE, "demo/trivy-report-head.json"),
            ScannerType.SEMGREP, Map.of(
                    Flavor.CLEAN, "demo/semgrep-report-base.json",
                    Flavor.VULNERABLE, "demo/semgrep-report-head.json"),
            ScannerType.DEPENDENCY_CHECK, Map.of(
                    Flavor.CLEAN, "demo/dependency-check-report-base.json",
                    Flavor.VULNERABLE, "demo/dependency-check-report-head.json"));

    private static final Map<Flavor, String> SBOMS = Map.of(
            Flavor.CLEAN, "demo/sbom-base.json",
            Flavor.VULNERABLE, "demo/sbom-head.json");

    private final Map<String, Flavor> flavorByCommit = new ConcurrentHashMap<>(Map.of(
            BASE_COMMIT, Flavor.CLEAN,
            HEAD_COMMIT, Flavor.VULNERABLE));

    /** Points a seeded commit at one of the recorded report sets. */
    public void register(String commitSha, Flavor flavor) {
        flavorByCommit.put(commitSha, flavor);
    }

    public String report(ScannerType engine, String commitSha) {
        return read(REPORTS.get(engine).get(flavorOf(commitSha)));
    }

    public String sbom(String commitSha) {
        return read(SBOMS.get(flavorOf(commitSha)));
    }

    public String vulnerabilitySnapshot() {
        return read("demo/vulnerability-snapshot.json");
    }

    private Flavor flavorOf(String commitSha) {
        Flavor flavor = flavorByCommit.get(commitSha);
        if (flavor == null) {
            throw new IllegalArgumentException("Demo mode has no recorded reports for commit " + commitSha);
        }
        return flavor;
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
