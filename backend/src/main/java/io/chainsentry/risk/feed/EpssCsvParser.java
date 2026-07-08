package io.chainsentry.risk.feed;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Parses the daily EPSS scores CSV ({@code cve,epss,percentile} rows preceded
 * by {@code #}-comment and header lines). Streams line by line — the full
 * file covers ~290k CVEs.
 */
@Component
public class EpssCsvParser {

    public Map<String, BigDecimal> parse(InputStream csv) {
        Map<String, BigDecimal> scores = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(csv, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#") || line.startsWith("cve,")) {
                    continue;
                }
                String[] parts = line.split(",");
                if (parts.length < 2) {
                    continue;
                }
                try {
                    scores.put(parts[0].strip(), new BigDecimal(parts[1].strip()));
                } catch (NumberFormatException e) {
                    // malformed row — skip, never fail the whole sync
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed reading EPSS CSV", e);
        }
        return scores;
    }
}
