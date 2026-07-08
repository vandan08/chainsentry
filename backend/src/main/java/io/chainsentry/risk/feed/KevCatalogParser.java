package io.chainsentry.risk.feed;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses the CISA KEV catalog JSON
 * (<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">format</a>):
 * a top-level {@code vulnerabilities} array with {@code cveID} and {@code dateAdded}.
 */
@Component
public class KevCatalogParser {

    private final ObjectMapper objectMapper;

    KevCatalogParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<KevEntry> parse(String catalogJson) {
        JsonNode root = read(catalogJson);
        List<KevEntry> entries = new ArrayList<>();
        for (JsonNode vuln : root.path("vulnerabilities")) {
            String cveId = vuln.path("cveID").asText(null);
            if (cveId == null) {
                continue;
            }
            entries.add(new KevEntry(cveId, parseDate(vuln.path("dateAdded").asText(null))));
        }
        return entries;
    }

    private LocalDate parseDate(String date) {
        if (date == null) {
            return null;
        }
        try {
            return LocalDate.parse(date);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private JsonNode read(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unparseable KEV catalog", e);
        }
    }
}
