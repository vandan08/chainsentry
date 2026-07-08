package io.chainsentry.risk.feed;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KevCatalogParserTest {

    private final KevCatalogParser parser = new KevCatalogParser(JsonMapper.builder().build());

    @Test
    void parsesCatalogEntries() {
        List<KevEntry> entries = parser.parse("""
                {
                  "title": "CISA Catalog of Known Exploited Vulnerabilities",
                  "catalogVersion": "2026.07.08",
                  "vulnerabilities": [
                    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "dateAdded": "2021-12-10"},
                    {"cveID": "CVE-2021-45046", "dateAdded": "2021-12-10"}
                  ]
                }
                """);

        assertThat(entries).containsExactly(
                new KevEntry("CVE-2021-44228", LocalDate.of(2021, 12, 10)),
                new KevEntry("CVE-2021-45046", LocalDate.of(2021, 12, 10)));
    }

    @Test
    void skipsEntriesWithoutCveIdAndToleratesBadDates() {
        List<KevEntry> entries = parser.parse("""
                {"vulnerabilities": [
                  {"vendorProject": "NoCve"},
                  {"cveID": "CVE-2020-1", "dateAdded": "not-a-date"}
                ]}
                """);

        assertThat(entries).containsExactly(new KevEntry("CVE-2020-1", null));
    }

    @Test
    void rejectsGarbage() {
        assertThatThrownBy(() -> parser.parse("<html>maintenance page</html>"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
