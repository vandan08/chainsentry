package io.chainsentry.risk.feed;

import java.time.LocalDate;

/** One entry from the CISA Known Exploited Vulnerabilities catalog. */
public record KevEntry(String cveId, LocalDate dateAdded) {
}
