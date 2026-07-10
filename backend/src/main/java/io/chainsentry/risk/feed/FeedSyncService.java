package io.chainsentry.risk.feed;

import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import io.chainsentry.shared.config.ChainSentryProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * Pulls the two public exploitation feeds into the {@code vulnerability} table:
 * <ul>
 *   <li><b>CISA KEV</b> (~1.3k entries) — upserted completely; a KEV CVE gets a
 *       row even before any scan sees it, so the step function fires on first
 *       contact.</li>
 *   <li><b>EPSS</b> (~290k rows) — only CVEs already known to ChainSentry are
 *       updated; scoring never needs an EPSS value for a CVE no scan has
 *       reported.</li>
 * </ul>
 */
@Service
public class FeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(FeedSyncService.class);

    private final VulnerabilityRepository vulnerabilities;
    private final KevCatalogParser kevParser;
    private final EpssCsvParser epssParser;
    private final ChainSentryProperties properties;
    private final RestClient restClient;
    private final ApplicationEventPublisher events;

    FeedSyncService(VulnerabilityRepository vulnerabilities, KevCatalogParser kevParser,
                    EpssCsvParser epssParser, ChainSentryProperties properties,
                    RestClient.Builder restClientBuilder, ApplicationEventPublisher events) {
        this.vulnerabilities = vulnerabilities;
        this.kevParser = kevParser;
        this.epssParser = epssParser;
        this.properties = properties;
        this.restClient = restClientBuilder.build();
        this.events = events;
    }

    @Transactional
    public void syncKev() {
        String catalog = restClient.get().uri(properties.feeds().kevUrl()).retrieve().body(String.class);
        Instant now = Instant.now();
        Set<String> changed = new HashSet<>();
        var entries = kevParser.parse(catalog);
        for (KevEntry entry : entries) {
            Vulnerability vuln = vulnerabilities.findById(entry.cveId())
                    .orElseGet(() -> new Vulnerability(entry.cveId(), null, null, null));
            if (!vuln.inKev()) {
                changed.add(entry.cveId());
            }
            vuln.markInKev(entry.dateAdded(), now);
            vulnerabilities.save(vuln);
        }
        log.info("KEV sync: {} catalog entries applied, {} newly in KEV", entries.size(), changed.size());
        publishIfChanged(changed);
    }

    @Transactional
    public void syncEpss() {
        byte[] gzipped = restClient.get().uri(properties.feeds().epssUrl()).retrieve().body(byte[].class);
        Map<String, BigDecimal> scores = parseGzippedCsv(gzipped);
        Instant now = Instant.now();
        Set<String> changed = new HashSet<>();
        for (Vulnerability vuln : vulnerabilities.findAll()) {
            BigDecimal epss = scores.get(vuln.id());
            if (epss != null && !epss.equals(vuln.epssScore())) {
                vuln.updateEpss(epss, now);
                vulnerabilities.save(vuln);
                changed.add(vuln.id());
            }
        }
        log.info("EPSS sync: {} of {} feed rows changed known vulnerabilities", changed.size(), scores.size());
        publishIfChanged(changed);
    }

    private void publishIfChanged(Set<String> changed) {
        if (!changed.isEmpty()) {
            events.publishEvent(new VulnerabilityFeedsUpdated(Set.copyOf(changed)));
        }
    }

    private Map<String, BigDecimal> parseGzippedCsv(byte[] gzipped) {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gzipped))) {
            return epssParser.parse(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to decompress EPSS feed", e);
        }
    }
}
