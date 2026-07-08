package io.chainsentry.risk.feed;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class EpssCsvParserTest {

    private final EpssCsvParser parser = new EpssCsvParser();

    private Map<String, BigDecimal> parse(String csv) {
        return parser.parse(new ByteArrayInputStream(csv.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parsesScoresSkippingCommentAndHeaderLines() {
        Map<String, BigDecimal> scores = parse("""
                #model_version:v2025.03.14,score_date:2026-07-08T00:00:00+0000
                cve,epss,percentile
                CVE-2021-44228,0.97580,0.99997
                CVE-2020-36518,0.01140,0.84213
                """);

        assertThat(scores).containsOnlyKeys("CVE-2021-44228", "CVE-2020-36518");
        assertThat(scores.get("CVE-2021-44228")).isEqualByComparingTo("0.97580");
    }

    @Test
    void skipsMalformedRowsWithoutFailing() {
        Map<String, BigDecimal> scores = parse("""
                cve,epss,percentile
                CVE-2021-44228,not-a-number,0.9
                CVE-2020-36518,0.01140,0.84213
                short-row
                """);

        assertThat(scores).containsOnlyKeys("CVE-2020-36518");
    }
}
