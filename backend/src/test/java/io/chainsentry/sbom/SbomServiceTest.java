package io.chainsentry.sbom;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/** The PR supply-chain delta: base scan vs head scan of the demo fixtures. */
@ExtendWith(MockitoExtension.class)
class SbomServiceTest {

    private static final String LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
    private static final String SNAKEYAML_PURL = "pkg:maven/org.yaml/snakeyaml@1.30";

    @Mock
    private SbomRepository sboms;
    @Mock
    private SbomComponentRepository components;
    @Mock
    private FindingRepository findings;
    @Mock
    private VulnerabilityRepository vulnerabilities;

    private SbomService service;

    private final UUID baseScanId = UUID.randomUUID();
    private final UUID headScanId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        service = new SbomService(sboms, components, findings, vulnerabilities,
                new CycloneDxParser(JsonMapper.builder().build()));

        Sbom baseSbom = new Sbom(baseScanId, "CycloneDX-1.6", null, "{}");
        Sbom headSbom = new Sbom(headScanId, "CycloneDX-1.6", null, "{}");
        lenient().when(sboms.findByScanJobId(baseScanId)).thenReturn(Optional.of(baseSbom));
        lenient().when(sboms.findByScanJobId(headScanId)).thenReturn(Optional.of(headSbom));

        lenient().when(components.findBySbomId(baseSbom.id())).thenReturn(List.of(
                component(baseSbom, "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "jackson-databind", "2.13.0", true),
                component(baseSbom, "pkg:maven/com.google.guava/guava@31.0-jre", "guava", "31.0-jre", false),
                component(baseSbom, "pkg:maven/commons-io/commons-io@2.11.0", "commons-io", "2.11.0", true),
                component(baseSbom, "pkg:maven/org.springframework/spring-web@6.1.0", "spring-web", "6.1.0", true)));
        lenient().when(components.findBySbomId(headSbom.id())).thenReturn(List.of(
                component(headSbom, "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "jackson-databind", "2.13.0", true),
                component(headSbom, "pkg:maven/com.google.guava/guava@31.0-jre", "guava", "31.0-jre", false),
                component(headSbom, "pkg:maven/commons-io/commons-io@2.15.1", "commons-io", "2.15.1", true),
                component(headSbom, "pkg:maven/org.springframework/spring-web@6.1.0", "spring-web", "6.1.0", true),
                component(headSbom, "pkg:maven/com.acme/audit-logging-starter@1.0.0", "audit-logging-starter", "1.0.0", true),
                component(headSbom, LOG4J_PURL, "log4j-core", "2.14.1", false),
                component(headSbom, SNAKEYAML_PURL, "snakeyaml", "1.30", false)));

        lenient().when(findings.findByScanJobIdOrderByRiskScoreDesc(headScanId)).thenReturn(List.of(
                finding("CVE-2021-44228", Severity.CRITICAL, 0.9603, LOG4J_PURL),
                finding("CVE-2021-45046", Severity.CRITICAL, 0.9339, LOG4J_PURL),
                finding("CVE-2022-1471", Severity.CRITICAL, 0.3762, SNAKEYAML_PURL)));

        Map<String, Vulnerability> vulnCatalog = Map.of(
                "CVE-2021-44228", kev("CVE-2021-44228"),
                "CVE-2021-45046", kev("CVE-2021-45046"),
                "CVE-2022-1471", new Vulnerability("CVE-2022-1471", BigDecimal.valueOf(9.8), null, null));
        lenient().when(vulnerabilities.findAllById(any())).thenAnswer(invocation -> {
            Iterable<String> ids = invocation.getArgument(0);
            return StreamSupport.stream(ids.spliterator(), false)
                    .map(vulnCatalog::get)
                    .filter(v -> v != null)
                    .toList();
        });
    }

    @Test
    void diffSeparatesAddedChangedAndRemoved() {
        SbomDiff diff = service.diff(baseScanId, headScanId);

        assertThat(diff.added()).extracting(SbomDiff.ComponentChange::name)
                .containsExactly("audit-logging-starter", "log4j-core", "snakeyaml");
        assertThat(diff.removed()).isEmpty();
        assertThat(diff.changed()).singleElement().satisfies(change -> {
            assertThat(change.name()).isEqualTo("commons-io");
            assertThat(change.baseVersion()).isEqualTo("2.11.0");
            assertThat(change.headVersion()).isEqualTo("2.15.1");
        });
    }

    @Test
    void addedComponentsCarryTheirRiskAnnotations() {
        SbomDiff diff = service.diff(baseScanId, headScanId);

        SbomDiff.ComponentChange log4j = diff.added().stream()
                .filter(c -> c.name().equals("log4j-core")).findFirst().orElseThrow();
        assertThat(log4j.direct()).isFalse();
        assertThat(log4j.vulnerabilities()).hasSize(2);
        assertThat(log4j.vulnerabilities())
                .anySatisfy(v -> {
                    assertThat(v.vulnerabilityId()).isEqualTo("CVE-2021-44228");
                    assertThat(v.knownExploited()).isTrue();
                    assertThat(v.riskScore()).isGreaterThan(0.9);
                });

        SbomDiff.ComponentChange starter = diff.added().stream()
                .filter(c -> c.name().equals("audit-logging-starter")).findFirst().orElseThrow();
        assertThat(starter.vulnerabilities()).isEmpty();
    }

    @Test
    void diffAgainstAScanWithoutSbomIs404() {
        UUID unknownScan = UUID.randomUUID();
        when(sboms.findByScanJobId(unknownScan)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.diff(unknownScan, headScanId))
                .isInstanceOf(SbomNotFoundException.class);
    }

    private SbomComponent component(Sbom sbom, String purl, String name, String version, Boolean direct) {
        return new SbomComponent(sbom.id(), purl, name, version, "Apache-2.0", direct);
    }

    private Finding finding(String cveId, Severity severity, double riskScore, String purl) {
        Finding finding = new Finding(headScanId, cveId + "-fp", FindingType.SCA, severity, cveId);
        finding.describePackage(cveId, purl, "x", "y", DependencyScope.TRANSITIVE_RUNTIME);
        finding.applyRiskScore(BigDecimal.valueOf(riskScore));
        return finding;
    }

    private Vulnerability kev(String cveId) {
        Vulnerability vuln = new Vulnerability(cveId, BigDecimal.valueOf(10.0), null, null);
        vuln.markInKev(LocalDate.of(2021, 12, 10), Instant.now());
        return vuln;
    }
}
