package io.chainsentry.sbom;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import io.chainsentry.sbom.SbomDiff.ComponentChange;
import io.chainsentry.sbom.SbomDiff.VersionChange;
import io.chainsentry.sbom.SbomDiff.VulnerabilityAnnotation;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Stores CycloneDX documents per scan and computes the diff between two scans. */
@Service
public class SbomService {

    private final SbomRepository sboms;
    private final SbomComponentRepository components;
    private final FindingRepository findings;
    private final VulnerabilityRepository vulnerabilities;
    private final CycloneDxParser parser;

    SbomService(SbomRepository sboms, SbomComponentRepository components, FindingRepository findings,
                VulnerabilityRepository vulnerabilities, CycloneDxParser parser) {
        this.sboms = sboms;
        this.components = components;
        this.findings = findings;
        this.vulnerabilities = vulnerabilities;
        this.parser = parser;
    }

    @Transactional
    public void store(UUID scanJobId, String cycloneDxJson) {
        CycloneDxParser.ParsedSbom parsed = parser.parse(cycloneDxJson);
        String format = parsed.specVersion() != null ? "CycloneDX-" + parsed.specVersion() : "CycloneDX-1.6";
        Sbom sbom = sboms.save(new Sbom(scanJobId, format, parsed.serialNumber(), cycloneDxJson));
        components.saveAll(parsed.components().stream()
                .map(c -> new SbomComponent(sbom.id(), c.purl(), c.name(), c.version(), c.license(), c.direct()))
                .toList());
    }

    @Transactional(readOnly = true)
    public Optional<String> document(UUID scanJobId) {
        return sboms.findByScanJobId(scanJobId).map(Sbom::document);
    }

    @Transactional(readOnly = true)
    public SbomDiff diff(UUID baseScanJobId, UUID headScanJobId) {
        Map<String, SbomComponent> base = componentIndex(baseScanJobId);
        Map<String, SbomComponent> head = componentIndex(headScanJobId);
        Map<String, List<Finding>> headFindingsByPurl = findingsByPurl(headScanJobId);

        List<ComponentChange> added = head.values().stream()
                .filter(c -> !base.containsKey(c.purlWithoutVersion()))
                .sorted(Comparator.comparing(SbomComponent::name))
                .map(c -> componentChange(c, headFindingsByPurl))
                .toList();

        List<ComponentChange> removed = base.values().stream()
                .filter(c -> !head.containsKey(c.purlWithoutVersion()))
                .sorted(Comparator.comparing(SbomComponent::name))
                .map(c -> new ComponentChange(c.purl(), c.name(), c.version(), c.direct(), List.of()))
                .toList();

        List<VersionChange> changed = head.values().stream()
                .filter(c -> {
                    SbomComponent before = base.get(c.purlWithoutVersion());
                    return before != null && !java.util.Objects.equals(before.version(), c.version());
                })
                .sorted(Comparator.comparing(SbomComponent::name))
                .map(c -> new VersionChange(c.name(), base.get(c.purlWithoutVersion()).version(),
                        c.version(), c.purl(), annotations(headFindingsByPurl.get(c.purl()))))
                .toList();

        return new SbomDiff(baseScanJobId, headScanJobId, added, removed, changed);
    }

    private ComponentChange componentChange(SbomComponent component, Map<String, List<Finding>> findingsByPurl) {
        return new ComponentChange(component.purl(), component.name(), component.version(),
                component.direct(), annotations(findingsByPurl.get(component.purl())));
    }

    private Map<String, SbomComponent> componentIndex(UUID scanJobId) {
        Sbom sbom = sboms.findByScanJobId(scanJobId)
                .orElseThrow(() -> new SbomNotFoundException(scanJobId));
        return components.findBySbomId(sbom.id()).stream()
                .collect(Collectors.toMap(SbomComponent::purlWithoutVersion, Function.identity(),
                        (a, b) -> a)); // duplicate purls in one SBOM: keep the first
    }

    private Map<String, List<Finding>> findingsByPurl(UUID scanJobId) {
        return findings.findByScanJobIdOrderByRiskScoreDesc(scanJobId).stream()
                .filter(f -> f.packageCoordinates() != null)
                .collect(Collectors.groupingBy(Finding::packageCoordinates));
    }

    private List<VulnerabilityAnnotation> annotations(List<Finding> packageFindings) {
        if (packageFindings == null) {
            return List.of();
        }
        List<String> vulnIds = packageFindings.stream()
                .map(Finding::vulnerabilityId)
                .filter(id -> id != null)
                .distinct()
                .toList();
        Map<String, Vulnerability> vulnById = vulnerabilities.findAllById(vulnIds).stream()
                .collect(Collectors.toMap(Vulnerability::id, Function.identity()));
        return packageFindings.stream()
                .map(f -> {
                    Vulnerability vuln = f.vulnerabilityId() != null ? vulnById.get(f.vulnerabilityId()) : null;
                    return new VulnerabilityAnnotation(
                            f.vulnerabilityId(),
                            f.severity(),
                            f.riskScoreOrZero(),
                            vuln != null && vuln.inKev());
                })
                .toList();
    }
}
