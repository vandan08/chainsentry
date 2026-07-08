package io.chainsentry.dashboard.dto;

import io.chainsentry.normalization.Finding;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingStatus;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.ScannerType;
import io.chainsentry.shared.model.Severity;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public record FindingResponse(
        UUID id,
        FindingType type,
        Severity severity,
        double riskScore,
        String title,
        VulnerabilityInfo vulnerability,
        String packageCoordinates,
        String installedVersion,
        String fixedVersion,
        DependencyScope dependencyScope,
        String filePath,
        FindingStatus status,
        List<SourceInfo> sources
) {

    public record VulnerabilityInfo(
            String id,
            Double cvss,
            Double epss,
            boolean knownExploited,
            LocalDate kevAdded,
            String summary
    ) {
    }

    public record SourceInfo(ScannerType engine, String ruleId) {
    }

    public static FindingResponse from(Finding finding, Vulnerability vulnerability) {
        VulnerabilityInfo vulnInfo = null;
        if (vulnerability != null) {
            vulnInfo = new VulnerabilityInfo(
                    vulnerability.id(),
                    vulnerability.cvssScore() != null ? vulnerability.cvssScore().doubleValue() : null,
                    vulnerability.epssScore() != null ? vulnerability.epssScore().doubleValue() : null,
                    vulnerability.inKev(),
                    vulnerability.kevAdded(),
                    vulnerability.summary());
        }
        return new FindingResponse(
                finding.id(),
                finding.type(),
                finding.severity(),
                finding.riskScoreOrZero(),
                finding.title(),
                vulnInfo,
                finding.packageCoordinates(),
                finding.installedVersion(),
                finding.fixedVersion(),
                finding.dependencyScope(),
                finding.filePath(),
                finding.status(),
                finding.sources().stream()
                        .map(s -> new SourceInfo(s.engine(), s.engineRuleId()))
                        .toList());
    }
}
