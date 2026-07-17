package io.chainsentry.policy;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Creates suppressions (with their OpenVEX audit trail) and applies them:
 * at creation to the finding being suppressed, and during every scan to
 * freshly normalized findings — so a suppressed CVE stays suppressed on the
 * next scan until the suppression expires.
 */
@Service
public class SuppressionService {

    public record SuppressionResult(Suppression suppression, VexStatement vexStatement) {
    }

    private final SuppressionRepository suppressions;
    private final VexStatementRepository vexStatements;
    private final FindingRepository findings;
    private final OpenVexGenerator openVexGenerator;

    SuppressionService(SuppressionRepository suppressions, VexStatementRepository vexStatements,
                       FindingRepository findings, OpenVexGenerator openVexGenerator) {
        this.suppressions = suppressions;
        this.vexStatements = vexStatements;
        this.findings = findings;
        this.openVexGenerator = openVexGenerator;
    }

    @Transactional
    public SuppressionResult suppress(UUID repositoryId, Finding finding,
                                      SuppressionJustification justification, String rationale,
                                      String approvedBy, LocalDate expiresOn) {
        if (finding.vulnerabilityId() == null) {
            throw new IllegalArgumentException(
                    "Only vulnerability-backed findings (SCA/container) can be suppressed");
        }
        if (!expiresOn.isAfter(LocalDate.now())) {
            throw new IllegalArgumentException(
                    "expiresOn must be in the future — suppressions are time-boxed, never permanent");
        }
        Suppression suppression = suppressions.save(new Suppression(repositoryId,
                finding.vulnerabilityId(), finding.packageCoordinates(), justification,
                rationale, approvedBy, expiresOn));
        finding.suppress();
        findings.save(finding);

        UUID vexId = UUID.randomUUID();
        VexStatement vex = vexStatements.save(new VexStatement(vexId, suppression.id(),
                openVexGenerator.document(vexId, suppression, Instant.now())));
        return new SuppressionResult(suppression, vex);
    }

    /** Called by the scan pipeline before findings are persisted. */
    public void applyTo(UUID repositoryId, Collection<Finding> scanFindings) {
        List<Suppression> active = suppressions
                .findByRepositoryIdAndExpiresOnAfter(repositoryId, LocalDate.now());
        if (active.isEmpty()) {
            return;
        }
        for (Finding finding : scanFindings) {
            boolean suppressed = active.stream()
                    .anyMatch(s -> s.matches(finding.vulnerabilityId(), finding.packageCoordinates()));
            if (suppressed) {
                finding.suppress();
            }
        }
    }

    /** The repo's live VEX position: every statement from unexpired suppressions, merged. */
    @Transactional(readOnly = true)
    public String aggregateVex(UUID repositoryId) {
        List<UUID> activeIds = suppressions
                .findByRepositoryIdAndExpiresOnAfter(repositoryId, LocalDate.now()).stream()
                .map(Suppression::id)
                .toList();
        List<String> documents = vexStatements.findBySuppressionIdIn(activeIds).stream()
                .map(VexStatement::openvexDocument)
                .toList();
        return openVexGenerator.aggregate(repositoryId, documents, Instant.now());
    }
}
