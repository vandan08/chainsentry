package io.chainsentry.policy;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

/**
 * An approved, time-boxed exception to the gate for one vulnerability in one
 * repository (optionally narrowed to a package). Expiry is mandatory —
 * product opinion: there are no permanent suppressions, only ones nobody
 * re-reviewed.
 */
@Entity
@Table(name = "suppression")
public class Suppression {

    @Id
    private UUID id;

    @Column(name = "repository_id", nullable = false)
    private UUID repositoryId;

    @Column(name = "vulnerability_id", nullable = false)
    private String vulnerabilityId;

    @Column(name = "package_purl")
    private String packagePurl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SuppressionJustification justification;

    @Column(nullable = false)
    private String rationale;

    @Column(name = "approved_by", nullable = false)
    private String approvedBy;

    @Column(name = "expires_on", nullable = false)
    private LocalDate expiresOn;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Suppression() {
        // JPA
    }

    public Suppression(UUID repositoryId, String vulnerabilityId, String packagePurl,
                       SuppressionJustification justification, String rationale, String approvedBy,
                       LocalDate expiresOn) {
        this.id = UUID.randomUUID();
        this.repositoryId = repositoryId;
        this.vulnerabilityId = vulnerabilityId;
        this.packagePurl = packagePurl;
        this.justification = justification;
        this.rationale = rationale;
        this.approvedBy = approvedBy;
        this.expiresOn = expiresOn;
        this.createdAt = Instant.now();
    }

    /** A suppression is live through the day before {@code expiresOn}. */
    public boolean activeOn(LocalDate date) {
        return expiresOn.isAfter(date);
    }

    public boolean matches(String vulnerabilityId, String purl) {
        return this.vulnerabilityId.equals(vulnerabilityId)
                && (this.packagePurl == null || this.packagePurl.equals(purl));
    }

    public UUID id() {
        return id;
    }

    public UUID repositoryId() {
        return repositoryId;
    }

    public String vulnerabilityId() {
        return vulnerabilityId;
    }

    public String packagePurl() {
        return packagePurl;
    }

    public SuppressionJustification justification() {
        return justification;
    }

    public String rationale() {
        return rationale;
    }

    public String approvedBy() {
        return approvedBy;
    }

    public LocalDate expiresOn() {
        return expiresOn;
    }
}
