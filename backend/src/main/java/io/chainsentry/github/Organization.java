package io.chainsentry.github;

import io.chainsentry.risk.RiskWeights;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * A GitHub org (or user account) that installed ChainSentry. Holds the
 * optional per-org override of the risk-score weights (JSONB).
 */
@Entity
@Table(name = "organization")
public class Organization {

    @Id
    private UUID id;

    @Column(name = "github_installation_id", unique = true)
    private Long githubInstallationId;

    @Column(nullable = false)
    private String login;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "risk_weights")
    private RiskWeights riskWeights;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Organization() {
        // JPA
    }

    public Organization(String login, Long githubInstallationId) {
        this.id = UUID.randomUUID();
        this.login = login;
        this.githubInstallationId = githubInstallationId;
        this.createdAt = Instant.now();
    }

    public UUID id() {
        return id;
    }

    public String login() {
        return login;
    }

    public Long githubInstallationId() {
        return githubInstallationId;
    }

    /** Never null: falls back to the platform default weights. */
    public RiskWeights effectiveRiskWeights() {
        return riskWeights != null ? riskWeights : RiskWeights.DEFAULT;
    }

    public void overrideRiskWeights(RiskWeights weights) {
        this.riskWeights = weights;
    }
}
