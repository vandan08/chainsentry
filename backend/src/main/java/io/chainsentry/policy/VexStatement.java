package io.chainsentry.policy;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/** The OpenVEX document issued for one suppression — the machine-readable audit trail. */
@Entity
@Table(name = "vex_statement")
public class VexStatement {

    @Id
    private UUID id;

    @Column(name = "suppression_id", nullable = false, unique = true)
    private UUID suppressionId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "openvex_document", nullable = false)
    private String openvexDocument;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    protected VexStatement() {
        // JPA
    }

    public VexStatement(UUID id, UUID suppressionId, String openvexDocument) {
        this.id = id;
        this.suppressionId = suppressionId;
        this.openvexDocument = openvexDocument;
        this.issuedAt = Instant.now();
    }

    public UUID id() {
        return id;
    }

    public UUID suppressionId() {
        return suppressionId;
    }

    public String openvexDocument() {
        return openvexDocument;
    }
}
