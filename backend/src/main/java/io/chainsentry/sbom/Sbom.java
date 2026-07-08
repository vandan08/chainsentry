package io.chainsentry.sbom;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

/** A CycloneDX document captured for one scan; components are indexed separately for diffing. */
@Entity
@Table(name = "sbom")
public class Sbom {

    @Id
    private UUID id;

    @Column(name = "scan_job_id", nullable = false, unique = true)
    private UUID scanJobId;

    @Column(nullable = false)
    private String format;

    @Column(name = "serial_number")
    private String serialNumber;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false)
    private String document;

    protected Sbom() {
        // JPA
    }

    public Sbom(UUID scanJobId, String format, String serialNumber, String document) {
        this.id = UUID.randomUUID();
        this.scanJobId = scanJobId;
        this.format = format;
        this.serialNumber = serialNumber;
        this.document = document;
    }

    public UUID id() {
        return id;
    }

    public UUID scanJobId() {
        return scanJobId;
    }

    public String format() {
        return format;
    }

    public String serialNumber() {
        return serialNumber;
    }

    public String document() {
        return document;
    }
}
