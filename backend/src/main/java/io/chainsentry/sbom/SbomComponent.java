package io.chainsentry.sbom;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** One component row extracted from a CycloneDX document, keyed by purl for diffing. */
@Entity
@Table(name = "sbom_component")
public class SbomComponent {

    @Id
    private UUID id;

    @Column(name = "sbom_id", nullable = false)
    private UUID sbomId;

    @Column(nullable = false)
    private String purl;

    @Column(nullable = false)
    private String name;

    @Column
    private String version;

    @Column
    private String license;

    @Column
    private Boolean direct;

    protected SbomComponent() {
        // JPA
    }

    public SbomComponent(UUID sbomId, String purl, String name, String version, String license, Boolean direct) {
        this.id = UUID.randomUUID();
        this.sbomId = sbomId;
        this.purl = purl;
        this.name = name;
        this.version = version;
        this.license = license;
        this.direct = direct;
    }

    public UUID id() {
        return id;
    }

    public UUID sbomId() {
        return sbomId;
    }

    public String purl() {
        return purl;
    }

    /** purl without the @version suffix — the identity used when diffing two SBOMs. */
    public String purlWithoutVersion() {
        int at = purl.lastIndexOf('@');
        return at > 0 ? purl.substring(0, at) : purl;
    }

    public String name() {
        return name;
    }

    public String version() {
        return version;
    }

    public String license() {
        return license;
    }

    public Boolean direct() {
        return direct;
    }
}
