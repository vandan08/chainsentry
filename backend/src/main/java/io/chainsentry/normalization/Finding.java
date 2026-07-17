package io.chainsentry.normalization;

import io.chainsentry.shared.model.DependencyScope;
import io.chainsentry.shared.model.FindingStatus;
import io.chainsentry.shared.model.FindingType;
import io.chainsentry.shared.model.Severity;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The unified finding model every engine's output maps into. One real
 * vulnerability = one row; the engines that reported it live in
 * {@code sources} (cross-scanner dedup evidence).
 */
@Entity
@Table(name = "finding")
public class Finding {

    @Id
    private UUID id;

    @Column(name = "scan_job_id", nullable = false)
    private UUID scanJobId;

    @Column(name = "vulnerability_id")
    private String vulnerabilityId;

    @Column(nullable = false)
    private String fingerprint;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(name = "risk_score")
    private BigDecimal riskScore;

    @Column(name = "package_coordinates")
    private String packageCoordinates;

    @Column(name = "installed_version")
    private String installedVersion;

    @Column(name = "fixed_version")
    private String fixedVersion;

    @Enumerated(EnumType.STRING)
    @Column(name = "dependency_scope")
    private DependencyScope dependencyScope;

    @Column(name = "file_path")
    private String filePath;

    @Column(name = "line")
    private Integer line;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus status;

    @Column(name = "title")
    private String title;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "finding_source", joinColumns = @JoinColumn(name = "finding_id"))
    private List<FindingSource> sources = new ArrayList<>();

    protected Finding() {
        // JPA
    }

    public Finding(UUID scanJobId, String fingerprint, FindingType type, Severity severity, String title) {
        this.id = UUID.randomUUID();
        this.scanJobId = scanJobId;
        this.fingerprint = fingerprint;
        this.type = type;
        this.severity = severity;
        this.title = title;
        this.status = FindingStatus.OPEN;
    }

    public void describePackage(String vulnerabilityId, String purl, String installedVersion,
                                String fixedVersion, DependencyScope scope) {
        this.vulnerabilityId = vulnerabilityId;
        this.packageCoordinates = purl;
        this.installedVersion = installedVersion;
        this.fixedVersion = fixedVersion;
        this.dependencyScope = scope;
    }

    public void locate(String filePath, Integer line) {
        this.filePath = filePath;
        this.line = line;
    }

    /**
     * Later engines fill package gaps the first reporter left — never
     * overwrite, so the more graph-aware engine's data wins regardless of
     * report order.
     */
    public void fillPackageGaps(String fixedVersion, DependencyScope scope) {
        if (this.fixedVersion == null) {
            this.fixedVersion = fixedVersion;
        }
        if (this.dependencyScope == null) {
            this.dependencyScope = scope;
        }
    }

    public void addSource(FindingSource source) {
        if (sources.stream().noneMatch(s -> s.engine() == source.engine())) {
            sources.add(source);
        }
    }

    public void applyRiskScore(BigDecimal riskScore) {
        this.riskScore = riskScore;
    }

    /** Suppressed findings stay visible in the API but stop counting against the gate. */
    public void suppress() {
        this.status = FindingStatus.SUPPRESSED;
    }

    public UUID id() {
        return id;
    }

    public UUID scanJobId() {
        return scanJobId;
    }

    public String vulnerabilityId() {
        return vulnerabilityId;
    }

    public String fingerprint() {
        return fingerprint;
    }

    public FindingType type() {
        return type;
    }

    public Severity severity() {
        return severity;
    }

    public BigDecimal riskScore() {
        return riskScore;
    }

    public double riskScoreOrZero() {
        return riskScore != null ? riskScore.doubleValue() : 0.0;
    }

    public String packageCoordinates() {
        return packageCoordinates;
    }

    public String installedVersion() {
        return installedVersion;
    }

    public String fixedVersion() {
        return fixedVersion;
    }

    public DependencyScope dependencyScope() {
        return dependencyScope;
    }

    public String filePath() {
        return filePath;
    }

    public Integer line() {
        return line;
    }

    public FindingStatus status() {
        return status;
    }

    public String title() {
        return title;
    }

    public List<FindingSource> sources() {
        return List.copyOf(sources);
    }
}
