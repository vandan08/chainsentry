package io.chainsentry.orchestration;

import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScannerType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Duration;
import java.util.UUID;

/**
 * One engine execution within a scan job. The raw report is kept verbatim
 * (JSONB) for auditability and normalization regression tests.
 */
@Entity
@Table(name = "scanner_run")
public class ScannerRun {

    @Id
    private UUID id;

    @Column(name = "scan_job_id", nullable = false)
    private UUID scanJobId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScannerType engine;

    @Column(name = "engine_version")
    private String engineVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status;

    @Column(name = "duration_ms")
    private Integer durationMs;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "raw_report")
    private String rawReport;

    protected ScannerRun() {
        // JPA
    }

    public ScannerRun(UUID scanJobId, ScannerType engine) {
        this.id = UUID.randomUUID();
        this.scanJobId = scanJobId;
        this.engine = engine;
        this.status = ScanStatus.RUNNING;
    }

    public void complete(String engineVersion, String rawReport, Duration duration) {
        this.status = ScanStatus.COMPLETED;
        this.engineVersion = engineVersion;
        this.rawReport = rawReport;
        this.durationMs = (int) duration.toMillis();
    }

    public void fail(Duration duration) {
        this.status = ScanStatus.FAILED;
        this.durationMs = (int) duration.toMillis();
    }

    public UUID id() {
        return id;
    }

    public UUID scanJobId() {
        return scanJobId;
    }

    public ScannerType engine() {
        return engine;
    }

    public String engineVersion() {
        return engineVersion;
    }

    public ScanStatus status() {
        return status;
    }

    public Integer durationMs() {
        return durationMs;
    }

    public String rawReport() {
        return rawReport;
    }
}
