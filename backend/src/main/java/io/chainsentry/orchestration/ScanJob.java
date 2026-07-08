package io.chainsentry.orchestration;

import io.chainsentry.shared.model.GateStatus;
import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScanTrigger;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * One scan of one commit. Lifecycle: PENDING → RUNNING → COMPLETED / FAILED /
 * TIMED_OUT; {@code gateResult} is set only on completion.
 */
@Entity
@Table(name = "scan_job")
public class ScanJob {

    @Id
    private UUID id;

    @Column(name = "repository_id", nullable = false)
    private UUID repositoryId;

    @Column(name = "commit_sha", nullable = false)
    private String commitSha;

    @Column(name = "ref")
    private String ref;

    @Column(name = "pr_number")
    private Integer prNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "trigger", nullable = false)
    private ScanTrigger trigger;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "gate_result")
    private GateStatus gateResult;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "finished_at")
    private Instant finishedAt;

    protected ScanJob() {
        // JPA
    }

    public ScanJob(UUID repositoryId, String commitSha, String ref, Integer prNumber, ScanTrigger trigger) {
        this.id = UUID.randomUUID();
        this.repositoryId = repositoryId;
        this.commitSha = commitSha;
        this.ref = ref;
        this.prNumber = prNumber;
        this.trigger = trigger;
        this.status = ScanStatus.PENDING;
        this.createdAt = Instant.now();
    }

    public void markRunning() {
        this.status = ScanStatus.RUNNING;
    }

    public void complete(GateStatus gateResult) {
        this.status = ScanStatus.COMPLETED;
        this.gateResult = gateResult;
        this.finishedAt = Instant.now();
    }

    public void fail() {
        this.status = ScanStatus.FAILED;
        this.finishedAt = Instant.now();
    }

    public UUID id() {
        return id;
    }

    public UUID repositoryId() {
        return repositoryId;
    }

    public String commitSha() {
        return commitSha;
    }

    public String ref() {
        return ref;
    }

    public Integer prNumber() {
        return prNumber;
    }

    public ScanTrigger trigger() {
        return trigger;
    }

    public ScanStatus status() {
        return status;
    }

    public GateStatus gateResult() {
        return gateResult;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant finishedAt() {
        return finishedAt;
    }
}
