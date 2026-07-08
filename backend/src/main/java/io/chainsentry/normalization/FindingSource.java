package io.chainsentry.normalization;

import io.chainsentry.shared.model.ScannerType;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

/** Which engine reported a finding, and under which native rule id. */
@Embeddable
public record FindingSource(
        @Enumerated(EnumType.STRING)
        @Column(name = "engine", nullable = false)
        ScannerType engine,

        @Column(name = "engine_rule_id")
        String engineRuleId
) {
}
