package io.chainsentry.dashboard.dto;

import io.chainsentry.shared.model.ScanStatus;
import io.chainsentry.shared.model.ScannerType;

public record EngineRunResponse(
        ScannerType engine,
        String version,
        ScanStatus status,
        Integer durationMs
) {
}
