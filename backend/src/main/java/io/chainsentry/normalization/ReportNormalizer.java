package io.chainsentry.normalization;

import io.chainsentry.scanner.RawReport;
import io.chainsentry.shared.model.ScannerType;

import java.util.List;

/** Turns one engine's raw report into unified findings. One implementation per engine. */
public interface ReportNormalizer {

    ScannerType engine();

    List<NormalizedFinding> normalize(RawReport report);
}
