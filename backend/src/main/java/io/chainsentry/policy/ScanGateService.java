package io.chainsentry.policy;

import io.chainsentry.normalization.Finding;
import io.chainsentry.normalization.FindingRepository;
import io.chainsentry.risk.Vulnerability;
import io.chainsentry.risk.VulnerabilityRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Gate evaluation for a persisted scan. Note the gate is recomputed from the
 * current effective policy — the persisted {@code scan_job.gate_result} is
 * the verdict at scan time.
 */
@Service
public class ScanGateService {

    private final FindingRepository findings;
    private final VulnerabilityRepository vulnerabilities;
    private final GateEvaluator evaluator;

    ScanGateService(FindingRepository findings, VulnerabilityRepository vulnerabilities, GateEvaluator evaluator) {
        this.findings = findings;
        this.vulnerabilities = vulnerabilities;
        this.evaluator = evaluator;
    }

    @Transactional(readOnly = true)
    public GateEvaluation evaluate(UUID scanJobId, PolicyRules rules) {
        List<Finding> scanFindings = findings.findByScanJobIdOrderByRiskScoreDesc(scanJobId);
        return evaluator.evaluate(scanFindings, vulnerabilityIndex(scanFindings), rules);
    }

    public Map<String, Vulnerability> vulnerabilityIndex(List<Finding> scanFindings) {
        List<String> vulnIds = scanFindings.stream()
                .map(Finding::vulnerabilityId)
                .filter(id -> id != null)
                .distinct()
                .toList();
        return vulnerabilities.findAllById(vulnIds).stream()
                .collect(Collectors.toMap(Vulnerability::id, Function.identity()));
    }
}
