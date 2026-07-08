#!/usr/bin/env python3
"""ChainSentry CI policy gate.

Parses a Trivy JSON report, counts findings by severity, and exits non-zero
when the configured gate is breached — that non-zero exit is what fails the
GitHub Actions build.

Phase-4 upgrades planned: EPSS/KEV enrichment via the ChainSentry API, full
chainsentry.yml policy support, SARIF emission for the code-scanning tab.
"""

import argparse
import json
import os
import sys
from collections import Counter

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def load_findings(report_path: str) -> list[dict]:
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    findings = []
    for result in report.get("Results") or []:
        findings.extend(result.get("Vulnerabilities") or [])
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--fail-on-severity", default="critical",
                        choices=["critical", "high", "medium", "none"])
    parser.add_argument("--fail-on-kev", default="true")
    args = parser.parse_args()

    findings = load_findings(args.report)
    by_severity = Counter(v.get("Severity", "UNKNOWN") for v in findings)

    print("ChainSentry gate — findings by severity:")
    for sev in SEVERITY_ORDER:
        if by_severity[sev]:
            print(f"  {sev:<8} {by_severity[sev]}")
    if not findings:
        print("  none 🎉")

    # TODO(phase 4): enrich with the CISA KEV catalog (via ChainSentry API or a
    # bundled daily snapshot) so fail-on-kev gates on real membership.
    kev_count = 0

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as out:
            out.write(f"critical-count={by_severity['CRITICAL']}\n")
            out.write(f"kev-count={kev_count}\n")

    threshold = args.fail_on_severity.upper()
    if threshold != "NONE":
        breaching = SEVERITY_ORDER[: SEVERITY_ORDER.index(threshold) + 1]
        breach_total = sum(by_severity[s] for s in breaching)
        if breach_total:
            print(f"\n❌ Gate FAILED: {breach_total} finding(s) at or above {threshold}")
            return 1

    print("\n✅ Gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
