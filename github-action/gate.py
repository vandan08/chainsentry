#!/usr/bin/env python3
"""ChainSentry CI policy gate.

Parses a Trivy JSON report, counts findings by severity, checks findings
against the CISA Known Exploited Vulnerabilities catalog, and exits non-zero
when the configured gate is breached — that non-zero exit is what fails the
GitHub Actions build.

KEV data comes from --kev-file (a downloaded catalog snapshot) or, when
--fail-on-kev is enabled and no file is given, a live download of the CISA
catalog. A failed download degrades gracefully: the severity gate still runs.

Phase-4 upgrades planned: EPSS enrichment via the ChainSentry API, full
chainsentry.yml policy support, SARIF emission for the code-scanning tab.
"""

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter

# Emoji output survives non-UTF-8 consoles (Windows cp1252) instead of crashing.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def load_findings(report_path: str) -> list[dict]:
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    findings = []
    for result in report.get("Results") or []:
        findings.extend(result.get("Vulnerabilities") or [])
    return findings


def load_kev_ids(kev_file: str | None, download: bool) -> set[str] | None:
    """Returns the set of KEV CVE ids, or None if unavailable."""
    raw = None
    if kev_file:
        with open(kev_file, encoding="utf-8") as f:
            raw = f.read()
    elif download:
        try:
            with urllib.request.urlopen(KEV_CATALOG_URL, timeout=30) as response:
                raw = response.read().decode("utf-8")
        except OSError as e:
            print(f"⚠ Could not download the CISA KEV catalog ({e}); skipping KEV gate")
            return None
    if raw is None:
        return None
    catalog = json.loads(raw)
    return {
        entry["cveID"]
        for entry in catalog.get("vulnerabilities", [])
        if "cveID" in entry
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--fail-on-severity", default="critical",
                        choices=["critical", "high", "medium", "none"])
    parser.add_argument("--fail-on-kev", default="true")
    parser.add_argument("--kev-file", default=None,
                        help="Path to a CISA KEV catalog JSON snapshot (skips the download)")
    args = parser.parse_args()
    fail_on_kev = args.fail_on_kev.lower() == "true"

    findings = load_findings(args.report)
    by_severity = Counter(v.get("Severity", "UNKNOWN") for v in findings)

    print("ChainSentry gate — findings by severity:")
    for sev in SEVERITY_ORDER:
        if by_severity[sev]:
            print(f"  {sev:<8} {by_severity[sev]}")
    if not findings:
        print("  none 🎉")

    kev_ids = load_kev_ids(args.kev_file, download=fail_on_kev)
    kev_findings = []
    if kev_ids is not None:
        kev_findings = [v for v in findings if v.get("VulnerabilityID") in kev_ids]
        for v in kev_findings:
            print(f"  ⚠ KEV: {v.get('VulnerabilityID')} in {v.get('PkgName')} "
                  f"{v.get('InstalledVersion')} (actively exploited)")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as out:
            out.write(f"critical-count={by_severity['CRITICAL']}\n")
            out.write(f"kev-count={len(kev_findings)}\n")

    breached = False
    if fail_on_kev and kev_findings:
        print(f"\n❌ Gate FAILED: {len(kev_findings)} finding(s) on actively exploited "
              "(CISA KEV) vulnerabilities")
        breached = True

    threshold = args.fail_on_severity.upper()
    if threshold != "NONE":
        breaching = SEVERITY_ORDER[: SEVERITY_ORDER.index(threshold) + 1]
        breach_total = sum(by_severity[s] for s in breaching)
        if breach_total:
            print(f"\n❌ Gate FAILED: {breach_total} finding(s) at or above {threshold}")
            breached = True

    if breached:
        return 1
    print("\n✅ Gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
