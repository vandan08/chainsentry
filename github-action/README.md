# ChainSentry GitHub Action

Fails your build when your dependencies fail you.

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: ChainSentry scan
        uses: <your-username>/chainsentry/github-action@v1
        with:
          fail-on-severity: critical     # critical | high | medium | none
          fail-on-kev: 'true'            # any actively-exploited CVE fails the build
          scan-image: ''                 # optionally scan a built image too
          sbom: 'true'                   # CycloneDX SBOM as artifact
          # Optional: upload to a ChainSentry platform instance for history & dashboards
          # upload-url: https://chainsentry.example.com
          # upload-token: ${{ secrets.CHAINSENTRY_TOKEN }}
```

## Modes

- **CI-only (default):** engines run inside the runner; **code and results never leave your infrastructure**. The gate is evaluated locally.
- **Connected:** add `upload-url` + `upload-token` and results also flow to the platform for history, PR supply-chain deltas, and dashboards.

## Status

Phase-0 skeleton: Trivy filesystem/image scan + severity gate + SBOM artifact work end-to-end. Planned (see [roadmap](../docs/06-ROADMAP.md)): Semgrep/Dependency-Check engines, EPSS/KEV-aware risk gate, `chainsentry.yml` policy file support, SARIF upload to the GitHub code-scanning tab.
