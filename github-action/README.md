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
          code-scanning: 'false'         # SARIF → GitHub code scanning tab
                                         # (needs `security-events: write`)
          # Optional: upload to a ChainSentry platform instance for history & dashboards
          # upload-url: https://chainsentry.example.com
          # upload-token: ${{ secrets.CHAINSENTRY_TOKEN }}
```

## Modes

- **CI-only (default):** engines run inside the runner; **code and results never leave your infrastructure**. The gate is evaluated locally.
- **Connected:** add `upload-url` + `upload-token` and results also flow to `POST /api/v1/scans/upload` for history, risk re-ranking against live EPSS/KEV data, PR supply-chain deltas, and dashboards. The upload self-registers the repository — no GitHub App installation required.
- **Code scanning:** set `code-scanning: 'true'` (and grant the workflow `security-events: write`) to upload SARIF so findings land in the repository's Security tab. Platform-side scans can also be exported via `GET /api/v1/scans/{id}/sarif`.

## Status

Working: Trivy filesystem/image scan, severity + real CISA-KEV gate, SBOM artifact, platform upload, SARIF code scanning. Planned (see [roadmap](../docs/06-ROADMAP.md)): Semgrep/Dependency-Check engines in the runner, EPSS-aware risk gate, `chainsentry.yml` policy file support, repo-scoped upload tokens.
