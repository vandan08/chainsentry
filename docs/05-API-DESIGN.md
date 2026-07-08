# API Design

REST, versioned under `/api/v1`. JSON everywhere; SARIF/CycloneDX/OpenVEX served with their proper media types. Errors follow RFC 9457 (`application/problem+json`) — Spring's `ProblemDetail` gives this natively.

## Authentication

| Consumer | Mechanism |
|---|---|
| GitHub webhooks | HMAC-SHA256 signature (`X-Hub-Signature-256`) |
| GitHub Action uploads | Repo-scoped upload token (issued per installation) |
| Dashboard users | GitHub OAuth → session; org membership drives authorization |
| API tokens (later) | PAT-style org tokens for scripting |

## Endpoints

### Webhooks & ingestion
```
POST /webhooks/github                      GitHub App events (PR, push, installation)
POST /api/v1/scans/upload                  Action mode: upload normalized scan bundle
                                           (findings + SBOM + engine metadata, gzip JSON)
```

### Scans
```
POST /api/v1/repos/{repoId}/scans          Trigger manual scan  {ref, scanners?}
GET  /api/v1/scans/{scanId}                Status + summary (counts by severity, gate result)
GET  /api/v1/scans/{scanId}/findings       Paged; filter: severity, type, engine, status,
                                           minRiskScore; sort: risk_score desc (default)
GET  /api/v1/scans/{scanId}/gate           Policy evaluation detail (which rule fired, why)
```

### Findings
```
GET  /api/v1/repos/{repoId}/findings       Open findings across latest scans (the backlog view)
GET  /api/v1/findings/{id}                 Full detail: sources, CVE data, EPSS/KEV, fix version
POST /api/v1/findings/{id}/suppress        {justification, rationale, expiresOn} → creates
                                           suppression + OpenVEX statement (requires approver role)
```

### SBOM
```
GET  /api/v1/scans/{scanId}/sbom           CycloneDX JSON (Content-Type: application/vnd.cyclonedx+json)
GET  /api/v1/sboms/diff?base={scanId}&head={scanId}
                                           {added[], removed[], upgraded[]} each with vuln annotations
GET  /api/v1/repos/{repoId}/vex            Aggregate OpenVEX document for the repo
```

### Policies
```
GET/PUT /api/v1/orgs/{orgId}/policies/default    Org-level default policy
GET     /api/v1/repos/{repoId}/policy            Effective policy (repo file > org default)
POST    /api/v1/policies/validate                Lint a chainsentry.yml without committing it
```

### Dashboard read-model
```
GET /api/v1/orgs/{orgId}/overview          Repos, open criticals, KEV count, trend (30d)
GET /api/v1/repos/{repoId}/trend           Findings-over-time series for charts
```

## Representative payload — finding detail

```json
{
  "id": "5f0c…",
  "type": "SCA",
  "vulnerability": {
    "id": "CVE-2021-44228",
    "summary": "Apache Log4j2 JNDI RCE (Log4Shell)",
    "cvss": 10.0,
    "epss": 0.975,
    "kev": true,
    "kevAdded": "2021-12-10"
  },
  "riskScore": 0.94,
  "package": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  "dependencyScope": "TRANSITIVE_RUNTIME",
  "fixedVersion": "2.17.1",
  "sources": [
    {"engine": "TRIVY", "ruleId": "CVE-2021-44228"},
    {"engine": "DEPENDENCY_CHECK", "ruleId": "CVE-2021-44228"}
  ],
  "status": "OPEN",
  "firstSeen": "2026-07-01T09:12:00Z"
}
```

## Conventions

- Cursor pagination (`?cursor=…&limit=…`) on all collections.
- Idempotency: scan triggers accept `Idempotency-Key`; webhook deliveries deduped by `X-GitHub-Delivery`.
- Rate limits per token, surfaced via standard `RateLimit-*` headers.
- OpenAPI spec generated via springdoc; served at `/api/docs`.
