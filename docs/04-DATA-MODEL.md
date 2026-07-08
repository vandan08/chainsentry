# Data Model

## ERD

```mermaid
erDiagram
    ORGANIZATION ||--o{ REPOSITORY : owns
    ORGANIZATION ||--o{ POLICY : defines
    REPOSITORY ||--o{ SCAN_JOB : has
    SCAN_JOB ||--o{ SCANNER_RUN : "fans out to"
    SCAN_JOB ||--o{ FINDING : produces
    SCAN_JOB ||--o| SBOM : generates
    FINDING }o--|| VULNERABILITY : references
    FINDING ||--o{ FINDING_SOURCE : "reported by"
    SBOM ||--o{ SBOM_COMPONENT : contains
    REPOSITORY ||--o{ SUPPRESSION : has
    SUPPRESSION ||--o| VEX_STATEMENT : "emits"

    ORGANIZATION {
        uuid id PK
        bigint github_installation_id UK
        string login
        jsonb risk_weights "custom W_cvss/W_epss/W_kev/W_scope"
    }
    REPOSITORY {
        uuid id PK
        uuid organization_id FK
        bigint github_repo_id UK
        string full_name
        string default_branch
    }
    SCAN_JOB {
        uuid id PK
        uuid repository_id FK
        string commit_sha
        string ref
        int pr_number "nullable"
        enum trigger "PR | PUSH | MANUAL | ACTION_UPLOAD"
        enum status "PENDING|RUNNING|COMPLETED|FAILED|TIMED_OUT"
        enum gate_result "PASS|FAIL|WARN — policy verdict"
        timestamptz created_at
        timestamptz finished_at
    }
    SCANNER_RUN {
        uuid id PK
        uuid scan_job_id FK
        enum engine "TRIVY|SEMGREP|DEPENDENCY_CHECK"
        enum status
        int duration_ms
        jsonb raw_report "original engine output"
    }
    VULNERABILITY {
        string id PK "CVE-/GHSA-id"
        numeric cvss_score
        string cvss_vector
        numeric epss_score "synced daily"
        boolean in_kev "CISA KEV membership"
        date kev_added
        text summary
        jsonb refs
        timestamptz feed_synced_at
    }
    FINDING {
        uuid id PK
        uuid scan_job_id FK
        string vulnerability_id FK "null for SAST findings"
        string fingerprint UK "dedup key (per scan)"
        enum type "SCA|SAST|CONTAINER|SECRET"
        enum severity "CRITICAL|HIGH|MEDIUM|LOW|INFO"
        numeric risk_score "computed composite 0..1"
        string package_coordinates "purl"
        string installed_version
        string fixed_version "nullable"
        enum dependency_scope "DIRECT_RUNTIME|TRANSITIVE_RUNTIME|DIRECT_TEST|TRANSITIVE_TEST"
        string file_path
        int line
        enum status "OPEN|FIXED|SUPPRESSED"
    }
    FINDING_SOURCE {
        uuid finding_id FK
        enum engine
        string engine_rule_id
    }
    SBOM {
        uuid id PK
        uuid scan_job_id FK
        string format "CycloneDX 1.6"
        jsonb document
        string serial_number
    }
    SBOM_COMPONENT {
        uuid id PK
        uuid sbom_id FK
        string purl
        string name
        string version
        string license
        boolean direct
    }
    SUPPRESSION {
        uuid id PK
        uuid repository_id FK
        string vulnerability_id
        string package_purl "nullable — scope of suppression"
        enum justification "NOT_AFFECTED|FALSE_POSITIVE|MITIGATED|ACCEPTED_RISK"
        text rationale "required, human-written"
        string approved_by
        date expires_on "required — no forever suppressions"
    }
    VEX_STATEMENT {
        uuid id PK
        uuid suppression_id FK
        jsonb openvex_document
        timestamptz issued_at
    }
    POLICY {
        uuid id PK
        uuid organization_id FK
        string name
        jsonb rules "parsed chainsentry.yml"
        boolean is_default
    }
```

## Design notes

- **`VULNERABILITY` is a shared reference table**, not per-finding data. EPSS/KEV sync updates it in place; risk scores are recomputed for open findings when feeds change (a CVE entering KEV overnight should re-rank existing findings — nice demo).
- **`fingerprint`** = SHA-256 of `(vuln id | purl | normalized path)` — dedups the same CVE reported by both Trivy and Dependency-Check within a scan; across scans it enables "first seen / still open" tracking.
- **`purl`** (package URL, e.g. `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`) is the universal component key — the ecosystem standard worth name-dropping.
- **SBOM diff** is computed from `SBOM_COMPONENT` sets of two scans (base vs head), not stored — it's derived data.
- **Suppressions require an expiry and rationale** — this is a product opinion (no permanent silencing) and generates the OpenVEX statement.

## Risk score computation

```
risk = 0.25·(CVSS/10) + 0.40·EPSS + 0.25·KEV + 0.10·scope_factor
```

- Stored per finding (`risk_score`), recomputed on feed sync.
- Weights come from `ORGANIZATION.risk_weights` with these defaults.
- SAST findings (no CVE) fall back to severity-mapped base + Semgrep confidence.

## Policy file (`chainsentry.yml` in the scanned repo)

```yaml
version: 1
gate:
  fail_on:
    - kev: true                    # any KEV finding fails the build
    - severity: critical
      fix_available: true          # critical + upgradable = no excuse
    - risk_score: ">= 0.75"
  warn_on:
    - severity: high
ignore:
  paths: ["**/test/**", "docs/**"]
suppressions_file: .chainsentry/suppressions.yml
sbom:
  formats: [cyclonedx-json]
  attach_to_release: true
```
