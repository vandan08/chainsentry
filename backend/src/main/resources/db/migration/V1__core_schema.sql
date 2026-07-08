-- ChainSentry core schema. Enum-like columns are VARCHAR + CHECK rather than
-- native Postgres enums so JPA @Enumerated(STRING) maps cleanly and adding
-- values stays a data migration, not a type migration.

CREATE TABLE organization (
    id                     UUID PRIMARY KEY,
    github_installation_id BIGINT UNIQUE,
    login                  VARCHAR(255) NOT NULL,
    risk_weights           JSONB,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE repository (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organization (id),
    github_repo_id  BIGINT UNIQUE NOT NULL,
    full_name       VARCHAR(512) NOT NULL,
    default_branch  VARCHAR(255) NOT NULL DEFAULT 'main',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_job (
    id            UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repository (id),
    commit_sha    VARCHAR(40) NOT NULL,
    ref           VARCHAR(512),
    pr_number     INTEGER,
    trigger       VARCHAR(20) NOT NULL CHECK (trigger IN ('PR', 'PUSH', 'MANUAL', 'ACTION_UPLOAD')),
    status        VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT')),
    gate_result   VARCHAR(10) CHECK (gate_result IN ('PASS', 'FAIL', 'WARN')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ
);
CREATE INDEX idx_scan_job_repo_created ON scan_job (repository_id, created_at DESC);
CREATE UNIQUE INDEX idx_scan_job_idempotency ON scan_job (repository_id, commit_sha, trigger);

CREATE TABLE scanner_run (
    id          UUID PRIMARY KEY,
    scan_job_id UUID NOT NULL REFERENCES scan_job (id),
    engine      VARCHAR(20) NOT NULL CHECK (engine IN ('TRIVY', 'SEMGREP', 'DEPENDENCY_CHECK')),
    status      VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT')),
    duration_ms INTEGER,
    raw_report  JSONB
);

-- Shared CVE reference data, enriched daily from EPSS + CISA KEV feeds.
CREATE TABLE vulnerability (
    id             VARCHAR(64) PRIMARY KEY, -- CVE-… or GHSA-…
    cvss_score     NUMERIC(3, 1),
    cvss_vector    VARCHAR(128),
    epss_score     NUMERIC(6, 5),
    in_kev         BOOLEAN NOT NULL DEFAULT FALSE,
    kev_added      DATE,
    summary        TEXT,
    refs           JSONB,
    feed_synced_at TIMESTAMPTZ
);
CREATE INDEX idx_vulnerability_kev ON vulnerability (in_kev) WHERE in_kev;

CREATE TABLE finding (
    id                  UUID PRIMARY KEY,
    scan_job_id         UUID NOT NULL REFERENCES scan_job (id),
    vulnerability_id    VARCHAR(64) REFERENCES vulnerability (id), -- null for SAST findings
    fingerprint         VARCHAR(64) NOT NULL,                      -- sha256(vulnId|purl|path)
    type                VARCHAR(20) NOT NULL CHECK (type IN ('SCA', 'SAST', 'CONTAINER', 'SECRET')),
    severity            VARCHAR(10) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    risk_score          NUMERIC(5, 4),
    package_coordinates VARCHAR(1024), -- purl
    installed_version   VARCHAR(128),
    fixed_version       VARCHAR(128),
    dependency_scope    VARCHAR(30) CHECK (dependency_scope IN
                            ('DIRECT_RUNTIME', 'TRANSITIVE_RUNTIME', 'DIRECT_TEST', 'TRANSITIVE_TEST')),
    file_path           VARCHAR(1024),
    line                INTEGER,
    status              VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'FIXED', 'SUPPRESSED')),
    UNIQUE (scan_job_id, fingerprint)
);
CREATE INDEX idx_finding_scan_risk ON finding (scan_job_id, risk_score DESC);

-- Which engines reported a finding (cross-scanner dedup evidence).
CREATE TABLE finding_source (
    finding_id     UUID NOT NULL REFERENCES finding (id),
    engine         VARCHAR(20) NOT NULL CHECK (engine IN ('TRIVY', 'SEMGREP', 'DEPENDENCY_CHECK')),
    engine_rule_id VARCHAR(255),
    PRIMARY KEY (finding_id, engine)
);

CREATE TABLE sbom (
    id            UUID PRIMARY KEY,
    scan_job_id   UUID NOT NULL UNIQUE REFERENCES scan_job (id),
    format        VARCHAR(50) NOT NULL DEFAULT 'CycloneDX-1.6',
    serial_number VARCHAR(128),
    document      JSONB NOT NULL
);

CREATE TABLE sbom_component (
    id      UUID PRIMARY KEY,
    sbom_id UUID NOT NULL REFERENCES sbom (id),
    purl    VARCHAR(1024) NOT NULL,
    name    VARCHAR(512) NOT NULL,
    version VARCHAR(128),
    license VARCHAR(255),
    direct  BOOLEAN
);
CREATE INDEX idx_sbom_component_sbom ON sbom_component (sbom_id);

CREATE TABLE suppression (
    id               UUID PRIMARY KEY,
    repository_id    UUID NOT NULL REFERENCES repository (id),
    vulnerability_id VARCHAR(64) NOT NULL,
    package_purl     VARCHAR(1024),
    justification    VARCHAR(30) NOT NULL CHECK (justification IN
                         ('NOT_AFFECTED', 'FALSE_POSITIVE', 'MITIGATED', 'ACCEPTED_RISK')),
    rationale        TEXT NOT NULL,
    approved_by      VARCHAR(255) NOT NULL,
    expires_on       DATE NOT NULL, -- product opinion: no permanent suppressions
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vex_statement (
    id               UUID PRIMARY KEY,
    suppression_id   UUID NOT NULL UNIQUE REFERENCES suppression (id),
    openvex_document JSONB NOT NULL,
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organization (id),
    name            VARCHAR(255) NOT NULL,
    rules           JSONB NOT NULL,
    is_default      BOOLEAN NOT NULL DEFAULT FALSE
);
