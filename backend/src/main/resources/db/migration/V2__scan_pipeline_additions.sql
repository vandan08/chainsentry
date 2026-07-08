-- Phase 1 scan pipeline: findings need a human-readable title for the API and
-- PR annotations; scanner runs record the engine version that produced them
-- (normalization behavior can differ between engine releases).

ALTER TABLE finding ADD COLUMN title VARCHAR(1024);
ALTER TABLE scanner_run ADD COLUMN engine_version VARCHAR(64);
