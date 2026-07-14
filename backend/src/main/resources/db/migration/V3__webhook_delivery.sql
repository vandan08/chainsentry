-- Phase 3 GitHub App: webhook deliveries are recorded before processing so
-- GitHub's redeliveries (same X-GitHub-Delivery GUID) are acknowledged
-- without triggering a second scan.

CREATE TABLE webhook_delivery (
    id          UUID PRIMARY KEY,
    delivery_id VARCHAR(64) NOT NULL UNIQUE,
    event       VARCHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
