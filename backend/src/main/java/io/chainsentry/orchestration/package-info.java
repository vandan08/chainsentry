/**
 * Scan lifecycle: job creation (transactional outbox), Redis Streams queue,
 * fan-out to scanner engines on virtual threads, retries and timeouts. Phase 1.
 */
package io.chainsentry.orchestration;
