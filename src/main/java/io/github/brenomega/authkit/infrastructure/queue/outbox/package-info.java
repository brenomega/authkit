/**
 * Persists email intent with business data and dispatches it after commit.
 * Claiming and state transitions use short database transactions, while provider
 * or broker dispatch occurs outside them. Stale claims are reclaimable and retries
 * imply at-least-once attempts rather than exactly-once delivery.
 */
package io.github.brenomega.authkit.infrastructure.queue.outbox;
