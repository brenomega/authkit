/**
 * Records privacy-preserving security and consent evidence. Critical security
 * events join the caller's business transaction and fail closed; non-critical
 * events are best-effort and may be dropped after recording an operational metric.
 * Event digests protect individual rows and do not form a chained ledger.
 */
package io.github.brenomega.authkit.infrastructure.audit;
