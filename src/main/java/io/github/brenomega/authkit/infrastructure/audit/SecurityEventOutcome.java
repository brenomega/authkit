package io.github.brenomega.authkit.infrastructure.audit;

/**
 * Outcome classification for durable security events.
 */
public enum SecurityEventOutcome {
    SUCCESS,
    FAILURE,
    DENIED,
    INFO
}
