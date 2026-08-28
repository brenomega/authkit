package io.github.brenomega.authkit.infrastructure.audit;

/** Represents the semantic result recorded for a security event. */
public enum SecurityEventOutcome {
    SUCCESS,
    FAILURE,
    DENIED,
    INFO
}
