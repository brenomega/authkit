package io.github.brenomega.authkit.infrastructure.persistence.securityeffects;

/** Retry lifecycle for a durable external security effect. */
public enum SecurityEffectStatus {
    PENDING,
    PROCESSING,
    FAILED,
    COMPLETED
}
