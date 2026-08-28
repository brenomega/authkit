package io.github.brenomega.authkit.infrastructure.audit;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Applies distinct transaction propagation to critical and non-critical audit writes. */
@Service
public class SecurityEventWriter {

    private final SecurityEventRepository repository;

    public SecurityEventWriter(SecurityEventRepository repository) {
        this.repository = repository;
    }

    /** Persists best-effort evidence in an independent transaction. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void persistNonCritical(@NonNull SecurityEvent event) {
        repository.saveAndFlush(event);
    }

    /** Joins the caller's transaction so business data and critical evidence commit or roll back together. */
    @Transactional(propagation = Propagation.REQUIRED)
    public void persistCritical(@NonNull SecurityEvent event) {
        repository.saveAndFlush(event);
    }
}
