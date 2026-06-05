package io.github.brenomega.authkit.infrastructure.audit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurityEventWriter {

    private final SecurityEventRepository repository;

    public SecurityEventWriter(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void persistNonCritical(SecurityEvent event) {
        repository.saveAndFlush(event);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void persistCritical(SecurityEvent event) {
        repository.saveAndFlush(event);
    }
}
