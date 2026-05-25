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
    public void persist(SecurityEvent event) {
        repository.save(event);
    }
}
