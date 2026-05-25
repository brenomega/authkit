package io.github.brenomega.authkit.infrastructure.audit;

import java.util.List;
import java.util.UUID;

import org.springframework.data.repository.Repository;

@org.springframework.stereotype.Repository
public interface ConsentEventRepository extends Repository<ConsentEvent, UUID> {

    ConsentEvent save(ConsentEvent event);

    List<ConsentEvent> findByUserIdOrderByAcceptedAtDesc(UUID userId);
}
