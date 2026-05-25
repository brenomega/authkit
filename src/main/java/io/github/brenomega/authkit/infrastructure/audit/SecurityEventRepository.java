package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    List<SecurityEvent> findTop100ByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId);

    List<SecurityEvent> findTop100ByActorUserIdOrderByOccurredAtDesc(UUID actorUserId);

    List<SecurityEvent> findByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId, Pageable pageable);

    long deleteByOccurredAtBefore(Instant cutoff);
}
