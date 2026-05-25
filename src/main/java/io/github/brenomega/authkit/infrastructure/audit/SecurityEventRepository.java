package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

@org.springframework.stereotype.Repository
public interface SecurityEventRepository extends Repository<SecurityEvent, UUID> {

    SecurityEvent save(SecurityEvent event);

    List<SecurityEvent> findTop100ByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId);

    List<SecurityEvent> findByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId, Pageable pageable);

    @Query("select e.id from SecurityEvent e where e.occurredAt < :cutoff order by e.occurredAt asc")
    List<UUID> findExpiredIds(@Param("cutoff") Instant cutoff, Pageable pageable);

    @Modifying
    @Query("delete from SecurityEvent e where e.id in :ids")
    long purgeByIdIn(@Param("ids") Collection<UUID> ids);
}
