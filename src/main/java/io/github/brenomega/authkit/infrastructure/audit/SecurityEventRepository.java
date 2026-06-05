package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

@org.springframework.stereotype.Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    List<SecurityEvent> findTop100ByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId);

    List<SecurityEvent> findByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId, Pageable pageable);

    @Query("select e.id from SecurityEvent e where e.occurredAt < :cutoff order by e.occurredAt asc")
    List<UUID> findExpiredIds(@Param("cutoff") Instant cutoff, Pageable pageable);

    @Modifying
    @Query("delete from SecurityEvent e where e.id in :ids")
    long purgeByIdIn(@Param("ids") Collection<UUID> ids);

    @Modifying
    @Query("""
            delete from SecurityEvent e
             where e.actorUserId in :userIds
                or e.targetUserId in :userIds
            """)
    long purgeByUserReferences(@Param("userIds") Collection<UUID> userIds);
}
