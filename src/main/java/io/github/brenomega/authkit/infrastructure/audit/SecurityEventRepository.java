package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

@org.springframework.stereotype.Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    List<SecurityEvent> findTop100ByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId);

    List<SecurityEvent> findByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId, Pageable pageable);
    List<SecurityEvent> findByTargetUserIdOrderByOccurredAtDesc(UUID targetUserId);

    @Query("select e.id from SecurityEvent e where e.occurredAt < :cutoff order by e.occurredAt asc")
    List<UUID> findExpiredIds(@Param("cutoff") Instant cutoff, Pageable pageable);

    @Query("""
            select event from SecurityEvent event
             where :userId is null
                or event.actorUserId = :userId
                or event.targetUserId = :userId
            """)
    Page<SecurityEvent> searchForAdministration(@Param("userId") UUID userId, Pageable pageable);

}
