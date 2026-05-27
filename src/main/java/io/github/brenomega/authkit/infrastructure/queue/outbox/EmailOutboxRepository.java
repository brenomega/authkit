package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.LockModeType;

@Repository
public interface EmailOutboxRepository extends JpaRepository<EmailOutboxMessage, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select message
            from EmailOutboxMessage message
            where (
                message.status in :dueStatuses
                and message.nextAttemptAt <= :now
            ) or (
                message.status = :processingStatus
                and message.lockedAt <= :staleBefore
            )
            order by message.createdAt asc
            """)
    List<EmailOutboxMessage> findClaimable(
            @Param("dueStatuses") Collection<EmailOutboxStatus> dueStatuses,
            @Param("processingStatus") EmailOutboxStatus processingStatus,
            @Param("now") Instant now,
            @Param("staleBefore") Instant staleBefore,
            Pageable pageable);

    Optional<EmailOutboxMessage> findTopByRecipientOrderByCreatedAtDesc(String recipient);

    @Modifying
    long deleteByRecipientIn(Collection<String> recipients);
}
