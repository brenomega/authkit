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

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update EmailOutboxMessage message
            set message.status = :queued,
                message.lockedAt = null,
                message.lastError = null,
                message.nextAttemptAt = :nextAttemptAt
            where message.id = :id and message.status in :queueEligible
            """)
    int markQueued(@Param("id") UUID id,
                   @Param("queueEligible") Collection<EmailOutboxStatus> queueEligible,
                   @Param("queued") EmailOutboxStatus queued,
                   @Param("nextAttemptAt") Instant nextAttemptAt);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update EmailOutboxMessage message
            set message.status = :sent,
                message.lockedAt = null,
                message.lastError = null,
                message.providerMessageId = coalesce(message.providerMessageId, :providerMessageId),
                message.deliveredAt = coalesce(message.deliveredAt, :deliveredAt)
            where message.id = :id and message.status <> :sent
            """)
    int markSent(@Param("id") UUID id,
                 @Param("sent") EmailOutboxStatus sent,
                 @Param("providerMessageId") String providerMessageId,
                 @Param("deliveredAt") Instant deliveredAt);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update EmailOutboxMessage message
            set message.status = case when message.attempts >= :maxAttempts then :dead else :failed end,
                message.lockedAt = null,
                message.lastError = :error,
                message.nextAttemptAt = :nextAttemptAt
            where message.id = :id and message.status in :failureEligible
            """)
    int markFailed(@Param("id") UUID id,
                   @Param("failureEligible") Collection<EmailOutboxStatus> failureEligible,
                   @Param("failed") EmailOutboxStatus failed,
                   @Param("dead") EmailOutboxStatus dead,
                   @Param("maxAttempts") int maxAttempts,
                   @Param("error") String error,
                   @Param("nextAttemptAt") Instant nextAttemptAt);

    @Modifying
    long deleteByRecipientIn(Collection<String> recipients);
}
