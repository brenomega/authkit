package io.github.brenomega.authkit.infrastructure.persistence.securityeffects;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

/** Locked claiming and inspection for the durable security-effect outbox. */
public interface SecurityEffectRepository extends JpaRepository<SecurityEffectTask, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select task from SecurityEffectTask task where task.id = :id")
    Optional<SecurityEffectTask> findByIdForUpdate(@Param("id") UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select task from SecurityEffectTask task
            where ((task.status in :dueStatuses and task.nextAttemptAt <= :now)
                or (task.status = :processing and task.lockedAt <= :staleBefore))
            order by task.createdAt asc
            """)
    List<SecurityEffectTask> findClaimable(
            @Param("dueStatuses") List<SecurityEffectStatus> dueStatuses,
            @Param("processing") SecurityEffectStatus processing,
            @Param("now") Instant now,
            @Param("staleBefore") Instant staleBefore,
            Pageable pageable);

    @Query("select count(task) from SecurityEffectTask task where task.status <> :completed")
    long countOutstanding(@Param("completed") SecurityEffectStatus completed);

    @Query("""
            select count(task) from SecurityEffectTask task
            where task.recoveryEmailDigest = :digest and task.id <> :id
              and task.createdAt >= :createdAt
            """)
    long countNewerRecoveryIntents(@Param("digest") String digest, @Param("id") UUID id,
            @Param("createdAt") Instant createdAt);

    long countByRecoveryEmailDigestAndEffectTypeAndStatusNotAndCreatedAtLessThanEqual(
            String digest, SecurityEffectType type, SecurityEffectStatus completed, Instant createdAt);

    @org.springframework.data.jpa.repository.Modifying
    @Query(value = """
            delete from security_effect_outbox where id in (
                select id from security_effect_outbox
                where status = 'COMPLETED' and completed_at < :cutoff
                order by completed_at, id limit :batchSize
            ) and status = 'COMPLETED'
            """, nativeQuery = true)
    int purgeCompletedBatch(@Param("cutoff") Instant cutoff, @Param("batchSize") int batchSize);

    @org.springframework.data.jpa.repository.Modifying
    @Query(value = """
            delete from auth_recovery_activations where id in (
                select id from auth_recovery_activations where expires_at < :cutoff
                order by expires_at, id limit :batchSize
            )
            """, nativeQuery = true)
    int purgeExpiredActivationsBatch(@Param("cutoff") Instant cutoff, @Param("batchSize") int batchSize);
}
