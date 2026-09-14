package io.github.brenomega.authkit.infrastructure.persistence.securityeffects;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/** Reclaims and retries committed external security effects until completion. */
@Component
public class SecurityEffectProcessor {

    private static final Logger log = LoggerFactory.getLogger(SecurityEffectProcessor.class);
    private static final Duration CLAIM_TTL = Duration.ofMinutes(1);

    private final SecurityEffectRepository repository;
    private final TokenStorage tokenStorage;
    private final TransactionTemplate transactions;
    private final MeterRegistry meters;
    private final io.github.brenomega.authkit.repository.UserRepository users;
    private final io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository emails;
    private final io.github.brenomega.authkit.infrastructure.audit.AuditDigestService digests;

    public SecurityEffectProcessor(SecurityEffectRepository repository,
                                   TokenStorage tokenStorage,
                                   PlatformTransactionManager transactionManager,
                                   MeterRegistry meters,
                                   io.github.brenomega.authkit.repository.UserRepository users,
                                   io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository emails,
                                   io.github.brenomega.authkit.infrastructure.audit.AuditDigestService digests) {
        this.repository = repository;
        this.tokenStorage = tokenStorage;
        this.transactions = new TransactionTemplate(transactionManager);
        this.transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.meters = meters;
        this.users = users;
        this.emails = emails;
        this.digests = digests;
        Gauge.builder("security.effects.outstanding", repository,
                value -> value.countOutstanding(SecurityEffectStatus.COMPLETED))
                .register(meters);
    }

    @Scheduled(
            fixedDelayString = "${authkit.auth.security-effects.poll-delay-ms:1000}",
            initialDelayString = "${authkit.auth.security-effects.initial-delay-ms:1000}")
    @SchedulerLock(name = "securityEffectReconciliation", lockAtMostFor = "PT5M")
    public void reconcile() {
        Instant now = Instant.now();
        List<UUID> claimed = transactions.execute(status -> repository.findClaimable(
                        List.of(SecurityEffectStatus.PENDING, SecurityEffectStatus.FAILED),
                        SecurityEffectStatus.PROCESSING, now, now.minus(CLAIM_TTL), PageRequest.of(0, 50))
                .stream().peek(task -> task.markProcessing(now)).map(SecurityEffectTask::getId).toList());
        if (claimed != null) {
            claimed.forEach(this::executeClaimed);
        }
    }

    /** Attempts one freshly committed task without sacrificing its durable retry record. */
    public void processOne(UUID id) {
        Instant now = Instant.now();
        Boolean claimed = transactions.execute(status -> repository.findByIdForUpdate(id)
                .filter(task -> task.claimableAt(now, now.minus(CLAIM_TTL)))
                .map(task -> {
                    task.markProcessing(now);
                    return true;
                }).orElse(false));
        if (Boolean.TRUE.equals(claimed)) {
            executeClaimed(id);
        }
    }

    private void executeClaimed(UUID id) {
        TaskSnapshot task = transactions.execute(status -> repository.findById(id)
                .filter(current -> current.getStatus() == SecurityEffectStatus.PROCESSING)
                .map(TaskSnapshot::from)
                .orElse(null));
        if (task == null) {
            return;
        }
        try {
            switch (task.effectType()) {
                case ACTIVATE_RECOVERY_TOKEN -> activateRecovery(id);
                case REVOKE_STALE_SESSIONS -> tokenStorage.revokeSessionsBeforeVersion(
                        task.userId().toString(), task.targetVersion(), task.preservedSessionJti());
                case REVOKE_RECOVERY_TOKEN -> revokeRecovery(id);
            }
            transactions.executeWithoutResult(status -> repository.findByIdForUpdate(id)
                    .ifPresent(current -> current.markCompleted(Instant.now())));
            meters.counter("security.effects.completed", "type", task.effectType().name()).increment();
        } catch (RuntimeException ex) {
            Duration delay = Duration.ofSeconds(Math.min(60, 1L << Math.min(task.attempts(), 6)));
            transactions.executeWithoutResult(status -> repository.findByIdForUpdate(id)
                    .ifPresent(current -> current.markFailed(ex.getMessage(), Instant.now().plus(delay))));
            meters.counter("security.effects.retry", "type", task.effectType().name()).increment();
            log.error("Durable security effect {} failed; retry remains pending.", id, ex);
        }
    }

    private void revokeRecovery(UUID id) {
        transactions.executeWithoutResult(status -> repository.findByIdForUpdate(id)
                .filter(task -> task.getStatus() == SecurityEffectStatus.PROCESSING)
                .ifPresent(task -> {
                    // Hold the row lock through the external command and its durable
                    // completion. A stale claimant cannot execute after a newer token
                    // has been released based on this task's COMPLETED status.
                    tokenStorage.revokeRecoveryTokenByDigest(task.getRecoveryEmailDigest());
                    task.markCompleted(Instant.now());
                }));
    }

    private void activateRecovery(UUID id) {
        transactions.executeWithoutResult(status -> {
            SecurityEffectTask task = repository.findById(id).orElseThrow();
            // Serialize against password/email mutations and subsequent recovery requests.
            var owner = users.findByIdForUpdate(task.getUserId());
            boolean usable = owner.filter(user -> user.isActive() && user.getPassword() != null
                    && user.getSecurityVersion() == task.getTargetVersion()
                    && digests.hmacHex(io.github.brenomega.authkit.domain.user.util.EmailNormalizer.normalize(
                            user.getEmail())).equals(task.getRecoveryEmailDigest())).isPresent()
                    && task.getRecoveryExpiresAt().isAfter(Instant.now())
                    && repository.countNewerRecoveryIntents(task.getRecoveryEmailDigest(), task.getId(),
                            task.getCreatedAt()) == 0;
            if (usable) {
                if (repository.countByRecoveryEmailDigestAndEffectTypeAndStatusNotAndCreatedAtLessThanEqual(
                        task.getRecoveryEmailDigest(), SecurityEffectType.REVOKE_RECOVERY_TOKEN,
                        SecurityEffectStatus.COMPLETED, task.getCreatedAt()) > 0) {
                    throw new IllegalStateException("Recovery activation awaits an older durable revocation");
                }
                tokenStorage.activateRecoveryToken(task.getId().toString(), task.getRecoveryEmailDigest(),
                        task.getRecoveryTokenDigest(), task.getRecoveryExpiresAt());
            }
            // A delayed Redis acknowledgement must not release an already expired email.
            boolean deliverable = usable && task.getRecoveryExpiresAt().isAfter(Instant.now());
            emails.findById(task.getEmailMessageId()).ifPresent(message -> message.finishActivation(deliverable));
            task.markCompleted(Instant.now());
        });
    }

    private record TaskSnapshot(
            SecurityEffectType effectType,
            UUID userId,
            Long targetVersion,
            String preservedSessionJti,
            String recoveryEmailDigest,
            int attempts) {

        private static TaskSnapshot from(SecurityEffectTask task) {
            return new TaskSnapshot(
                    task.getEffectType(), task.getUserId(), task.getTargetVersion(),
                    task.getPreservedSessionJti(), task.getRecoveryEmailDigest(), task.getAttempts());
        }
    }
}
