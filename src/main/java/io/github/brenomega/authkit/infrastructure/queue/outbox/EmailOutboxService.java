package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Owns transactional email-outbox creation, claiming, and state transitions.
 *
 * <p>Enqueue participates in the caller's database transaction. Claiming uses a
 * separate pessimistically locked transaction; transport dispatch happens only
 * after that transaction returns. Failed attempts use bounded exponential backoff
 * and eventually become terminal {@link EmailOutboxStatus#DEAD} records.</p>
 */
@Service
public class EmailOutboxService {

    private final EmailOutboxRepository repository;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;

    public EmailOutboxService(EmailOutboxRepository repository,
                              AuthProperties authProperties,
                              MeterRegistry meterRegistry) {
        this.repository = repository;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
    }

    /** Adds email intent to the caller's current database transaction. */
    @SuppressWarnings("null")
    @Transactional
    public void enqueue(EmailPayload payload) {
        repository.save(EmailOutboxMessage.pending(payload, Instant.now()));
    }

    /**
     * Claims the oldest due records and reclaims processing records whose lock is stale.
     *
     * <p>The returned records are committed as processing before dispatch begins.</p>
     */
    @Transactional
    public List<EmailOutboxMessage> claimDueMessages(int batchSize, Duration lockTtl) {
        Instant now = Instant.now();
        Instant staleBefore = now.minus(lockTtl);

        List<EmailOutboxMessage> messages = repository.findClaimable(
                List.of(EmailOutboxStatus.PENDING, EmailOutboxStatus.FAILED, EmailOutboxStatus.QUEUED),
                EmailOutboxStatus.PROCESSING,
                now,
                staleBefore,
                PageRequest.of(0, batchSize));

        messages.forEach(message -> message.markProcessing(now));
        return List.copyOf(messages);
    }

    /** Marks an eligible message accepted by the asynchronous transport. */
    @SuppressWarnings("null")
    @Transactional
    public void markQueued(UUID messageId, Duration deliveryTimeout) {
        repository.markQueued(messageId,
                List.of(EmailOutboxStatus.PROCESSING, EmailOutboxStatus.QUEUED), EmailOutboxStatus.QUEUED,
                Instant.now().plus(deliveryTimeout));
    }

    /** Idempotently marks an eligible message sent while preserving its first delivery metadata. */
    @SuppressWarnings("null")
    @Transactional
    public void markSent(UUID messageId, String providerMessageId) {
        repository.markSent(messageId,
                List.of(EmailOutboxStatus.PROCESSING, EmailOutboxStatus.QUEUED),
                EmailOutboxStatus.SENT,
                providerMessageId,
                Instant.now());
    }

    /** Schedules a retry or transitions an exhausted message to the dead state. */
    @SuppressWarnings("null")
    @Transactional
    public void markFailed(UUID messageId, String error) {
        EmailOutboxMessage message = repository.findById(messageId).orElse(null);
        if (message == null || message.getStatus() == EmailOutboxStatus.SENT
                || message.getStatus() == EmailOutboxStatus.DEAD) {
            return;
        }
        int maxAttempts = authProperties.getEmailOutbox().getMaxAttempts();
        Instant nextAttemptAt = Instant.now().plus(backoffDelay(message.getAttempts()));
        int updated = repository.markFailed(
                messageId,
                List.of(EmailOutboxStatus.PROCESSING, EmailOutboxStatus.QUEUED),
                EmailOutboxStatus.FAILED,
                EmailOutboxStatus.DEAD,
                maxAttempts,
                truncate(error),
                nextAttemptAt);
        if (updated == 1) {
            String outcome = message.getAttempts() >= maxAttempts ? "dead" : "retry";
            meterRegistry.counter("security.email.outbox." + outcome).increment();
        }
    }

    @Transactional
    public long deleteByRecipients(Collection<String> recipients) {
        if (recipients == null || recipients.isEmpty()) {
            return 0;
        }
        return repository.deleteByRecipientIn(recipients);
    }

    private Duration backoffDelay(int attempts) {
        long delaySeconds = Math.min(3600, 60L * (1L << Math.min(attempts, 5)));
        return Duration.ofSeconds(delaySeconds);
    }

    private String truncate(String error) {
        if (error == null || error.length() <= 1000) {
            return error;
        }
        return error.substring(0, 1000);
    }
}
