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
 * Owns durable email outbox creation, claiming, retry, and terminal transitions.
 *
 * <p>Enqueue joins the caller's database transaction, preventing notification work
 * for rolled-back business changes. Claiming locks a bounded due set and marks it
 * processing in one transaction. Stale processing or queued records become
 * claimable again after their lease, so dispatch is at-least-once; provider-level
 * idempotency must absorb duplicates. Failed attempts use bounded exponential
 * backoff and become terminal after the configured maximum.</p>
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

    /** Persists a pending message in the caller's transaction. */
    @Transactional
    public void enqueue(EmailPayload payload) {
        repository.save(EmailOutboxMessage.pending(payload, Instant.now()));
    }

    /** Claims up to {@code batchSize} due or stale records under database locking. */
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

    /** Marks broker submission and establishes the acknowledgement deadline. */
    @Transactional
    public void markQueued(UUID messageId, Duration deliveryTimeout) {
        repository.markQueued(messageId,
                List.of(EmailOutboxStatus.PROCESSING, EmailOutboxStatus.QUEUED), EmailOutboxStatus.QUEUED,
                Instant.now().plus(deliveryTimeout));
    }

    /** Records provider acceptance only from processing or queued state. */
    @Transactional
    public void markAccepted(UUID messageId, String providerMessageId) {
        repository.markAccepted(messageId,
                List.of(EmailOutboxStatus.PROCESSING, EmailOutboxStatus.QUEUED),
                EmailOutboxStatus.ACCEPTED,
                providerMessageId,
                Instant.now());
    }

    /** Schedules retry or terminal failure unless the message is already terminal. */
    @Transactional
    public void markFailed(UUID messageId, String error) {
        EmailOutboxMessage message = repository.findById(messageId).orElse(null);
        if (message == null || message.getStatus() == EmailOutboxStatus.ACCEPTED
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
