package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.service.dto.EmailPayload;

@Service
public class EmailOutboxService {

    private final EmailOutboxRepository repository;

    public EmailOutboxService(EmailOutboxRepository repository) {
        this.repository = repository;
    }

    @SuppressWarnings("null")
    @Transactional
    public void enqueue(EmailPayload payload) {
        repository.save(EmailOutboxMessage.pending(payload, Instant.now()));
    }

    @Transactional
    public List<EmailOutboxMessage> claimDueMessages(int batchSize, Duration lockTtl) {
        Instant now = Instant.now();
        Instant staleBefore = now.minus(lockTtl);

        List<EmailOutboxMessage> messages = repository.findClaimable(
                List.of(EmailOutboxStatus.PENDING, EmailOutboxStatus.FAILED),
                EmailOutboxStatus.PROCESSING,
                now,
                staleBefore,
                PageRequest.of(0, batchSize));

        messages.forEach(message -> message.markProcessing(now));
        return List.copyOf(messages);
    }

    @SuppressWarnings("null")
    @Transactional
    public void markSent(UUID messageId) {
        repository.findById(messageId).ifPresent(EmailOutboxMessage::markSent);
    }

    @SuppressWarnings("null")
    @Transactional
    public void markFailed(UUID messageId, String error) {
        repository.findById(messageId)
                .ifPresent(message -> message.markFailed(error, Instant.now()));
    }
}
