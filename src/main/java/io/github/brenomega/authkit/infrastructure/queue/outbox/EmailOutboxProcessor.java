package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "enabled", havingValue = "true", matchIfMissing = true)
public class EmailOutboxProcessor {

    private static final Logger log = LoggerFactory.getLogger(EmailOutboxProcessor.class);

    private final EmailOutboxService outboxService;
    private final EmailDispatchStrategy emailDispatchStrategy;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;

    public EmailOutboxProcessor(
            EmailOutboxService outboxService,
            EmailDispatchStrategy emailDispatchStrategy,
            AuthProperties authProperties,
            MeterRegistry meterRegistry) {
        this.outboxService = outboxService;
        this.emailDispatchStrategy = emailDispatchStrategy;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
    }

    @Scheduled(
            fixedDelayString = "${authkit.auth.email-outbox.poll-delay-ms:5000}",
            scheduler = "emailOutboxTaskScheduler")
    public void publishDueMessages() {
        var properties = authProperties.getEmailOutbox();
        var messages = outboxService.claimDueMessages(
                batchSize(properties),
                lockTimeout(properties));

        for (EmailOutboxMessage message : messages) {
            try {
                emailDispatchStrategy.dispatch(message);
            } catch (RuntimeException ex) {
                log.warn("Email outbox dispatch failed for message {}.", message.getId());
                meterRegistry.counter("security.infrastructure.failure", "component", "email_outbox").increment();
                outboxService.markFailed(message.getId(), ex.getMessage());
            }
        }
    }

    private int batchSize(AuthProperties.EmailOutbox properties) {
        return "direct".equals(properties.getDispatchMode())
                ? properties.getDirectBatchSize()
                : properties.getBatchSize();
    }

    private Duration lockTimeout(AuthProperties.EmailOutbox properties) {
        return "direct".equals(properties.getDispatchMode())
                ? EmailOutboxTiming.directProcessingLockTimeout(authProperties)
                : Duration.ofSeconds(properties.getLockTtlSeconds());
    }
}
