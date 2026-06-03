package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.util.concurrent.Executor;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.infrastructure.email.DirectEmailDispatchStrategy;
import io.github.brenomega.authkit.service.spi.EmailProvider;
import io.github.brenomega.authkit.infrastructure.queue.QueueEmailDispatchStrategy;
import io.github.brenomega.authkit.infrastructure.queue.RabbitMqConfig;
import io.github.brenomega.authkit.infrastructure.queue.RabbitMqEmailListener;
import io.github.brenomega.authkit.infrastructure.queue.RabbitMqEmailPublisher;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

class EmailDispatchModeContextTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withBean(AuthProperties.class, AuthProperties::new)
            .withBean(EmailOutboxService.class, () -> mock(EmailOutboxService.class))
            .withBean(EmailProvider.class, () -> mock(EmailProvider.class))
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(RabbitTemplate.class, () -> mock(RabbitTemplate.class))
            .withBean("directEmailDispatchExecutor", Executor.class, () -> command -> { })
            .withUserConfiguration(
                    DirectEmailDispatchStrategy.class,
                    QueueEmailDispatchStrategy.class,
                    RabbitMqConfig.class,
                    RabbitMqEmailListener.class,
                    RabbitMqEmailPublisher.class);

    @Test
    @DisplayName("Direct dispatch mode loads direct strategy without AuthKit RabbitMQ email beans")
    void directMode_loadsDirectStrategyWithoutAuthKitRabbitBeans() {
        contextRunner
                .withPropertyValues("authkit.auth.email-outbox.dispatch-mode=direct")
                .run(context -> {
                    assertThat(context).hasSingleBean(DirectEmailDispatchStrategy.class);
                    assertThat(context).doesNotHaveBean(QueueEmailDispatchStrategy.class);
                    assertThat(context).doesNotHaveBean(RabbitMqEmailListener.class);
                    assertThat(context).doesNotHaveBean(RabbitMqEmailPublisher.class);
                    assertThat(context).doesNotHaveBean("apiExchange");
                });
    }

    @Test
    @DisplayName("Queue dispatch mode loads queue and RabbitMQ beans")
    void queueMode_loadsQueueAndRabbitBeans() {
        contextRunner
                .withPropertyValues("authkit.auth.email-outbox.dispatch-mode=queue")
                .run(context -> {
                    assertThat(context).hasSingleBean(QueueEmailDispatchStrategy.class);
                    assertThat(context).doesNotHaveBean(DirectEmailDispatchStrategy.class);
                    assertThat(context).hasSingleBean(RabbitMqEmailListener.class);
                    assertThat(context).hasSingleBean(RabbitMqEmailPublisher.class);
                    assertThat(context).hasBean("apiExchange");
                });
    }
}
