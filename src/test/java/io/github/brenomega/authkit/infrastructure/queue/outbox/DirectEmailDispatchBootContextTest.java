package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.amqp.RabbitHealthIndicator;
import org.springframework.boot.actuate.metrics.amqp.RabbitMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.infrastructure.email.DirectEmailDispatchStrategy;
import io.github.brenomega.authkit.infrastructure.queue.RabbitMqEmailListener;
import io.github.brenomega.authkit.infrastructure.queue.RabbitMqEmailPublisher;

@SpringBootTest(properties = {
        "authkit.auth.email-outbox.enabled=true",
        "authkit.auth.email-outbox.dispatch-mode=direct",
        "authkit.auth.email-provider.type=logging",
        "spring.rabbitmq.username=",
        "spring.rabbitmq.password=",
        "management.health.rabbit.enabled=true"
})
@ActiveProfiles("test")
class DirectEmailDispatchBootContextTest {

    @Autowired
    private ApplicationContext context;

    @Test
    @DisplayName("Direct mode starts without RabbitMQ auto-configuration artifacts")
    void directMode_startsWithoutRabbitArtifacts() {
        assertThat(context.getBeanNamesForType(DirectEmailDispatchStrategy.class)).hasSize(1);
        assertThat(context.getBeanNamesForType(RabbitMqEmailListener.class)).isEmpty();
        assertThat(context.getBeanNamesForType(RabbitMqEmailPublisher.class)).isEmpty();
        assertThat(context.getBeanNamesForType(RabbitTemplate.class)).isEmpty();
        assertThat(context.getBeanNamesForType(ConnectionFactory.class)).isEmpty();
        assertThat(context.getBeanNamesForType(RabbitHealthIndicator.class)).isEmpty();
        assertThat(context.getBeanNamesForType(RabbitMetrics.class)).isEmpty();
    }
}
