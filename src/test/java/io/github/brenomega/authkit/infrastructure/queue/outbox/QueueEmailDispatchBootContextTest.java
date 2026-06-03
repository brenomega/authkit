package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.infrastructure.queue.RabbitMqEmailListener;
import io.github.brenomega.authkit.infrastructure.queue.RabbitMqEmailPublisher;

@SpringBootTest(properties = {
        "authkit.auth.email-outbox.dispatch-mode=queue"
})
@ActiveProfiles("test")
class QueueEmailDispatchBootContextTest {

    @Autowired
    private ApplicationContext context;

    @Test
    @DisplayName("Queue mode still starts with RabbitMQ infrastructure")
    void queueMode_startsWithRabbitArtifacts() {
        assertThat(context.getBeanNamesForType(RabbitMqEmailListener.class)).hasSize(1);
        assertThat(context.getBeanNamesForType(RabbitMqEmailPublisher.class)).hasSize(1);
        assertThat(context.getBeanNamesForType(RabbitTemplate.class)).hasSize(1);
        assertThat(context.getBeanNamesForType(ConnectionFactory.class)).hasSize(1);
    }
}
