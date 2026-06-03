package io.github.brenomega.authkit.infrastructure.queue.outbox;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

@Configuration
public class EmailOutboxExecutionConfig {

    @Bean(name = "emailOutboxTaskScheduler")
    @ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ThreadPoolTaskScheduler emailOutboxTaskScheduler(AuthProperties authProperties) {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setThreadNamePrefix("email-outbox-scheduler-");
        scheduler.setPoolSize(authProperties.getEmailOutbox().getSchedulerPoolSize());
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        scheduler.setAwaitTerminationSeconds(10);
        scheduler.initialize();
        return scheduler;
    }

    @Bean(name = "directEmailDispatchExecutor")
    @ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "dispatch-mode", havingValue = "direct")
    public ThreadPoolTaskExecutor directEmailDispatchExecutor(AuthProperties authProperties) {
        AuthProperties.EmailOutbox outbox = authProperties.getEmailOutbox();
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setThreadNamePrefix("direct-email-dispatch-");
        executor.setCorePoolSize(outbox.getDirectCorePoolSize());
        executor.setMaxPoolSize(outbox.getDirectMaxPoolSize());
        executor.setQueueCapacity(outbox.getDirectQueueCapacity());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(10);
        executor.initialize();
        return executor;
    }
}
