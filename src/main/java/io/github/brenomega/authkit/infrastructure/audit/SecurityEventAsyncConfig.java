package io.github.brenomega.authkit.infrastructure.audit;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

@Configuration
public class SecurityEventAsyncConfig {

    @Bean
    public ThreadPoolTaskExecutor securityEventExecutor(AuthProperties authProperties) {
        AuthProperties.Audit audit = authProperties.getAudit();
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setThreadNamePrefix("security-event-writer-");
        executor.setCorePoolSize(audit.getWriterCorePoolSize());
        executor.setMaxPoolSize(audit.getWriterMaxPoolSize());
        executor.setQueueCapacity(audit.getWriterQueueCapacity());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(audit.getWriterShutdownTimeoutSeconds());
        executor.initialize();
        return executor;
    }
}
