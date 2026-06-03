package io.github.brenomega.authkit.infrastructure.queue;

import java.util.Set;

import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;

public class RabbitAutoConfigurationImportFilter implements AutoConfigurationImportFilter, EnvironmentAware {

    private static final Set<String> RABBIT_AUTO_CONFIGURATIONS = Set.of(
            "org.springframework.boot.autoconfigure.amqp.RabbitAutoConfiguration",
            "org.springframework.boot.actuate.autoconfigure.amqp.RabbitHealthContributorAutoConfiguration",
            "org.springframework.boot.actuate.autoconfigure.metrics.amqp.RabbitMetricsAutoConfiguration"
    );

    private Environment environment;

    @Override
    public void setEnvironment(@NonNull Environment environment) {
        this.environment = environment;
    }

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata autoConfigurationMetadata) {
        boolean directMode = environment != null
                && "direct".equals(environment.getProperty("authkit.auth.email-outbox.dispatch-mode", "queue"));
        boolean[] matches = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            String autoConfigurationClass = autoConfigurationClasses[i];
            matches[i] = autoConfigurationClass == null
                    || !directMode
                    || !RABBIT_AUTO_CONFIGURATIONS.contains(autoConfigurationClass);
        }
        return matches;
    }
}
