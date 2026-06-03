package io.github.brenomega.authkit.infrastructure.queue;

import java.util.Set;

import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;

public class RabbitObservabilityAutoConfigurationImportFilter implements AutoConfigurationImportFilter, EnvironmentAware {

    private static final String DISPATCH_MODE_PROPERTY = "authkit.auth.email-outbox.dispatch-mode";
    private static final String PRESERVE_OBSERVABILITY_PROPERTY =
            "authkit.auth.email-outbox.preserve-rabbit-observability";

    private static final Set<String> RABBIT_OBSERVABILITY_AUTO_CONFIGURATIONS = Set.of(
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
        boolean suppressRabbitObservability = shouldSuppressRabbitObservability();
        boolean[] matches = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            String autoConfigurationClass = autoConfigurationClasses[i];
            matches[i] = autoConfigurationClass == null
                    || !suppressRabbitObservability
                    || !RABBIT_OBSERVABILITY_AUTO_CONFIGURATIONS.contains(autoConfigurationClass);
        }
        return matches;
    }

    private boolean shouldSuppressRabbitObservability() {
        if (environment == null) {
            return false;
        }
        boolean directMode = "direct".equals(environment.getProperty(DISPATCH_MODE_PROPERTY, "queue"));
        boolean preserveRabbitObservability = Boolean.parseBoolean(
                environment.getProperty(PRESERVE_OBSERVABILITY_PROPERTY, "false"));
        return directMode && !preserveRabbitObservability;
    }
}
