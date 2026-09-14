package io.github.brenomega.authkit.infrastructure.network.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

/**
 * Binds the dedicated worker-network allowlist. This trust boundary is
 * deliberately separate from the public reverse-proxy allowlist.
 */
@Component
@Validated
@ConfigurationProperties(prefix = "network.security.worker-trusted-origins")
public class WorkerNetworkSecurityProperties {

    private final Environment environment;
    private List<String> ranges = new ArrayList<>();

    public WorkerNetworkSecurityProperties(Environment environment) {
        this.environment = environment;
    }

    public List<String> getRanges() {
        return ranges;
    }

    public void setRanges(List<String> ranges) {
        this.ranges = ranges;
    }

    /** Returns an immutable effective allowlist with production loopback excluded. */
    public List<String> getEffectiveRanges() {
        List<String> source = ranges == null ? Collections.emptyList() : ranges;
        if (environment.acceptsProfiles(Profiles.of("prod"))) {
            return source.stream().filter(range -> !isLoopback(range)).toList();
        }
        return Collections.unmodifiableList(source);
    }

    private boolean isLoopback(String range) {
        return range.equals("127.0.0.1/32")
                || range.equals("0:0:0:0:0:0:0:1/128")
                || range.equals("::1/128");
    }
}
