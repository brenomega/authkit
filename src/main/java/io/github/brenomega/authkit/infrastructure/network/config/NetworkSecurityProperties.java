package io.github.brenomega.authkit.infrastructure.network.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration properties for trusted origin CIDR ranges (DT 3.2.19).
 *
 * <p>Provides a dynamic way to manage trusted reverse proxy origin CIDRs.
 * Ranges are externalized and managed via Kubernetes ConfigMaps/NetworkPolicies
 * to prevent security bypass without hardcoded assumptions.</p>
 *
 * <p>This class is reverse-proxy agnostic — the CIDR ranges can represent
 * any edge provider (Cloudflare, AWS API Gateway, Nginx, etc.).</p>
 *
 * <p>In the {@code prod} profile, loopback addresses are automatically stripped
 * from the effective ranges unless explicitly configured, preventing local
 * spoofing attacks.</p>
 *
 * @see ConfiguredOriginsProvider
 * @see OriginFirewallFilter
 */
@Component
@Validated
@ConfigurationProperties(prefix = "network.security.trusted-origins")
public class NetworkSecurityProperties {

    private final Environment environment;
    private List<String> ranges = new ArrayList<>();

    public NetworkSecurityProperties(Environment environment) {
        this.environment = environment;
    }

    public List<String> getRanges() {
        return ranges;
    }

    public void setRanges(List<String> ranges) {
        this.ranges = ranges;
    }

    /**
     * Returns the configured ranges (DT 3.2.19 safety).
     *
     * <p>Strictly excludes loopback addresses in the 'prod' profile to prevent local spoofing
     * unless explicitly configured in application.yml.</p>
     *
     * @return the effective list of trusted CIDR ranges
     */
    public List<String> getEffectiveRanges() {
        List<String> source = (ranges == null) ? Collections.emptyList() : ranges;

        if (environment.acceptsProfiles(Profiles.of("prod"))) {
            return source.stream()
                    .filter(range -> !isLoopback(range))
                    .toList();
        }
        
        return Collections.unmodifiableList(source);
    }

    private boolean isLoopback(String range) {
        return range.equals("127.0.0.1/32") || range.equals("0:0:0:0:0:0:0:1/128") || range.equals("::1/128");
    }
}
