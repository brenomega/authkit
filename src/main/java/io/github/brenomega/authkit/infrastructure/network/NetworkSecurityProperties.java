package io.github.brenomega.authkit.infrastructure.network;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration properties for network security, specifically Cloudflare IP ranges (DT 3.2.19).
 *
 * <p>Provides a dynamic way to manage trusted origin CIDRs with a safe internal fallback
 * to official Cloudflare ranges if the configuration is missing or empty.</p>
 */
@Component
@Validated
@ConfigurationProperties(prefix = "network.security.cloudflare")
public class NetworkSecurityProperties {

    /**
     * Default hardcoded Cloudflare CIDR ranges to prevent security bypass if config is empty.
     */
    private static final List<String> CLOUDFLARE_FALLBACK_RANGES = List.of(
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
            "127.0.0.1/32",
            "0:0:0:0:0:0:0:1/128"
    );

    private List<String> ranges = new ArrayList<>();

    public List<String> getRanges() {
        return ranges;
    }

    public void setRanges(List<String> ranges) {
        this.ranges = ranges;
    }

    /**
     * Returns the configured ranges or the fallback list if empty (DT 3.2.19 safety).
     */
    public List<String> getEffectiveRanges() {
        if (ranges == null || ranges.isEmpty()) {
            return CLOUDFLARE_FALLBACK_RANGES;
        }
        return Collections.unmodifiableList(ranges);
    }
}
