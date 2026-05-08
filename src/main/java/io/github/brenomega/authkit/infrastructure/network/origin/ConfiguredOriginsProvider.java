package io.github.brenomega.authkit.infrastructure.network.origin;

import io.github.brenomega.authkit.infrastructure.network.config.NetworkSecurityProperties;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Duration;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Default implementation of {@link TrustedOriginProvider} backed by CIDR configuration (DT 3.2.19).
 *
 * <p>Reads trusted origin CIDR ranges from {@link NetworkSecurityProperties} and compiles
 * them into {@link IpAddressMatcher} instances at construction time for efficient
 * per-request evaluation.</p>
 *
 * <p>Includes a startup validation that warns if loopback addresses are permitted
 * in a production profile, as this may indicate a misconfiguration that bypasses
 * edge protections.</p>
 *
 * @see TrustedOriginProvider
 * @see NetworkSecurityProperties
 */
@Component
public class ConfiguredOriginsProvider implements TrustedOriginProvider {

    private static final Logger log = LoggerFactory.getLogger(ConfiguredOriginsProvider.class);
    private final List<IpAddressMatcher> trustedMatchers;
    private final Cache<String, Boolean> resolutionCache;

    /**
     * Constructs the provider from externalized CIDR configuration.
     *
     * @param properties the trusted origin CIDR ranges (DT 3.2.19)
     * @param env        the Spring environment for profile-aware validation
     */
    public ConfiguredOriginsProvider(NetworkSecurityProperties properties, Environment env) {
        this.trustedMatchers = properties.getEffectiveRanges().stream()
                .map(IpAddressMatcher::new)
                .toList();

        // DT 3.2.19 — Startup security validation for production environments
        if (env.acceptsProfiles(Profiles.of("prod"))) {
            boolean allowsLoopback = trustedMatchers.stream()
                    .anyMatch(m -> m.matches("127.0.0.1") || m.matches("::1"));
            if (allowsLoopback) {
                log.error("SECURITY VULNERABILITY: Origin Firewall is configured to allow loopback addresses " +
                          "in a PRODUCTION profile. This defeats perimeter security and is forbidden (DT 3.2.19).");
                throw new IllegalStateException("Loopback addresses are forbidden in production origin firewall");
            }
        }

        // Cache for O(1) lookups of previously evaluated IPs to mitigate O(N) sequential CIDR matching
        this.resolutionCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterAccess(Duration.ofHours(1))
                .build();

        log.info("ConfiguredOriginsProvider initialized with {} trusted CIDR ranges and an evaluation cache (DT 3.2.19).",
                 trustedMatchers.size());
    }

    /**
     * Evaluates whether the given IP matches any configured trusted CIDR range.
     * Uses a local Caffeine cache to prevent O(N) CIDR matching bottlenecks.
     *
     * @param ip the remote IP address to validate
     * @return {@code true} if the IP is within a trusted range
     */
    @Override
    public boolean isTrusted(String ip) {
        return resolutionCache.get(ip, key -> 
                trustedMatchers.stream().anyMatch(matcher -> matcher.matches(key))
        );
    }
}
