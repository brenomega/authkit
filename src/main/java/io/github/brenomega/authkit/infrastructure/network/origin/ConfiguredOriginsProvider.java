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

@Component
public class ConfiguredOriginsProvider implements TrustedOriginProvider {

    private static final Logger log = LoggerFactory.getLogger(ConfiguredOriginsProvider.class);
    private final List<IpAddressMatcher> trustedMatchers;
    private final Cache<String, Boolean> resolutionCache;

    public ConfiguredOriginsProvider(NetworkSecurityProperties properties, Environment env) {
        this.trustedMatchers = properties.getEffectiveRanges().stream()
                .map(IpAddressMatcher::new)
                .toList();

        if (env.acceptsProfiles(Profiles.of("prod"))) {
            boolean allowsLoopback = trustedMatchers.stream()
                    .anyMatch(m -> m.matches("127.0.0.1") || m.matches("::1"));
            if (allowsLoopback) {
                log.error("SECURITY VULNERABILITY: Origin Firewall is configured to allow loopback addresses " +
                          "in a PRODUCTION profile. This defeats perimeter security and is forbidden (DT 3.2.19).");
                throw new IllegalStateException("Loopback addresses are forbidden in production origin firewall");
            }
        }

        this.resolutionCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterAccess(Duration.ofHours(1))
                .build();

        log.info("ConfiguredOriginsProvider initialized with {} trusted CIDR " +
            "ranges and an evaluation cache (DT 3.2.19).",
                 trustedMatchers.size());
    }

    @Override
    public boolean isTrusted(String ip) {
        return resolutionCache.get(ip, key ->
                trustedMatchers.stream().anyMatch(matcher -> matcher.matches(key))
        );
    }
}
