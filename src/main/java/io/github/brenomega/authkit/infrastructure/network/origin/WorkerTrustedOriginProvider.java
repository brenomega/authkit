package io.github.brenomega.authkit.infrastructure.network.origin;

import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.brenomega.authkit.infrastructure.network.config.WorkerNetworkSecurityProperties;

/** Evaluates direct peers against the dedicated internal-worker CIDR list. */
@Component
public class WorkerTrustedOriginProvider {

    private static final Logger log = LoggerFactory.getLogger(WorkerTrustedOriginProvider.class);
    private final List<IpAddressMatcher> trustedMatchers;
    private final Cache<String, Boolean> resolutionCache;

    public WorkerTrustedOriginProvider(WorkerNetworkSecurityProperties properties, Environment env) {
        this.trustedMatchers = properties.getEffectiveRanges().stream()
                .map(IpAddressMatcher::new)
                .toList();

        if (env.acceptsProfiles(Profiles.of("prod")) && trustedMatchers.isEmpty()) {
            throw new IllegalStateException("A non-loopback worker trusted-origin range is required in production");
        }

        this.resolutionCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterAccess(Duration.ofHours(1))
                .build();

        log.info("WorkerTrustedOriginProvider initialized with {} dedicated worker CIDR ranges.",
                trustedMatchers.size());
    }

    public boolean isTrusted(String ip) {
        return resolutionCache.get(ip, key ->
                trustedMatchers.stream().anyMatch(matcher -> matcher.matches(key)));
    }
}
