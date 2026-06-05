package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.brenomega.authkit.service.spi.CompromisedPasswordChecker;
import io.micrometer.core.instrument.MeterRegistry;

@Service
public class HibpCompromisedPasswordChecker implements CompromisedPasswordChecker {

    private static final Logger securityAlert = LoggerFactory.getLogger("SECURITY_ALERT");
    private static final long ALERT_INTERVAL_MS = Duration.ofMinutes(5).toMillis();

    private final HibpRangeClient rangeClient;
    private final MeterRegistry meterRegistry;
    private final boolean enabled;
    private final Cache<String, Map<String, Long>> prefixCache;
    private final AtomicLong lastAlertAt = new AtomicLong();

    public HibpCompromisedPasswordChecker(HibpRangeClient rangeClient,
                                          MeterRegistry meterRegistry,
                                          AuthProperties authProperties) {
        AuthProperties.Password config = authProperties.getPassword();
        this.rangeClient = rangeClient;
        this.meterRegistry = meterRegistry;
        this.enabled = config.isHibpEnabled();
        this.prefixCache = Caffeine.newBuilder()
                .maximumSize(config.getHibpCacheMaxPrefixes())
                .expireAfterWrite(Duration.ofSeconds(config.getHibpCacheTtlSeconds()))
                .build();
    }

    @Override
    public boolean isCompromised(String rawPassword) {
        if (!enabled) {
            return false;
        }

        String sha1 = sha1Hex(rawPassword);
        String prefix = sha1.substring(0, 5);
        String suffix = sha1.substring(5);
        try {
            Map<String, Long> results = prefixCache.get(prefix, key -> fetchAndParse(key));
            return results.getOrDefault(suffix, 0L) > 0;
        } catch (RuntimeException ex) {
            recordDegraded();
            return false;
        }
    }

    private Map<String, Long> fetchAndParse(String prefix) {
        try {
            String body = rangeClient.fetchRange(prefix);
            Map<String, Long> results = new java.util.HashMap<>();
            for (String line : body.split("\\R")) {
                int separator = line.indexOf(':');
                if (separator != 35) {
                    continue;
                }
                String suffix = line.substring(0, separator).trim().toUpperCase(Locale.ROOT);
                try {
                    results.put(suffix, Long.parseLong(line.substring(separator + 1).trim()));
                } catch (NumberFormatException ignored) {
                    // Ignore malformed provider rows and preserve fail-open behavior.
                }
            }
            return Map.copyOf(results);
        } catch (IOException ex) {
            throw new HibpLookupException(ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new HibpLookupException(ex);
        }
    }

    private String sha1Hex(String rawPassword) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1")
                    .digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-1 unavailable", ex);
        }
    }

    private void recordDegraded() {
        meterRegistry.counter("security.password.hibp.degraded").increment();
        long now = System.currentTimeMillis();
        long previous = lastAlertAt.get();
        if (now - previous >= ALERT_INTERVAL_MS && lastAlertAt.compareAndSet(previous, now)) {
            securityAlert.error("HIBP password screening is degraded; password validation continued fail-open");
        }
    }

    private static final class HibpLookupException extends RuntimeException {
        private HibpLookupException(Throwable cause) {
            super(cause);
        }
    }
}
