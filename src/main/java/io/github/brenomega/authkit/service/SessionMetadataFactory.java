package io.github.brenomega.authkit.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import io.github.brenomega.authkit.service.spi.SessionMetadata;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Captures privacy-reduced request context when a first-party session is created.
 *
 * <p>The factory separates the public session identifier from the JWT JTI,
 * masks the resolved client IP, normalizes control characters in user-provided
 * labels and user agents, and applies strict length bounds. Calls outside an HTTP
 * request use explicit unknown values rather than failing.</p>
 */
@Component
public class SessionMetadataFactory {

    /** Optional request header used as a user-chosen session label. */
    public static final String DEVICE_LABEL_HEADER = "X-AuthKit-Device-Label";
    private static final int MAX_USER_AGENT_LENGTH = 200;
    private static final int MAX_DEVICE_LABEL_LENGTH = 80;

    private final NetworkIpResolver networkIpResolver;

    public SessionMetadataFactory(NetworkIpResolver networkIpResolver) {
        this.networkIpResolver = networkIpResolver;
    }

    /**
     * Creates immutable metadata with a fresh public identifier.
     *
     * @param durationDays session lifetime in days
     */
    public SessionMetadata create(String jti, long securityVersion, List<String> initialAmr, long durationDays) {
        Instant now = Instant.now();
        HttpServletRequest request = currentRequest();
        String ip = request == null ? "unknown" : IpMasker.mask(networkIpResolver.resolveClientIp(request));
        String userAgent = summarize(request == null ? null : request.getHeader("User-Agent"));
        String deviceLabel = clean(request == null ? null : request.getHeader(DEVICE_LABEL_HEADER),
                MAX_DEVICE_LABEL_LENGTH, null);
        return new SessionMetadata(
                UUID.randomUUID().toString(),
                jti,
                now,
                now,
                now.plus(Duration.ofDays(durationDays)),
                securityVersion,
                initialAmr,
                userAgent,
                deviceLabel,
                ip,
                ip);
    }

    /** Returns the current resolved client address after masking, or {@code unknown}. */
    public String currentMaskedIp() {
        HttpServletRequest request = currentRequest();
        return request == null ? "unknown" : IpMasker.mask(networkIpResolver.resolveClientIp(request));
    }

    private HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest()
                : null;
    }

    static String summarize(String value) {
        return clean(value, MAX_USER_AGENT_LENGTH, "Unknown client");
    }

    private static String clean(String value, int maxLength, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        String normalized = value.replaceAll("[\\p{Cntrl}\\s]+", " ").trim();
        if (normalized.isEmpty()) {
            return fallback;
        }
        return normalized.length() <= maxLength ? normalized : normalized.substring(0, maxLength);
    }
}
