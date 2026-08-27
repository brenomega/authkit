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

/** Creates deliberately coarse session metadata from the trusted request boundary. */
@Component
public class SessionMetadataFactory {

    public static final String DEVICE_LABEL_HEADER = "X-AuthKit-Device-Label";
    private static final int MAX_USER_AGENT_LENGTH = 200;
    private static final int MAX_DEVICE_LABEL_LENGTH = 80;

    private final NetworkIpResolver networkIpResolver;

    public SessionMetadataFactory(NetworkIpResolver networkIpResolver) {
        this.networkIpResolver = networkIpResolver;
    }

    public SessionMetadata create(String jti, List<String> initialAmr, long durationDays) {
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
                initialAmr,
                userAgent,
                deviceLabel,
                ip,
                ip);
    }

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
