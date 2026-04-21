package io.github.brenomega.authkit.infrastructure.network;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Service strategy to accurately resolve client IP based on network priorities.
 */
@Component
public class NetworkIPResolver {

    /**
     * Resolves the real IP address based on Cloudflare Priority (DT 3.2.17).
     * 
     * <ol>
     *   <li>{@code CF-Connecting-IP} (Cloudflare Edge)</li>
     *   <li>{@code X-Forwarded-For} (TRUSTED_PROXY DT 3.2.20)</li>
     *   <li>DIRECT (Remote Addr DT 3.2.20)</li>
     * </ol>
     *
     * @param request the active servlet request
     * @return the extracted IP string boundary
     */
    public String resolveClientIp(HttpServletRequest request) {
        String cfConnectingIp = request.getHeader("CF-Connecting-IP");
        if (cfConnectingIp != null && !cfConnectingIp.isBlank()) {
            return cfConnectingIp.split(",")[0].trim();
        }

        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
