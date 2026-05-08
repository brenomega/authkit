package io.github.brenomega.authkit.infrastructure.network.ip;

/**
 * Utility for masking PII (such as IP addresses) in logs to comply with privacy regulations.
 */
public class IpMasker {
    
    private IpMasker() {
        // utility class
    }

    /**
     * Masks an IP address by obscuring the last octet for IPv4 or the last segment for IPv6.
     * Example: 192.168.1.123 -> 192.168.1.***
     * 
     * @param ip the raw IP address
     * @return the masked IP address, or "***" if invalid
     */
    public static String mask(String ip) {
        if (ip == null || ip.isBlank()) {
            return "unknown";
        }
        
        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot) + ".***";
        }
        
        if (ip.contains(":")) {
            int lastColon = ip.lastIndexOf(':');
            if (lastColon > 0) {
                return ip.substring(0, lastColon) + ":****";
            }
        }
        
        return "***";
    }
}
