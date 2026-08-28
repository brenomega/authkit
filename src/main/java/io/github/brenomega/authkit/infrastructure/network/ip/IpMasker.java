package io.github.brenomega.authkit.infrastructure.network.ip;

/** Reduces IP-address precision before diagnostic or session metadata is retained. */
public class IpMasker {

    private IpMasker() {

    }

    /** Masks the final IPv4 octet or IPv6 segment and handles absent input as {@code unknown}. */
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
