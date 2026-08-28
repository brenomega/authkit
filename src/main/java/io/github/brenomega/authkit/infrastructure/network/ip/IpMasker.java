package io.github.brenomega.authkit.infrastructure.network.ip;

public class IpMasker {

    private IpMasker() {

    }

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
