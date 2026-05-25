package io.github.brenomega.authkit.domain.user.util;

/**
 * Shared privacy-safe email masking for logs and security-event exports.
 */
public final class EmailMasker {

    private EmailMasker() {
    }

    public static String mask(String email) {
        if (email == null || !email.contains("@")) {
            return "[REDACTED]";
        }

        int atIndex = email.indexOf('@');
        String local = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        return local.isBlank() ? "***" + domain : local.charAt(0) + "***" + domain;
    }
}
