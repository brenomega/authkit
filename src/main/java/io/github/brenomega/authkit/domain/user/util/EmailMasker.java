package io.github.brenomega.authkit.domain.user.util;

/** Reduces an email address to a non-secret display form for logs and audit evidence. */
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
