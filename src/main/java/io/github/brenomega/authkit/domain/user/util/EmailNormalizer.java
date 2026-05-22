package io.github.brenomega.authkit.domain.user.util;

import java.util.Locale;

/**
 * Canonicalizes email identifiers before persistence, lookup, or lockout use.
 */
public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    public static String normalize(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
