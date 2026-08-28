package io.github.brenomega.authkit.domain.user.util;

import java.util.Locale;

/** Defines the canonical email identity used for lookup, uniqueness, and security keys. */
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
