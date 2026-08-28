package io.github.brenomega.authkit.service.spi;

/**
 * Checks candidate passwords against a breach corpus without exposing the
 * candidate outside the application boundary.
 *
 * <p>Implementations define their availability policy. The built-in HIBP adapter
 * fails open on transport errors and records that degradation separately.</p>
 */
@FunctionalInterface
public interface CompromisedPasswordChecker {

    /**
     * Checks a raw candidate before it is accepted by the password policy.
     *
     * @return {@code true} when the candidate appears in the configured corpus
     */
    boolean isCompromised(String rawPassword);
}
