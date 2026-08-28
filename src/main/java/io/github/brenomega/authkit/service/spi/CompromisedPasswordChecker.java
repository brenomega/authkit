package io.github.brenomega.authkit.service.spi;

/**
 * Screens candidate passwords against an external or local compromise corpus.
 *
 * <p>Implementations receive plaintext solely for the duration of the check and
 * must not persist or log it. A {@code false} result means that the checker did
 * not identify the value as compromised; it is not a general password-strength
 * guarantee.</p>
 */
@FunctionalInterface
public interface CompromisedPasswordChecker {

    /**
     * Tests a plaintext candidate without retaining it.
     *
     * @return {@code true} when the backing corpus reports the password
     */
    boolean isCompromised(String rawPassword);
}
