package io.github.brenomega.authkit.service.spi;

/** Checks passwords against a privacy-preserving breach corpus. */
@FunctionalInterface
public interface CompromisedPasswordChecker {

    boolean isCompromised(String rawPassword);
}
