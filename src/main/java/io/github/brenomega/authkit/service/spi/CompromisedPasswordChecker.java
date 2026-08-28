package io.github.brenomega.authkit.service.spi;

@FunctionalInterface
public interface CompromisedPasswordChecker {

    boolean isCompromised(String rawPassword);
}
