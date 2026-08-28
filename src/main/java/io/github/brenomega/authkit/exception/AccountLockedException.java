package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Indicates that progressive lockout blocks an authenticated management operation.
 *
 * <p>Lockout state is cleared after a complete successful authentication ceremony
 * or successful password recovery, not after an isolated credential check.</p>
 */
public class AccountLockedException extends ApiBaseException {

    public AccountLockedException() {
        super("Account is locked due to too many failed attempts. Reset your password to unlock.",
                HttpStatus.FORBIDDEN);
    }
}
