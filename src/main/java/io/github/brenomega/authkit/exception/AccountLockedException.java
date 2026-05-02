package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when an operation is attempted on an account that has been locked
 * due to exceeding the progressive lockout threshold (DT 3.2.23).
 *
 * <p>Maps to HTTP 403 Forbidden. This exception is used for management
 * endpoints ({@code /users/me/password}, {@code /users/me/sessions/*})
 * where the user is already authenticated but the account is frozen.</p>
 *
 * <p>The <strong>only</strong> way to clear the lockout is via the email-based
 * password recovery flow (RF 2.1.4).</p>
 */
public class AccountLockedException extends ApiBaseException {

    public AccountLockedException() {
        super("Account is locked due to too many failed attempts. Reset your password to unlock.",
                HttpStatus.FORBIDDEN);
    }
}
