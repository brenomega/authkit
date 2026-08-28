package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that progressive failure budgets currently prohibit account authentication or step-up. */
public class AccountLockedException extends ApiBaseException {

    public AccountLockedException() {
        super("Account is locked due to too many failed attempts. Reset your password to unlock.",
                HttpStatus.FORBIDDEN);
    }
}
