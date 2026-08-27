package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Raised when an authenticated operation targets a non-active account. */
public class AccountNotActiveException extends ApiBaseException {

    public AccountNotActiveException() {
        super("Account is not active", HttpStatus.FORBIDDEN);
    }
}
