package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that the account lifecycle state does not permit the requested operation. */
public class AccountNotActiveException extends ApiBaseException {

    public AccountNotActiveException() {
        super("Account is not active", HttpStatus.FORBIDDEN);
    }
}
