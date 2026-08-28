package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class AccountNotActiveException extends ApiBaseException {

    public AccountNotActiveException() {
        super("Account is not active", HttpStatus.FORBIDDEN);
    }
}
