package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that removing a credential would leave the account without a usable authenticator. */
public class LastAuthenticatorException extends ApiBaseException {
    public LastAuthenticatorException() {
        super("Cannot remove the last usable authenticator", HttpStatus.CONFLICT);
    }
}
