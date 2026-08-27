package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class LastAuthenticatorException extends ApiBaseException {
    public LastAuthenticatorException() {
        super("Cannot remove the last usable authenticator", HttpStatus.CONFLICT);
    }
}
