package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidMfaCodeException extends ApiBaseException {

    public InvalidMfaCodeException() {
        super("Invalid MFA code", HttpStatus.UNAUTHORIZED);
    }
}
