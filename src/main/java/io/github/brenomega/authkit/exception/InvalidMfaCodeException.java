package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that an MFA factor is invalid, expired, reused, or unavailable. */
public class InvalidMfaCodeException extends ApiBaseException {

    public InvalidMfaCodeException() {
        super("Invalid MFA code", HttpStatus.UNAUTHORIZED);
    }
}
