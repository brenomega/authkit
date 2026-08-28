package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that an expiring one-time application token cannot be validated or consumed. */
public class InvalidTokenException extends ApiBaseException {
    public InvalidTokenException() {
        super("Invalid or expired token", HttpStatus.BAD_REQUEST);
    }
}
