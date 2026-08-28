package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates failed double-submit validation for a cookie-backed session operation. */
public class InvalidCsrfTokenException extends ApiBaseException {

    public InvalidCsrfTokenException() {
        super("Invalid CSRF token", HttpStatus.FORBIDDEN);
    }
}
