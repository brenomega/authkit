package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised when a cookie-backed browser request omits or mismatches the CSRF token.
 */
public class InvalidCsrfTokenException extends ApiBaseException {

    public InvalidCsrfTokenException() {
        super("Invalid CSRF token", HttpStatus.FORBIDDEN);
    }
}
