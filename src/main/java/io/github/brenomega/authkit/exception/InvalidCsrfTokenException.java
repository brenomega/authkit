package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidCsrfTokenException extends ApiBaseException {

    public InvalidCsrfTokenException() {
        super("Invalid CSRF token", HttpStatus.FORBIDDEN);
    }
}
