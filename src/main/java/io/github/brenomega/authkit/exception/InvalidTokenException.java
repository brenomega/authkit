package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidTokenException extends ApiBaseException {
    public InvalidTokenException() {
        super("Invalid or expired token", HttpStatus.BAD_REQUEST);
    }
}
