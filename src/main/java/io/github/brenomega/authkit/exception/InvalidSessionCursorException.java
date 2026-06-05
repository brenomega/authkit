package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidSessionCursorException extends ApiBaseException {

    public InvalidSessionCursorException() {
        super("Invalid or expired session cursor.", HttpStatus.BAD_REQUEST);
    }
}
