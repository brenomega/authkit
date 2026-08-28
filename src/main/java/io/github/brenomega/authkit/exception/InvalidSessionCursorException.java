package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates an invalid, expired, reused, or owner-mismatched session cursor. */
public class InvalidSessionCursorException extends ApiBaseException {

    public InvalidSessionCursorException() {
        super("Invalid or expired session cursor.", HttpStatus.BAD_REQUEST);
    }
}
