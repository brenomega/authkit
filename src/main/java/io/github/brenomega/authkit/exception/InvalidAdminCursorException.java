package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates a malformed, expired, tampered, or query-mismatched administrative cursor. */
public class InvalidAdminCursorException extends ApiBaseException {
    public InvalidAdminCursorException() {
        super("Invalid or expired administrative cursor.", HttpStatus.BAD_REQUEST);
    }
}
