package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidAdminCursorException extends ApiBaseException {
    public InvalidAdminCursorException() {
        super("Invalid or expired administrative cursor.", HttpStatus.BAD_REQUEST);
    }
}
