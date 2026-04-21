package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when a user attempts to register with an email
 * that is already in use.
 */
public class UserAlreadyExistsException extends ApiBaseException {

    public UserAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}
