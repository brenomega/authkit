package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;

/** Indicates that a normalized account identity is already claimed. */
public class UserAlreadyExistsException extends ApiBaseException {

    public UserAlreadyExistsException(@NonNull String message) {
        super(message, HttpStatus.CONFLICT);
    }
}
