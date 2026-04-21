package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a generic user resource lookup fails. Mapped safely to 404.
 */
public class UserNotFoundException extends ApiBaseException {

    public UserNotFoundException() {
        super("User not found", HttpStatus.NOT_FOUND);
    }
}
