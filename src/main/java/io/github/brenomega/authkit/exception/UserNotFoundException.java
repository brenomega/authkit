package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates no account visible within the caller's authorized identity and tenant boundary. */
public class UserNotFoundException extends ApiBaseException {

    public UserNotFoundException() {
        super("User not found", HttpStatus.NOT_FOUND);
    }
}
