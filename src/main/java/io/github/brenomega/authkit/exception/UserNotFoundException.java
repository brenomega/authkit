package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends ApiBaseException {

    public UserNotFoundException() {
        super("User not found", HttpStatus.NOT_FOUND);
    }
}
