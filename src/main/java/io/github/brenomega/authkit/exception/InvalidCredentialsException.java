package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends ApiBaseException {

    public InvalidCredentialsException() {
        super("Invalid email or password", HttpStatus.UNAUTHORIZED);
    }
}
