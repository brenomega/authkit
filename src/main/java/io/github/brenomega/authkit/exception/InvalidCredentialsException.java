package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates authentication failure without disclosing which credential property failed. */
public class InvalidCredentialsException extends ApiBaseException {

    public InvalidCredentialsException() {
        super("Invalid email or password", HttpStatus.UNAUTHORIZED);
    }
}
