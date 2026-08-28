package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that bounded password-hashing capacity cannot admit more work immediately. */
public class AuthenticationCapacityExceededException extends ApiBaseException {

    public AuthenticationCapacityExceededException() {
        super("Authentication service is busy. Please try again later.",
                HttpStatus.SERVICE_UNAVAILABLE);
    }
}
