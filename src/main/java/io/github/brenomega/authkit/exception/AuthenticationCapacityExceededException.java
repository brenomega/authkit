package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised when password hashing capacity is exhausted and authentication work
 * must be shed to protect the service.
 */
public class AuthenticationCapacityExceededException extends ApiBaseException {

    public AuthenticationCapacityExceededException() {
        super("Authentication service is busy. Please try again later.",
                HttpStatus.SERVICE_UNAVAILABLE);
    }
}
