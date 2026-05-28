package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class RateLimitExceededException extends ApiBaseException {

    public RateLimitExceededException() {
        super("Too many requests", HttpStatus.TOO_MANY_REQUESTS);
    }
}
