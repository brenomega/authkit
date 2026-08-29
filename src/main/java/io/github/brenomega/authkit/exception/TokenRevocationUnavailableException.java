package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that a live token-state decision cannot be made safely. */
public class TokenRevocationUnavailableException extends ApiBaseException {
    public TokenRevocationUnavailableException() {
        super("Token state is temporarily unavailable. Please try again later.",
                HttpStatus.SERVICE_UNAVAILABLE);
    }

    public TokenRevocationUnavailableException(Throwable cause) {
        super("Token state is temporarily unavailable. Please try again later.",
                HttpStatus.SERVICE_UNAVAILABLE, cause);
    }
}
