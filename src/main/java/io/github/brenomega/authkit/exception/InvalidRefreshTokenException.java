package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that a first-party refresh secret is malformed, inactive, expired, or cannot rotate. */
public class InvalidRefreshTokenException extends ApiBaseException {

    public InvalidRefreshTokenException() {
        super("Invalid or expired refresh token", HttpStatus.UNAUTHORIZED);
    }
}
