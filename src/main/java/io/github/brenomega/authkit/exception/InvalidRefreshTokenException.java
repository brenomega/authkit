package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised when a refresh token is absent, expired, malformed, or replayed.
 */
public class InvalidRefreshTokenException extends ApiBaseException {

    public InvalidRefreshTokenException() {
        super("Invalid or expired refresh token", HttpStatus.UNAUTHORIZED);
    }
}
