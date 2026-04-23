package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a token (recovery, verification, etc.) is invalid or expired.
 *
 * <p>Returns HTTP 400 (Bad Request) as this is usually a client error.</p>
 */
public class InvalidTokenException extends ApiBaseException {
    public InvalidTokenException() {
        super("Invalid or expired token", HttpStatus.BAD_REQUEST);
    }
}
