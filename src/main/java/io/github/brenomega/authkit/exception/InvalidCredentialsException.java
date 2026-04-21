package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown unconditionally during auth failures (DT 3.4.3).
 *
 * <p>Always mapped to HTTP 401 with a generic message to prevent side-channel
 * user enumeration (e.g. failing with "User not found" vs "Wrong password").</p>
 */
public class InvalidCredentialsException extends ApiBaseException {

    public InvalidCredentialsException() {
        super("Invalid email or password", HttpStatus.UNAUTHORIZED);
    }
}
