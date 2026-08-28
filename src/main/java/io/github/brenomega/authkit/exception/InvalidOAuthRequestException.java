package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that an OAuth protocol request fails validation or client binding. */
public class InvalidOAuthRequestException extends ApiBaseException {

    public InvalidOAuthRequestException() {
        super("Invalid OAuth request", HttpStatus.BAD_REQUEST);
    }
}
