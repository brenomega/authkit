package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidOAuthRequestException extends ApiBaseException {

    public InvalidOAuthRequestException() {
        super("Invalid OAuth request", HttpStatus.BAD_REQUEST);
    }
}
