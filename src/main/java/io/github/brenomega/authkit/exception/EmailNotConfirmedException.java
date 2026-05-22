package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Raised when an account attempts write operations before email confirmation.
 */
public class EmailNotConfirmedException extends ApiBaseException {

    public EmailNotConfirmedException() {
        super("Email must be confirmed before performing this operation.",
                HttpStatus.FORBIDDEN);
    }
}
