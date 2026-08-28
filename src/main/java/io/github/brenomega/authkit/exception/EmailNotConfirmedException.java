package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that an operation requires completed email-ownership confirmation. */
public class EmailNotConfirmedException extends ApiBaseException {

    public EmailNotConfirmedException() {
        super("Email must be confirmed before performing this operation.",
                HttpStatus.FORBIDDEN);
    }
}
