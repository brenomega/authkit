package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class EmailNotConfirmedException extends ApiBaseException {

    public EmailNotConfirmedException() {
        super("Email must be confirmed before performing this operation.",
                HttpStatus.FORBIDDEN);
    }
}
