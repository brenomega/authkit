package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that public self-registration is disabled by deployment policy. */
public class RegistrationRestrictedException extends ApiBaseException {
    public RegistrationRestrictedException() {
        super("Public registration is disabled", HttpStatus.FORBIDDEN);
    }
}
