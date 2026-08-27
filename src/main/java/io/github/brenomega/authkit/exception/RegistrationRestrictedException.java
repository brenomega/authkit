package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class RegistrationRestrictedException extends ApiBaseException {
    public RegistrationRestrictedException() {
        super("Public registration is disabled", HttpStatus.FORBIDDEN);
    }
}
