package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class MfaAlreadyEnabledException extends ApiBaseException {

    public MfaAlreadyEnabledException() {
        super("MFA is already enabled", HttpStatus.CONFLICT);
    }
}
