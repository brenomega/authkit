package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that TOTP enrollment was requested for an already enabled account. */
public class MfaAlreadyEnabledException extends ApiBaseException {

    public MfaAlreadyEnabledException() {
        super("MFA is already enabled", HttpStatus.CONFLICT);
    }
}
