package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that a sensitive operation lacks its required MFA step-up. */
public class MfaRequiredException extends ApiBaseException {

    public MfaRequiredException() {
        super("MFA verification is required", HttpStatus.FORBIDDEN);
    }
}
