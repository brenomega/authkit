package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class MfaRequiredException extends ApiBaseException {

    public MfaRequiredException() {
        super("MFA verification is required", HttpStatus.FORBIDDEN);
    }
}
