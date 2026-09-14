package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Rejects acceptance of stale or otherwise non-current policy versions. */
public class InvalidConsentVersionException extends ApiBaseException {

    public InvalidConsentVersionException() {
        super("Consent versions do not match the current policy versions", HttpStatus.CONFLICT);
    }
}
