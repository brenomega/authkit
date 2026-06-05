package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Raised when an opted-in high-risk operation cannot use distributed abuse controls. */
public class AbuseProtectionUnavailableException extends ApiBaseException {

    public AbuseProtectionUnavailableException() {
        super("Authentication service is temporarily unavailable. Please try again later.",
                HttpStatus.SERVICE_UNAVAILABLE);
    }
}
