package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class AuditUnavailableException extends ApiBaseException {

    public AuditUnavailableException(Throwable cause) {
        super("Security audit service is temporarily unavailable. Please try again later.",
                HttpStatus.SERVICE_UNAVAILABLE, cause);
    }
}
