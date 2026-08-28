package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;

/** Base type for semantic application failures carrying a stable machine-readable code. */
public abstract class ApiBaseException extends RuntimeException {

    private final HttpStatus status;

    protected ApiBaseException(String message, @NonNull HttpStatus status) {
        super(message);
        this.status = status;
    }

    protected ApiBaseException(String message, @NonNull HttpStatus status, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    @NonNull
    public HttpStatus getStatus() {
        return status;
    }
}
