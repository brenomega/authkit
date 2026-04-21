package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Abstract base for all domain-specific exceptions (DT 3.4.2).
 *
 * <p>Each subclass defines the HTTP status code it maps to. The
 * {@link GlobalExceptionHandler} intercepts these exceptions and
 * converts them into standardized {@code ApiResponse} objects,
 * ensuring no raw stack traces leak to the client.</p>
 *
 * @see GlobalExceptionHandler
 */
public abstract class ApiBaseException extends RuntimeException {

    private final HttpStatus status;

    /**
     * Constructs a new API exception.
     *
     * @param message the domain-level error message
     * @param status  the HTTP status this exception maps to
     */
    protected ApiBaseException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    /**
     * Constructs a new API exception with a root cause.
     *
     * @param message the domain-level error message
     * @param status  the HTTP status this exception maps to
     * @param cause   the underlying cause
     */
    protected ApiBaseException(String message, HttpStatus status, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    /** @return the HTTP status code for this exception */
    public HttpStatus getStatus() {
        return status;
    }
}
