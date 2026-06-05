package io.github.brenomega.authkit.exception;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.http.converter.HttpMessageNotReadableException;

import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.response.FieldError;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Centralized exception handler for the entire API (DT 3.4.2).
 *
 * <p>Intercepts all exceptions thrown by controllers and converts them
 * into standardized {@link ApiResponse} envelopes. This ensures:</p>
 * <ul>
 *   <li>No raw stack traces leak to the client.</li>
 *   <li>Generic 500 errors return opaque messages (DT 3.4.2).</li>
 *   <li>Validation failures include per-field details (DT 3.4.10).</li>
 * </ul>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final MeterRegistry meterRegistry;

    public GlobalExceptionHandler(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    /**
     * Handles Jakarta Bean Validation failures (HTTP 400).
     *
     * <p>Extracts per-field error details so clients can map errors
     * programmatically (DT 3.4.10).</p>
     *
     * @param ex the validation exception
     * @return a 400 response with structured field errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<List<FieldError>>> handleValidation(
            MethodArgumentNotValidException ex) {

        List<FieldError> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fe -> new FieldError(fe.getField(), fe.getDefaultMessage()))
                .toList();

        log.warn("Validation failed: {}", fieldErrors);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.validationError(fieldErrors));
    }

    /**
     * Handles Jackson parse errors (e.g. strict duplicate keys, unknown properties).
     *
     * <p>Prevents Mass Assignment by failing the request cleanly (HTTP 400).</p>
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleMessageNotReadable(HttpMessageNotReadableException ex) {
        log.warn("Malformed JSON request: {}", ex.getClass().getSimpleName());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Malformed JSON request or unknown properties provided"));
    }

    /**
     * Handles domain-specific exceptions that extend {@link ApiBaseException}.
     *
     * <p>The HTTP status is determined by the exception itself.</p>
     *
     * @param ex the domain exception
     * @return a response with the appropriate status and message
     */
    @SuppressWarnings("null")
    @ExceptionHandler(ApiBaseException.class)
    public ResponseEntity<ApiResponse<Void>> handleApiException(ApiBaseException ex) {
        if (ex instanceof AuthenticationCapacityExceededException) {
            meterRegistry.counter("security.argon2.capacity_exceeded").increment();
        }
        log.warn("Domain exception [{}]: {}", ex.getStatus(), ex.getMessage());
        return ResponseEntity
                .status(ex.getStatus())
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * Handles Spring's NoResourceFoundException for unmapped endpoints (HTTP 404).
     *
     * @param ex the no-resource exception
     * @return a 404 response in ApiResponse format
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoResource(NoResourceFoundException ex) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error("Resource not found"));
    }

    /**
     * Handles database connectivity and persistence failures without leaking internals.
     */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataAccess(DataAccessException ex) {
        meterRegistry.counter("security.infrastructure.failure", "component", "postgres").increment();
        log.error("Persistence failure", ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Internal Server Error"));
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied(
            org.springframework.security.access.AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error("Forbidden"));
    }

    /**
     * Catch-all handler for unexpected exceptions (HTTP 500).
     *
     * <p>Returns an opaque "Internal Server Error" message to prevent
     * infrastructure detail leakage (DT 3.4.2). The full stack trace
     * is logged at ERROR level for operational debugging.</p>
     *
     * @param ex the unexpected exception
     * @return a 500 response with an opaque message
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Internal Server Error"));
    }
}
