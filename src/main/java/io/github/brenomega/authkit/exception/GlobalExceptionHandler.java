package io.github.brenomega.authkit.exception;

import java.util.List;
import java.util.Objects;
import java.util.Locale;
import java.util.Map;

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

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final MeterRegistry meterRegistry;

    public GlobalExceptionHandler(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

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

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleMessageNotReadable(HttpMessageNotReadableException ex) {
        log.warn("Malformed JSON request: {}", ex.getClass().getSimpleName());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("malformed_json",
                        "Malformed JSON request or unknown properties provided"));
    }

    @ExceptionHandler(ApiBaseException.class)
    public ResponseEntity<ApiResponse<Void>> handleApiException(ApiBaseException ex) {
        if (ex instanceof AuthenticationCapacityExceededException) {
            meterRegistry.counter("security.argon2.capacity_exceeded").increment();
        }
        String message = Objects.requireNonNullElse(ex.getMessage(), "Request failed");
        log.warn("Domain exception [{}]: {}", ex.getStatus(), message);
        return ResponseEntity
                .status(ex.getStatus())
                .headers(headersFor(ex.getStatus()))
                .body(ApiResponse.error(machineCode(ex), message));
    }

    @SuppressWarnings("null")
    @ExceptionHandler(OAuthProtocolException.class)
    public ResponseEntity<Map<String, String>> handleOAuthProtocol(OAuthProtocolException ex) {
        var builder = ResponseEntity.status(ex.protocolStatus())
                .cacheControl(org.springframework.http.CacheControl.noStore())
                .header(org.springframework.http.HttpHeaders.PRAGMA, "no-cache");
        if ("invalid_client".equals(ex.getError())) {
            builder.header(org.springframework.http.HttpHeaders.WWW_AUTHENTICATE,
                    "Basic realm=\"oauth2/client\"");
        }
        return builder.body(Map.of(
                "error", ex.getError(), "error_description", ex.getDescription()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoResource(NoResourceFoundException ex) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error("resource_not_found", "Resource not found"));
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataAccess(DataAccessException ex) {
        meterRegistry.counter("security.infrastructure.failure", "component", "postgres").increment();
        log.error("Persistence failure", ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("persistence_unavailable", "Internal Server Error"));
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied(
            org.springframework.security.access.AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error("forbidden", "Forbidden"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("internal_error", "Internal Server Error"));
    }

    private org.springframework.http.HttpHeaders headersFor(HttpStatus status) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        if (status == HttpStatus.TOO_MANY_REQUESTS) {
            headers.set(org.springframework.http.HttpHeaders.RETRY_AFTER, "60");
        }
        return headers;
    }

    private String machineCode(ApiBaseException ex) {
        String simple = ex.getClass().getSimpleName().replaceFirst("Exception$", "");
        return simple.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT);
    }
}
