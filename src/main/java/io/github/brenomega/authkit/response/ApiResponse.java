package io.github.brenomega.authkit.response;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        T data,
        List<String> errors,
        Instant timestamp,
        String code,
        String requestId
) {

    public ApiResponse(T data, List<String> errors, Instant timestamp) {
        this(data, errors, timestamp, null, RequestContext.currentRequestId());
    }

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(data, null, Instant.now());
    }

    public static <T> ApiResponse<T> error(String message) {
        return error("request_failed", message);
    }

    public static <T> ApiResponse<T> error(String code, String message) {
        return new ApiResponse<>(null, List.of(message), Instant.now(), code, RequestContext.currentRequestId());
    }

    public static <T> ApiResponse<T> errors(List<String> messages) {
        return new ApiResponse<>(null, messages, Instant.now(), "request_failed", RequestContext.currentRequestId());
    }

    public static ApiResponse<List<FieldError>> validationError(List<FieldError> fieldErrors) {
        return new ApiResponse<>(fieldErrors, List.of("Validation failed"), Instant.now(),
                "validation_failed", RequestContext.currentRequestId());
    }
}
