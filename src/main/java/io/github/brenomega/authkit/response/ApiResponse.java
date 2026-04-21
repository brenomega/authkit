package io.github.brenomega.authkit.response;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Standardized API response envelope (DT 3.1.8).
 *
 * <p>Every endpoint in the system returns this structure, ensuring that
 * clients always receive a consistent JSON shape regardless of success
 * or failure.</p>
 *
 * <p>Example success payload:</p>
 * <pre>{@code
 * { "data": { ... }, "errors": null, "timestamp": "2026-04-21T..." }
 * }</pre>
 *
 * <p>Example error payload:</p>
 * <pre>{@code
 * { "data": null, "errors": ["Invalid credentials"], "timestamp": "2026-04-21T..." }
 * }</pre>
 *
 * @param <T> the type of the response body
 * @param data      the response payload (null on error)
 * @param errors    error details (null on success)
 * @param timestamp the UTC instant when the response was created
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        T data,
        List<String> errors,
        Instant timestamp
) {

    /**
     * Creates a successful response containing the given payload.
     *
     * @param data the response body
     * @param <T>  the payload type
     * @return a timestamped success envelope
     */
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(data, null, Instant.now());
    }

    /**
     * Creates an error response with a single message.
     *
     * @param message the error description
     * @param <T>     the (absent) payload type
     * @return a timestamped error envelope
     */
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(null, List.of(message), Instant.now());
    }

    /**
     * Creates an error response with multiple messages.
     *
     * @param messages the error descriptions
     * @param <T>      the (absent) payload type
     * @return a timestamped error envelope
     */
    public static <T> ApiResponse<T> errors(List<String> messages) {
        return new ApiResponse<>(null, messages, Instant.now());
    }

    /**
     * Creates a validation error response with per-field details (DT 3.4.10).
     *
     * @param fieldErrors the list of field-level validation failures
     * @return a timestamped error envelope with structured field errors
     */
    public static ApiResponse<List<FieldError>> validationError(List<FieldError> fieldErrors) {
        return new ApiResponse<>(fieldErrors, List.of("Validation failed"), Instant.now());
    }
}
