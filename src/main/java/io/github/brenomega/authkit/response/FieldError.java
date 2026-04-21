package io.github.brenomega.authkit.response;

/**
 * Represents a single field-level validation error (DT 3.4.10).
 *
 * <p>Returned inside the {@link ApiResponse} data payload when a request
 * fails Jakarta Bean Validation, allowing clients to map errors to
 * specific input fields programmatically.</p>
 *
 * @param field   the name of the field that failed validation
 * @param message the human-readable validation message
 */
public record FieldError(
        String field,
        String message
) {
}
