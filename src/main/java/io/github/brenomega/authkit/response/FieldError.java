package io.github.brenomega.authkit.response;

/** Identifies one rejected input field without exposing the submitted value. */
public record FieldError(
        String field,
        String message
) {
}
