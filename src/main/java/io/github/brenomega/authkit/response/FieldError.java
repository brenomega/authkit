package io.github.brenomega.authkit.response;

public record FieldError(
        String field,
        String message
) {
}
