package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that a social OIDC ceremony or verified provider response cannot be accepted. */
public class InvalidSocialLoginException extends ApiBaseException {
    public InvalidSocialLoginException() { super("Invalid or expired social login", HttpStatus.BAD_REQUEST); }
    public InvalidSocialLoginException(Throwable cause) { super(
        "Invalid or expired social login",
        HttpStatus.BAD_REQUEST,
        cause); }
}
