package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidRefreshTokenException extends ApiBaseException {

    public InvalidRefreshTokenException() {
        super("Invalid or expired refresh token", HttpStatus.UNAUTHORIZED);
    }
}
