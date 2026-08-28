package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class TokenFamilyCompromisedException extends ApiBaseException {

    public TokenFamilyCompromisedException() {
        super("Refresh token reuse detected. All sessions revoked for your security.",
                HttpStatus.UNAUTHORIZED);
    }
}
