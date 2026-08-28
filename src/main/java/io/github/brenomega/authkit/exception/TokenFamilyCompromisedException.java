package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates first-party refresh replay after atomic revocation of the active token family. */
public class TokenFamilyCompromisedException extends ApiBaseException {

    public TokenFamilyCompromisedException() {
        super("Refresh token reuse detected. All sessions revoked for your security.",
                HttpStatus.UNAUTHORIZED);
    }
}
