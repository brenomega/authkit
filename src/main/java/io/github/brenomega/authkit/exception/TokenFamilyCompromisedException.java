package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a refresh token reuse attack is detected (DT 3.2.5).
 *
 * <p>Indicates that a previously rotated refresh token has been replayed.
 * Immediately revokes the entire token family to prevent unauthorized access.</p>
 */
public class TokenFamilyCompromisedException extends ApiBaseException {

    public TokenFamilyCompromisedException() {
        super("Refresh token reuse detected. All sessions revoked for your security.",
                HttpStatus.UNAUTHORIZED);
    }
}
