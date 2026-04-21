package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when a requested resource does not exist or when access is denied
 * due to ownership violations (DT 3.2.24).
 *
 * <p>Per DT 3.2.24, endpoints that enforce data ownership must return
 * {@code 404 Not Found} instead of {@code 403 Forbidden} to prevent
 * attackers from confirming the existence of third-party resource IDs.</p>
 */
public class ResourceNotFoundException extends ApiBaseException {

    /**
     * @param message a description of the missing resource
     */
    public ResourceNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
