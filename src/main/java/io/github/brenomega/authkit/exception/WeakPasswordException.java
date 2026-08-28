package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that a candidate violates composition, breach, or reuse policy. */
public class WeakPasswordException extends ApiBaseException {

    public WeakPasswordException() {
        super("Password does not meet security policy", HttpStatus.BAD_REQUEST);
    }
}
