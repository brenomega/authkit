package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class WeakPasswordException extends ApiBaseException {

    public WeakPasswordException() {
        super("Password does not meet security policy", HttpStatus.BAD_REQUEST);
    }
}
