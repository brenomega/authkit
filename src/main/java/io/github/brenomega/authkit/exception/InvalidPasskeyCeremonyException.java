package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class InvalidPasskeyCeremonyException extends ApiBaseException {

    public InvalidPasskeyCeremonyException() {
        super("Invalid or expired passkey ceremony", HttpStatus.BAD_REQUEST);
    }

    public InvalidPasskeyCeremonyException(Throwable cause) {
        super("Invalid or expired passkey ceremony", HttpStatus.BAD_REQUEST, cause);
    }
}
