package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that the account must accept the currently configured policy versions. */
public class ConsentRequiredException extends ApiBaseException {

    public ConsentRequiredException() {
        super("Current terms and privacy policy acceptance is required", HttpStatus.FORBIDDEN);
    }
}
