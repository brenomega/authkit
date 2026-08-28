package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

/** Indicates that a verified social email matches an account but explicit authenticated linking is required. */
public class SocialLinkRequiredException extends ApiBaseException {
    public SocialLinkRequiredException() {
        super("Existing account authentication and explicit social linking required", HttpStatus.CONFLICT);
    }
}
