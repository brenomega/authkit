package io.github.brenomega.authkit.exception;

import org.springframework.http.HttpStatus;

public class SocialLinkRequiredException extends ApiBaseException {
    public SocialLinkRequiredException() {
        super("Existing account authentication and explicit social linking required", HttpStatus.CONFLICT);
    }
}
