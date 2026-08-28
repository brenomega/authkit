package io.github.brenomega.authkit.domain.passkey.dto;

import java.util.UUID;

/** Carries browser-ready assertion options and their server-side challenge identity. */
public record PasskeyAssertionOptionsResponse(
        UUID challengeId,
        String publicKeyCredentialRequestOptionsJson
) {
}
