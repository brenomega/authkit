package io.github.brenomega.authkit.domain.passkey.dto;

import java.util.UUID;

/** Carries browser-ready creation options and their server-side challenge identity. */
public record PasskeyRegistrationOptionsResponse(
        UUID challengeId,
        String publicKeyCredentialCreationOptionsJson
) {
}
