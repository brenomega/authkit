package io.github.brenomega.authkit.domain.passkey.dto;

import java.util.UUID;

public record PasskeyRegistrationOptionsResponse(
        UUID challengeId,
        String publicKeyCredentialCreationOptionsJson
) {
}
