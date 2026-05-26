package io.github.brenomega.authkit.domain.user.dto;

import java.util.UUID;

public record PasskeyRegistrationOptionsResponse(
        UUID challengeId,
        String publicKeyCredentialCreationOptionsJson
) {
}
