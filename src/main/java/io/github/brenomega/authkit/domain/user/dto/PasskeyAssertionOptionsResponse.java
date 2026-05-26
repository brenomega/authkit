package io.github.brenomega.authkit.domain.user.dto;

import java.util.UUID;

public record PasskeyAssertionOptionsResponse(
        UUID challengeId,
        String publicKeyCredentialRequestOptionsJson
) {
}
