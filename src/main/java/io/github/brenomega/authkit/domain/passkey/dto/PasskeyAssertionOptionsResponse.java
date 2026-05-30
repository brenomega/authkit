package io.github.brenomega.authkit.domain.passkey.dto;

import java.util.UUID;

public record PasskeyAssertionOptionsResponse(
        UUID challengeId,
        String publicKeyCredentialRequestOptionsJson
) {
}
