package io.github.brenomega.authkit.domain.user.dto;

import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record PasskeyAssertionFinishRequest(
        @NotNull UUID challengeId,
        @NotBlank @Size(max = 20000) String credentialJson
) {
}
