package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record OAuthAuthorizeRequest(
        @NotBlank @Pattern(regexp = "code") String responseType,
        @NotBlank @Size(max = 128) String clientId,
        @NotBlank @Size(max = 512) String redirectUri,
        @NotBlank @Size(max = 512) String scope,
        @Size(max = 255) String state,
        @NotBlank @Size(min = 43, max = 128) String codeChallenge,
        @NotBlank @Pattern(regexp = "S256") String codeChallengeMethod,
        @Size(max = 255) String nonce,
        Boolean consentAccepted
) {
}
