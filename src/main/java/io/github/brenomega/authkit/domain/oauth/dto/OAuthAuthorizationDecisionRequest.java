package io.github.brenomega.authkit.domain.oauth.dto;
import jakarta.validation.constraints.NotNull;
public record OAuthAuthorizationDecisionRequest(@NotNull Boolean approved){}
