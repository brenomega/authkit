package io.github.brenomega.authkit.domain.oauth.dto;
import jakarta.validation.constraints.NotNull;
/** Carries the resource owner's decision for a previously bound authorization transaction. */
public record OAuthAuthorizationDecisionRequest(@NotNull Boolean approved){}
