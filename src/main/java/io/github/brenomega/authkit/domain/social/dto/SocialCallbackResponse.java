package io.github.brenomega.authkit.domain.social.dto;

import io.github.brenomega.authkit.domain.user.dto.LoginResponse;

/** Carries either a completed social login result or a non-login ceremony outcome. */
public record SocialCallbackResponse(String status, LoginResponse login) {
    public static SocialCallbackResponse linked() { return new SocialCallbackResponse("linked", null); }
    public static SocialCallbackResponse authenticated(LoginResponse login) { return new SocialCallbackResponse(
        "authenticated",
        login); }
}
