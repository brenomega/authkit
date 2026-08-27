package io.github.brenomega.authkit.domain.social.dto;

import io.github.brenomega.authkit.domain.user.dto.LoginResponse;

public record SocialCallbackResponse(String status, LoginResponse login) {
    public static SocialCallbackResponse linked() { return new SocialCallbackResponse("linked", null); }
    public static SocialCallbackResponse authenticated(LoginResponse login) { return new SocialCallbackResponse("authenticated", login); }
}
