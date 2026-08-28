package io.github.brenomega.authkit.domain.social.dto;

/** Captures consent assertions bound to a new social-login transaction. */
public record SocialLoginStartRequest(boolean termsAccepted, boolean privacyPolicyAccepted) {}
