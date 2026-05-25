package io.github.brenomega.authkit.domain.user.dto;

/**
 * Generic registration acknowledgement used when public deployments hide
 * whether the submitted email already belongs to an account.
 */
public record RegistrationAcceptedResponse(String message) {
}
