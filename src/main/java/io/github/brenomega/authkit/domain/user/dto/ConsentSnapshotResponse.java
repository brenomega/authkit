package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/**
 * Versioned consent state held for the authenticated account.
 */
public record ConsentSnapshotResponse(
        boolean termsAccepted,
        boolean privacyPolicyAccepted,
        String termsVersion,
        String privacyPolicyVersion,
        Instant consentAcceptedAt,
        String lawfulBasis
) {
}
