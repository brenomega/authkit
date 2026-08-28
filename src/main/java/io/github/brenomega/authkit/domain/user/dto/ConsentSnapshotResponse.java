package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/** Describes the consent versions and lawful basis retained on the current account. */
public record ConsentSnapshotResponse(
        boolean termsAccepted,
        boolean privacyPolicyAccepted,
        String termsVersion,
        String privacyPolicyVersion,
        Instant consentAcceptedAt,
        String lawfulBasis
) {
}
