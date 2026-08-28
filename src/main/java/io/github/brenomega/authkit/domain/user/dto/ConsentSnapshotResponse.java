package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

public record ConsentSnapshotResponse(
        boolean termsAccepted,
        boolean privacyPolicyAccepted,
        String termsVersion,
        String privacyPolicyVersion,
        Instant consentAcceptedAt,
        String lawfulBasis
) {
}
