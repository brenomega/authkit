package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/** Describes the consent versions and lawful basis retained on the current account. */
public record ConsentSnapshotResponse(
        boolean termsAccepted,
        boolean privacyPolicyAccepted,
        String acceptedTermsVersion,
        String acceptedPrivacyPolicyVersion,
        String requiredTermsVersion,
        String requiredPrivacyPolicyVersion,
        boolean consentRequired,
        Instant consentAcceptedAt,
        String lawfulBasis
) {
}
