package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.List;

/**
 * Privacy-safe account data export for LGPD/GDPR access requests.
 */
public record UserDataExportResponse(
        ProfileData profile,
        ConsentData consent,
        DeletionData deletion,
        List<SecurityEventData> securityEvents
) {

    public record ProfileData(
            String id,
            String email,
            String name,
            String phone,
            String role,
            String tenantId,
            boolean emailConfirmed
    ) {
    }

    public record ConsentData(
            boolean termsAccepted,
            boolean privacyPolicyAccepted,
            String termsVersion,
            String privacyPolicyVersion,
            Instant consentAcceptedAt,
            String lawfulBasis
    ) {
    }

    public record DeletionData(
            Instant deletionRequestedAt,
            Instant deletedAt,
            Instant anonymizedAt
    ) {
    }

    public record SecurityEventData(
            Instant occurredAt,
            String type,
            String outcome,
            String severity,
            String emailMasked,
            String clientIpMasked,
            String requestMethod,
            String requestPath,
            String reason
    ) {
    }
}
