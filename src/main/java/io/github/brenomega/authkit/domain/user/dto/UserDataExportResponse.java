package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.List;

/**
 * Privacy-safe account data export for LGPD/GDPR access requests.
 */
public record UserDataExportResponse(
        String schemaVersion,
        Instant generatedAt,
        ProfileData profile,
        ConsentData consent,
        List<ConsentEventData> consentHistory,
        List<OAuthConsentData> oauthConsents,
        CredentialData credentials,
        List<SessionData> sessions,
        DeletionData deletion,
        List<SecurityEventData> securityEvents
) {

    public record ProfileData(
            String id,
            String email,
            String name,
            String role,
            String tenantId,
            boolean emailConfirmed,
            String accountState,
            Instant suspendedAt,
            String suspensionReason,
            String pendingEmail,
            Instant emailChangeRequestedAt,
            Instant emailChangeExpiresAt
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

    public record ConsentEventData(
            String termsVersion,
            String privacyPolicyVersion,
            String lawfulBasis,
            Instant acceptedAt,
            Instant recordedAt,
            String eventHash
    ) {
    }

    public record OAuthConsentData(
            String clientId,
            List<String> scopes,
            Instant grantedAt,
            Instant revokedAt
    ) {
    }

    public record CredentialData(
            boolean localPasswordConfigured,
            List<PasswordHistoryData> passwordHistory,
            List<TotpData> totp,
            List<PasskeyData> passkeys,
            List<SocialIdentityData> socialIdentities
    ) {}

    public record PasswordHistoryData(Instant recordedAt) {}
    public record TotpData(String id, Instant createdAt, Instant confirmedAt, Instant disabledAt) {}
    public record PasskeyData(String id, String label, String transports, boolean discoverable,
                              long signatureCount, Instant createdAt, Instant lastUsedAt, Instant disabledAt) {}
    public record SocialIdentityData(String id, String providerKey, String issuer, String emailAtLink,
                                     boolean emailVerified, Instant createdAt, Instant lastLoginAt) {}
    public record SessionData(String sessionId, Instant createdAt, Instant lastSeenAt, Instant expiresAt,
                              List<String> initialAmr, String userAgentSummary, String deviceLabel,
                              String creationIpMasked, String lastIpMasked) {}

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
