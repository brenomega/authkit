package io.github.brenomega.authkit.infrastructure.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

class ConsentEventServiceTest {

    @Test
    void hashesExactlyTheTimestampPrecisionPersistedByPostgres() {
        ConsentEventRepository repository = mock(ConsentEventRepository.class);
        AuthProperties properties = new AuthProperties();
        properties.getAudit().setHashPepper("unit-test-audit-hash-pepper-at-least-32-chars");
        AuditDigestService digests = new AuditDigestService(properties);
        ConsentEventService service = new ConsentEventService(repository, digests);
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        Instant acceptedAt = Instant.parse("2026-09-08T16:02:03.123456789Z");
        when(user.isTermsAccepted()).thenReturn(true);
        when(user.isPrivacyPolicyAccepted()).thenReturn(true);
        when(user.getConsentAcceptedAt()).thenReturn(acceptedAt);
        when(user.getId()).thenReturn(userId);
        when(user.getTenantId()).thenReturn(tenantId);
        when(user.getTermsVersion()).thenReturn("terms-v1");
        when(user.getPrivacyPolicyVersion()).thenReturn("privacy-v1");
        when(user.getLawfulBasis()).thenReturn("consent");

        service.recordCurrentConsent(user);

        ArgumentCaptor<ConsentEvent> event = ArgumentCaptor.forClass(ConsentEvent.class);
        verify(repository).save(event.capture());
        ConsentEvent saved = event.getValue();
        assertEquals(123_456_000, saved.getAcceptedAt().getNano());
        assertEquals(0, saved.getRecordedAt().getNano() % 1_000);
        assertEquals(saved.getEventHash(), digests.hmacHex(String.join("|", userId.toString(), tenantId.toString(),
                "terms-v1", "privacy-v1", "consent", saved.getAcceptedAt().toString(),
                saved.getRecordedAt().toString())));
    }
}
