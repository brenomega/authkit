package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.entity.User;

@Service
public class ConsentEventService {

    private final ConsentEventRepository repository;
    private final AuditDigestService auditDigestService;

    public ConsentEventService(ConsentEventRepository repository, AuditDigestService auditDigestService) {
        this.repository = repository;
        this.auditDigestService = auditDigestService;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordCurrentConsent(User user) {
        if (!user.isTermsAccepted() || !user.isPrivacyPolicyAccepted() || user.getConsentAcceptedAt() == null) {
            return;
        }

        Instant recordedAt = Instant.now();
        String eventHash = auditDigestService.hmacHex(String.join("|",
                user.getId().toString(),
                user.getTenantId().toString(),
                user.getTermsVersion(),
                user.getPrivacyPolicyVersion(),
                user.getLawfulBasis(),
                user.getConsentAcceptedAt().toString(),
                recordedAt.toString()));

        repository.save(new ConsentEvent(
                user.getId(),
                user.getTenantId(),
                user.getTermsVersion(),
                user.getPrivacyPolicyVersion(),
                user.getLawfulBasis(),
                user.getConsentAcceptedAt(),
                recordedAt,
                eventHash));
    }
}
