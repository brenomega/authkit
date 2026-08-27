package io.github.brenomega.authkit.service;

import java.time.Instant;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.BootstrapAdminRequest;
import io.github.brenomega.authkit.domain.user.entity.BootstrapState;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.BootstrapStateRepository;
import io.github.brenomega.authkit.repository.UserRepository;

/** Transactional, database-serialized creation of the first platform administrator. */
@Service
public class BootstrapAdminService {

    private final BootstrapStateRepository bootstrapStateRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final ConsentEventService consentEventService;
    private final SecurityEventService securityEventService;
    private final AuthProperties authProperties;

    public BootstrapAdminService(BootstrapStateRepository bootstrapStateRepository,
                                 UserRepository userRepository,
                                 PasswordEncoder passwordEncoder,
                                 PasswordPolicyService passwordPolicyService,
                                 ConsentEventService consentEventService,
                                 SecurityEventService securityEventService,
                                 AuthProperties authProperties) {
        this.bootstrapStateRepository = bootstrapStateRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.consentEventService = consentEventService;
        this.securityEventService = securityEventService;
        this.authProperties = authProperties;
    }

    @Transactional
    public User bootstrap(BootstrapAdminRequest request) {
        BootstrapState state = bootstrapStateRepository
                .findByIdForUpdate(BootstrapState.SINGLETON_ID)
                .orElseThrow(() -> new IllegalStateException("Bootstrap database guard is missing"));
        if (state.isCompleted() || userRepository.countByRole(Role.PLATFORM_ADMIN) > 0) {
            throw new IllegalStateException("Platform administrator bootstrap is already complete");
        }
        if (!request.termsAccepted() || !request.privacyPolicyAccepted()) {
            throw new IllegalArgumentException("Terms and privacy policy acceptance are required");
        }

        String email = EmailNormalizer.normalize(request.email());
        passwordPolicyService.validateForRegistration(email, request.password());
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalStateException("Bootstrap identity conflicts with an existing account");
        }

        User admin = new User(
                email,
                passwordEncoder.encode(request.password()),
                request.name(),
                true,
                true,
                null);
        admin.setEmailConfirmed(true);
        admin.setRole(Role.PLATFORM_ADMIN);
        admin.recordConsent(
                authProperties.getCompliance().getTermsVersion(),
                authProperties.getCompliance().getPrivacyPolicyVersion(),
                authProperties.getCompliance().getLawfulBasis(),
                Instant.now());
        try {
            admin = userRepository.saveAndFlush(admin);
        } catch (DataIntegrityViolationException ex) {
            throw new IllegalStateException("Bootstrap identity conflicts with an existing account", ex);
        }

        consentEventService.recordCurrentConsent(admin);
        securityEventService.record(
                SecurityEventType.BOOTSTRAP,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.CRITICAL,
                admin.getId(),
                admin.getId(),
                admin.getTenantId(),
                admin.getEmail(),
                "first_platform_admin_bootstrapped",
                java.util.Map.of("mfa_enrollment_required", "true"));
        state.complete(admin.getId(), Instant.now());
        bootstrapStateRepository.save(state);
        return admin;
    }
}
