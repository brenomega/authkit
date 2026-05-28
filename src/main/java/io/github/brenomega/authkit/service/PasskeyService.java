package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyChallenge;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyChallengeType;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.PasskeyAssertionFinishRequest;
import io.github.brenomega.authkit.domain.user.dto.PasskeyAssertionOptionsRequest;
import io.github.brenomega.authkit.domain.user.dto.PasskeyAssertionOptionsResponse;
import io.github.brenomega.authkit.domain.user.dto.PasskeyCredentialResponse;
import io.github.brenomega.authkit.domain.user.dto.PasskeyRegistrationFinishRequest;
import io.github.brenomega.authkit.domain.user.dto.PasskeyRegistrationOptionsResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.exception.InvalidPasskeyCeremonyException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.JpaWebAuthnCredentialRepository;
import io.github.brenomega.authkit.repository.PasskeyChallengeRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@Service
public class PasskeyService {

    private final UserRepository userRepository;
    private final PasskeyCredentialRepository credentialRepository;
    private final PasskeyChallengeRepository challengeRepository;
    private final RelyingParty relyingParty;
    private final MfaService mfaService;
    private final AuthService authService;
    private final AuthProperties authProperties;
    private final SecurityEventService securityEventService;
    private final StepUpService stepUpService;
    private final AbuseThrottleService abuseThrottleService;

    public PasskeyService(UserRepository userRepository,
                          PasskeyCredentialRepository credentialRepository,
                          PasskeyChallengeRepository challengeRepository,
                          RelyingParty relyingParty,
                          MfaService mfaService,
                          AuthService authService,
                          AuthProperties authProperties,
                          SecurityEventService securityEventService,
                          StepUpService stepUpService,
                          AbuseThrottleService abuseThrottleService) {
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
        this.challengeRepository = challengeRepository;
        this.relyingParty = relyingParty;
        this.mfaService = mfaService;
        this.authService = authService;
        this.authProperties = authProperties;
        this.securityEventService = securityEventService;
        this.stepUpService = stepUpService;
        this.abuseThrottleService = abuseThrottleService;
    }

    @Transactional(readOnly = true)
    public List<PasskeyCredentialResponse> list(String userId) {
        User user = loadActiveUser(userId);
        return credentialRepository.findByUserIdAndDisabledAtIsNullOrderByCreatedAtDesc(user.getId())
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public PasskeyRegistrationOptionsResponse startRegistration(String userId, StepUpRequest request) {
        ensureEnabled();
        User user = loadActiveUser(userId);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.PASSKEY_CHANGE_USER, user);
        verifyPasswordStepUp(user,
                request == null ? null : request.currentPassword(),
                SecurityEventType.PASSKEY_REGISTRATION_STARTED,
                "passkey_registration_step_up_failed");
        mfaService.requireMfaIfEnabled(user, request == null ? null : request.mfaCode(), "passkey_registration");

        UserIdentity identity = UserIdentity.builder()
                .name(user.getId().toString())
                .displayName(displayName(user))
                .id(JpaWebAuthnCredentialRepository.userHandle(user.getId()))
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(identity)
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .residentKey(ResidentKeyRequirement.PREFERRED)
                                .userVerification(UserVerificationRequirement.REQUIRED)
                                .build())
                        .timeout(authProperties.getPasskey().getChallengeTtlMinutes() * 60_000)
                        .build());

        Instant now = Instant.now();
        PasskeyChallenge challenge = challengeRepository.save(new PasskeyChallenge(
                PasskeyChallengeType.REGISTRATION,
                user.getId(),
                toJson(options),
                now,
                now.plusSeconds(authProperties.getPasskey().getChallengeTtlMinutes() * 60)));

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.PASSKEY_REGISTRATION_STARTED,
                SecurityEventOutcome.INFO,
                SecurityEventSeverity.MEDIUM,
                user,
                "passkey_registration_started");

        return new PasskeyRegistrationOptionsResponse(challenge.getId(), toCredentialsCreateJson(options));
    }

    @Transactional
    public PasskeyCredentialResponse finishRegistration(String userId, PasskeyRegistrationFinishRequest request) {
        ensureEnabled();
        User user = loadActiveUser(userId);
        PasskeyChallenge challenge = loadChallenge(request.challengeId(), PasskeyChallengeType.REGISTRATION)
                .filter(existing -> user.getId().equals(existing.getUserId()))
                .orElseThrow(InvalidPasskeyCeremonyException::new);

        try {
            PublicKeyCredentialCreationOptions options =
                    PublicKeyCredentialCreationOptions.fromJson(challenge.getRequestJson());
            RegistrationResult result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                    .request(options)
                    .response(PublicKeyCredential.parseRegistrationResponseJson(request.credentialJson()))
                    .build());

            if (challengeRepository.consume(challenge.getId(), PasskeyChallengeType.REGISTRATION, Instant.now()) != 1) {
                throw new InvalidPasskeyCeremonyException();
            }

            String transports = result.getKeyId().getTransports()
                    .stream()
                    .flatMap(java.util.Collection::stream)
                    .map(AuthenticatorTransport::getId)
                    .sorted()
                    .collect(Collectors.joining(","));

            PasskeyCredential credential = credentialRepository.save(new PasskeyCredential(
                    user.getId(),
                    user.getTenantId(),
                    result.getKeyId().getId().getBase64Url(),
                    result.getPublicKeyCose().getBase64Url(),
                    result.getSignatureCount(),
                    transports,
                    request.label(),
                    result.isDiscoverable().orElse(false),
                    Instant.now()));

            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.PASSKEY_REGISTERED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.HIGH,
                    user,
                    "passkey_registered");

            return toResponse(credential);
        } catch (InvalidPasskeyCeremonyException ex) {
            throw ex;
        } catch (Exception ex) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.PASSKEY_FAILED,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH,
                    user,
                    "passkey_registration_failed");
            throw new InvalidPasskeyCeremonyException(ex);
        }
    }

    @Transactional
    public PasskeyAssertionOptionsResponse startAssertion(PasskeyAssertionOptionsRequest request) {
        ensureEnabled();
        StartAssertionOptions.StartAssertionOptionsBuilder builder = StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.REQUIRED)
                .timeout(authProperties.getPasskey().getChallengeTtlMinutes() * 60_000);

        UUID userId = null;
        if (request != null && request.email() != null && !request.email().isBlank()) {
            String normalizedEmail = EmailNormalizer.normalize(request.email());
            abuseThrottleService.checkEmail(AbuseRateLimitPolicy.PASSKEY_ASSERTION_EMAIL, normalizedEmail);
            User user = userRepository.findByEmail(normalizedEmail)
                    .filter(existing -> !existing.isDeleted())
                    .orElse(null);
            if (user != null) {
                userId = user.getId();
                builder.username(user.getId().toString());
            }
        }

        AssertionRequest assertionRequest = relyingParty.startAssertion(builder.build());
        Instant now = Instant.now();
        PasskeyChallenge challenge = challengeRepository.save(new PasskeyChallenge(
                PasskeyChallengeType.ASSERTION,
                userId,
                toJson(assertionRequest),
                now,
                now.plusSeconds(authProperties.getPasskey().getChallengeTtlMinutes() * 60)));

        securityEventService.record(
                SecurityEventType.PASSKEY_AUTHENTICATION_STARTED,
                SecurityEventOutcome.INFO,
                SecurityEventSeverity.LOW,
                userId,
                userId,
                null,
                null,
                "passkey_assertion_started",
                java.util.Map.of());

        return new PasskeyAssertionOptionsResponse(challenge.getId(), toCredentialsGetJson(assertionRequest));
    }

    @Transactional
    public AuthService.LoginResult finishAssertion(PasskeyAssertionFinishRequest request) {
        ensureEnabled();
        PasskeyChallenge challenge = loadChallenge(request.challengeId(), PasskeyChallengeType.ASSERTION)
                .orElseThrow(InvalidPasskeyCeremonyException::new);

        try {
            AssertionRequest assertionRequest = AssertionRequest.fromJson(challenge.getRequestJson());
            var result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(assertionRequest)
                    .response(PublicKeyCredential.parseAssertionResponseJson(request.credentialJson()))
                    .build());

            if (!result.isSuccess()) {
                throw new InvalidPasskeyCeremonyException();
            }
            if (challengeRepository.consume(challenge.getId(), PasskeyChallengeType.ASSERTION, Instant.now()) != 1) {
                throw new InvalidPasskeyCeremonyException();
            }

            UUID userId = UUID.fromString(result.getUsername());
            if (challenge.getUserId() != null && !challenge.getUserId().equals(userId)) {
                throw new InvalidPasskeyCeremonyException();
            }
            @SuppressWarnings("null")
            User user = userRepository.findById(userId)
                    .filter(existing -> !existing.isDeleted())
                    .orElseThrow(InvalidPasskeyCeremonyException::new);

            credentialRepository.markUsed(
                    result.getCredential().getCredentialId().getBase64Url(),
                    user.getId(),
                    result.getSignatureCount(),
                    Instant.now());

            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.PASSKEY_AUTHENTICATED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.MEDIUM,
                    user,
                    "passkey_authenticated");

            return authService.issueLoginForVerifiedUser(user, List.of("webauthn"), "login_success_passkey");
        } catch (InvalidPasskeyCeremonyException ex) {
            throw ex;
        } catch (Exception ex) {
            securityEventService.record(
                    SecurityEventType.PASSKEY_FAILED,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH,
                    challenge.getUserId(),
                    challenge.getUserId(),
                    null,
                    null,
                    "passkey_assertion_failed",
                    java.util.Map.of());
            throw new InvalidPasskeyCeremonyException(ex);
        }
    }

    @Transactional
    public void disable(String userId, UUID credentialId, StepUpRequest request) {
        User user = loadActiveUser(userId);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.PASSKEY_CHANGE_USER, user);
        verifyPasswordStepUp(user,
                request == null ? null : request.currentPassword(),
                SecurityEventType.PASSKEY_DISABLED,
                "passkey_disable_step_up_failed");
        mfaService.requireMfaIfEnabled(user, request == null ? null : request.mfaCode(), "passkey_disable");
        int updated = credentialRepository.disable(credentialId, user.getId(), Instant.now());
        if (updated != 1) {
            throw new UserNotFoundException();
        }
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.PASSKEY_DISABLED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "passkey_disabled");
    }

    private Optional<PasskeyChallenge> loadChallenge(UUID challengeId, PasskeyChallengeType type) {
        Instant now = Instant.now();
        return challengeRepository.findByIdAndCeremonyType(challengeId, type)
                .filter(challenge -> challenge.getConsumedAt() == null)
                .filter(challenge -> challenge.getExpiresAt().isAfter(now));
    }

    private PasskeyCredentialResponse toResponse(PasskeyCredential credential) {
        return new PasskeyCredentialResponse(
                credential.getId(),
                credential.getCredentialId(),
                credential.getLabel(),
                credential.getTransports(),
                credential.isDiscoverable(),
                credential.getCreatedAt(),
                credential.getLastUsedAt());
    }

    private User loadActiveUser(String userId) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        if (user.isDeleted()) {
            throw new UserNotFoundException();
        }
        user.requireEmailConfirmed();
        return user;
    }

    private void requireTenantAccess(User user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return;
        }
        String tenantId = JwtTenantResolver.extractTenantId(jwt);
        if (tenantId == null || !tenantId.equals(user.getTenantId().toString())) {
            throw new UserNotFoundException();
        }
    }

    private void ensureEnabled() {
        if (!authProperties.getPasskey().isEnabled()) {
            throw new InvalidPasskeyCeremonyException();
        }
    }

    private String displayName(User user) {
        if (user.getName() != null && !user.getName().isBlank()) {
            return user.getName();
        }
        return user.getEmail().toLowerCase(Locale.ROOT);
    }

    private void verifyPasswordStepUp(User user,
                                      String currentPassword,
                                      SecurityEventType eventType,
                                      String failureReason) {
        stepUpService.verifyCurrentPassword(user, currentPassword, eventType, failureReason);
    }

    private String toJson(PublicKeyCredentialCreationOptions options) {
        try {
            return options.toJson();
        } catch (JsonProcessingException ex) {
            throw new InvalidPasskeyCeremonyException(ex);
        }
    }

    private String toJson(AssertionRequest request) {
        try {
            return request.toJson();
        } catch (JsonProcessingException ex) {
            throw new InvalidPasskeyCeremonyException(ex);
        }
    }

    private String toCredentialsCreateJson(PublicKeyCredentialCreationOptions options) {
        try {
            return options.toCredentialsCreateJson();
        } catch (JsonProcessingException ex) {
            throw new InvalidPasskeyCeremonyException(ex);
        }
    }

    private String toCredentialsGetJson(AssertionRequest request) {
        try {
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException ex) {
            throw new InvalidPasskeyCeremonyException(ex);
        }
    }
}
