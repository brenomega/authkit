package io.github.brenomega.authkit.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.mfa.entity.MfaBackupCode;
import io.github.brenomega.authkit.domain.mfa.entity.MfaTotpCredential;
import io.github.brenomega.authkit.domain.mfa.util.Base32;
import io.github.brenomega.authkit.domain.mfa.util.TotpGenerator;
import io.github.brenomega.authkit.domain.user.dto.MfaBackupCodesResponse;
import io.github.brenomega.authkit.domain.user.dto.MfaStatusResponse;
import io.github.brenomega.authkit.domain.user.dto.MfaTotpConfirmRequest;
import io.github.brenomega.authkit.domain.user.dto.MfaTotpEnrollmentResponse;
import io.github.brenomega.authkit.domain.user.dto.MfaVerificationRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidMfaCodeException;
import io.github.brenomega.authkit.exception.MfaAlreadyEnabledException;
import io.github.brenomega.authkit.exception.MfaRequiredException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.MfaSecretCipher;
import io.github.brenomega.authkit.repository.MfaBackupCodeRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * MFA enrollment, verification, and recovery-code lifecycle.
 */
@Service
public class MfaService {

    private static final String BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final int BACKUP_CODE_GROUPS = 3;
    private static final int BACKUP_CODE_GROUP_LENGTH = 4;

    private final UserRepository userRepository;
    private final MfaTotpCredentialRepository totpRepository;
    private final MfaBackupCodeRepository backupCodeRepository;
    private final MfaSecretCipher mfaSecretCipher;
    private final PasswordEncoder passwordEncoder;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final AuthProperties authProperties;
    private final SecurityEventService securityEventService;
    private final AuditDigestService auditDigestService;
    private final TokenStorage tokenStorage;
    private final TotpGenerator totpGenerator = new TotpGenerator();
    private final SecureRandom secureRandom = new SecureRandom();

    public MfaService(UserRepository userRepository,
                      MfaTotpCredentialRepository totpRepository,
                      MfaBackupCodeRepository backupCodeRepository,
                      MfaSecretCipher mfaSecretCipher,
                      PasswordEncoder passwordEncoder,
                      Argon2ConcurrencyLimiter argon2Limiter,
                      AuthProperties authProperties,
                      SecurityEventService securityEventService,
                      AuditDigestService auditDigestService,
                      TokenStorage tokenStorage) {
        this.userRepository = userRepository;
        this.totpRepository = totpRepository;
        this.backupCodeRepository = backupCodeRepository;
        this.mfaSecretCipher = mfaSecretCipher;
        this.passwordEncoder = passwordEncoder;
        this.argon2Limiter = argon2Limiter;
        this.authProperties = authProperties;
        this.securityEventService = securityEventService;
        this.auditDigestService = auditDigestService;
        this.tokenStorage = tokenStorage;
    }

    @Transactional(readOnly = true)
    public MfaStatusResponse getStatus(String userId) {
        User user = loadActiveUser(userId);
        List<MfaTotpCredential> activeCredentials = totpRepository
                .findByUserIdAndConfirmedTrueAndDisabledAtIsNull(user.getId());
        Instant enrolledAt = activeCredentials.stream()
                .map(MfaTotpCredential::getConfirmedAt)
                .filter(java.util.Objects::nonNull)
                .min(Instant::compareTo)
                .orElse(null);
        return new MfaStatusResponse(
                !activeCredentials.isEmpty(),
                backupCodeRepository.countByUserIdAndUsedAtIsNull(user.getId()),
                enrolledAt);
    }

    @Transactional
    public MfaTotpEnrollmentResponse startTotpEnrollment(String userId, StepUpRequest request) {
        User user = loadActiveUser(userId);
        verifyPasswordStepUp(user, request == null ? null : request.currentPassword(),
                SecurityEventType.MFA_CHANGED, "mfa_enrollment_step_up_failed");

        if (totpRepository.existsByUserIdAndConfirmedTrueAndDisabledAtIsNull(user.getId())) {
            throw new MfaAlreadyEnabledException();
        }

        totpRepository.deleteByUserIdAndConfirmedFalse(user.getId());

        byte[] secretBytes = new byte[20];
        secureRandom.nextBytes(secretBytes);
        String secret = Base32.encode(secretBytes);
        MfaTotpCredential credential = totpRepository.save(new MfaTotpCredential(
                user.getId(),
                user.getTenantId(),
                mfaSecretCipher.encrypt(secret),
                Instant.now()));

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.MFA_CHANGED,
                SecurityEventOutcome.INFO,
                SecurityEventSeverity.MEDIUM,
                user,
                "totp_enrollment_started");

        return new MfaTotpEnrollmentResponse(
                credential.getId(),
                secret,
                provisioningUri(user.getEmail(), secret));
    }

    @Transactional
    public MfaBackupCodesResponse confirmTotp(String userId, MfaTotpConfirmRequest request) {
        User user = loadActiveUser(userId);
        verifyPasswordStepUp(user, request.currentPassword(),
                SecurityEventType.MFA_CHANGED, "mfa_confirmation_step_up_failed");

        if (totpRepository.existsByUserIdAndConfirmedTrueAndDisabledAtIsNull(user.getId())) {
            throw new MfaAlreadyEnabledException();
        }

        MfaTotpCredential credential = totpRepository.findByIdAndUserId(request.credentialId(), user.getId())
                .filter(existing -> existing.getDisabledAt() == null)
                .orElseThrow(InvalidMfaCodeException::new);
        String secret = mfaSecretCipher.decrypt(credential.getEncryptedSecret());
        var result = totpGenerator.verify(secret, request.code(), null);
        if (!result.valid()) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "totp_confirmation_invalid_code");
            throw new InvalidMfaCodeException();
        }

        credential.confirm(Instant.now());
        credential.markTimeStepUsed(result.timeStep());
        List<String> backupCodes = regenerateBackupCodes(user);
        tokenStorage.revokeAllSessions(user.getId().toString());

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.MFA_CHANGED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "totp_enabled");

        return new MfaBackupCodesResponse(backupCodes);
    }

    @Transactional
    public void disableTotp(String userId, MfaVerificationRequest request) {
        User user = loadActiveUser(userId);
        verifyPasswordStepUp(user, request.currentPassword(),
                SecurityEventType.MFA_CHANGED, "mfa_disable_password_step_up_failed");
        requireMfaIfEnabled(user, request.code(), "mfa_disable");

        Instant now = Instant.now();
        totpRepository.findByUserIdAndConfirmedTrueAndDisabledAtIsNull(user.getId())
                .forEach(credential -> credential.disable(now));
        backupCodeRepository.deleteByUserIdAndUsedAtIsNull(user.getId());
        tokenStorage.revokeAllSessions(user.getId().toString());

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.MFA_CHANGED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "totp_disabled");
    }

    @Transactional
    public MfaBackupCodesResponse regenerateBackupCodes(String userId, MfaVerificationRequest request) {
        User user = loadActiveUser(userId);
        verifyPasswordStepUp(user, request.currentPassword(),
                SecurityEventType.MFA_BACKUP_CODES_REGENERATED,
                "backup_code_regeneration_password_step_up_failed");
        requireMfaIfEnabled(user, request.code(), "backup_code_regeneration");

        List<String> backupCodes = regenerateBackupCodes(user);
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.MFA_BACKUP_CODES_REGENERATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "backup_codes_regenerated");
        return new MfaBackupCodesResponse(backupCodes);
    }

    @Transactional(readOnly = true)
    public boolean isMfaEnabled(User user) {
        return authProperties.getMfa().isEnabled()
                && totpRepository.existsByUserIdAndConfirmedTrueAndDisabledAtIsNull(user.getId());
    }

    @Transactional
    public MfaVerificationResult verifyMfaCode(User user, String code, String reason) {
        if (!authProperties.getMfa().isEnabled() || code == null || code.isBlank()) {
            return MfaVerificationResult.invalid();
        }

        String normalizedCode = normalizeCode(code);
        List<MfaTotpCredential> activeCredentials =
                totpRepository.findByUserIdAndConfirmedTrueAndDisabledAtIsNull(user.getId());
        if (activeCredentials.isEmpty()) {
            return MfaVerificationResult.invalid();
        }

        for (MfaTotpCredential credential : activeCredentials) {
            String secret = mfaSecretCipher.decrypt(credential.getEncryptedSecret());
            var result = totpGenerator.verify(secret, normalizedCode, credential.getLastUsedTimeStep());
            if (result.valid()
                    && totpRepository.markTimeStepUsedIfNewer(
                            credential.getId(), user.getId(), result.timeStep()) == 1) {
                return MfaVerificationResult.totp();
            }
        }

        String backupHash = backupCodeHash(user.getId(), normalizedCode);
        if (backupCodeRepository.consumeUnusedCode(user.getId(), backupHash, Instant.now()) == 1) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.MFA_BACKUP_CODE_USED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.HIGH,
                    user,
                    reason + "_backup_code_used");
            return MfaVerificationResult.backupCode();
        }

        return MfaVerificationResult.invalid();
    }

    @Transactional
    public void requireMfaIfEnabled(User user, String code, String reason) {
        if (!isMfaEnabled(user)) {
            return;
        }
        if (code == null || code.isBlank()) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    reason + "_mfa_missing");
            throw new MfaRequiredException();
        }
        if (!verifyMfaCode(user, code, reason).valid()) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    reason + "_mfa_invalid");
            throw new InvalidMfaCodeException();
        }
    }

    private List<String> regenerateBackupCodes(User user) {
        backupCodeRepository.deleteByUserIdAndUsedAtIsNull(user.getId());
        List<String> rawCodes = new ArrayList<>();
        for (int i = 0; i < authProperties.getMfa().getBackupCodeCount(); i++) {
            String code = newBackupCode();
            rawCodes.add(code);
            backupCodeRepository.save(new MfaBackupCode(
                    user.getId(),
                    user.getTenantId(),
                    backupCodeHash(user.getId(), normalizeCode(code)),
                    Instant.now()));
        }
        return List.copyOf(rawCodes);
    }

    private void verifyPasswordStepUp(User user,
                                      String currentPassword,
                                      SecurityEventType eventType,
                                      String failureReason) {
        if (currentPassword == null || currentPassword.isBlank()) {
            securityEventService.recordForAuthenticatedUser(
                    eventType,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    failureReason);
            throw new InvalidCredentialsException();
        }

        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                securityEventService.recordForAuthenticatedUser(
                        eventType,
                        SecurityEventOutcome.DENIED,
                        SecurityEventSeverity.HIGH,
                        user,
                        failureReason);
                throw new InvalidCredentialsException();
            }
        } finally {
            argon2Limiter.release();
        }
    }

    private User loadActiveUser(String userId) {
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

    private String provisioningUri(String email, String secret) {
        String issuer = "AuthKit";
        String label = issuer + ":" + email;
        return "otpauth://totp/" + urlEncode(label)
                + "?secret=" + urlEncode(secret)
                + "&issuer=" + urlEncode(issuer)
                + "&algorithm=SHA1"
                + "&digits=6"
                + "&period=30";
    }

    private String newBackupCode() {
        StringBuilder code = new StringBuilder();
        for (int group = 0; group < BACKUP_CODE_GROUPS; group++) {
            if (group > 0) {
                code.append('-');
            }
            for (int i = 0; i < BACKUP_CODE_GROUP_LENGTH; i++) {
                code.append(BACKUP_CODE_ALPHABET.charAt(secureRandom.nextInt(BACKUP_CODE_ALPHABET.length())));
            }
        }
        return code.toString();
    }

    private String backupCodeHash(UUID userId, String code) {
        return auditDigestService.hmacHex("mfa-backup-code|" + userId + '|' + code);
    }

    private String normalizeCode(String code) {
        return code.replace("-", "")
                .replace(" ", "")
                .toUpperCase(Locale.ROOT);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public record MfaVerificationResult(boolean valid, String method) {
        public static MfaVerificationResult invalid() {
            return new MfaVerificationResult(false, null);
        }

        public static MfaVerificationResult totp() {
            return new MfaVerificationResult(true, "otp");
        }

        public static MfaVerificationResult backupCode() {
            return new MfaVerificationResult(true, "backup_code");
        }
    }
}
