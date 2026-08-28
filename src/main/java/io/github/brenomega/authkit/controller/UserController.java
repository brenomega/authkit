package io.github.brenomega.authkit.controller;

import io.github.brenomega.authkit.domain.user.dto.PasswordChangeRequest;
import io.github.brenomega.authkit.domain.mfa.dto.MfaBackupCodesResponse;
import io.github.brenomega.authkit.domain.mfa.dto.MfaOptionalVerificationRequest;
import io.github.brenomega.authkit.domain.mfa.dto.MfaStatusResponse;
import io.github.brenomega.authkit.domain.mfa.dto.MfaTotpConfirmRequest;
import io.github.brenomega.authkit.domain.mfa.dto.MfaTotpEnrollmentResponse;
import io.github.brenomega.authkit.domain.mfa.dto.MfaVerificationRequest;
import io.github.brenomega.authkit.domain.passkey.dto.PasskeyCredentialResponse;
import io.github.brenomega.authkit.domain.passkey.dto.PasskeyRegistrationFinishRequest;
import io.github.brenomega.authkit.domain.passkey.dto.PasskeyRegistrationOptionsResponse;
import io.github.brenomega.authkit.domain.user.dto.AccountDeletionResponse;
import io.github.brenomega.authkit.domain.user.dto.ConsentSnapshotResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.SessionPageResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.dto.UserDataExportResponse;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.AccountLifecycleService;
import io.github.brenomega.authkit.service.MfaService;
import io.github.brenomega.authkit.service.PasskeyService;
import io.github.brenomega.authkit.service.ProfileService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Adapts authenticated self-service account, MFA, passkey, and session use cases.
 *
 * <p>Operations are bound to the authenticated subject; the service layer also
 * verifies tenant and account state.</p>
 */
@RestController
@RequestMapping("/api/v1/users/me")
@PreAuthorize("hasAnyRole('USER', 'OWNER', 'TENANT_ADMIN', 'ADMIN')")
public class UserController {

    private final ProfileService profileService;
    private final AccountLifecycleService accountLifecycleService;
    private final MfaService mfaService;
    private final PasskeyService passkeyService;

    public UserController(ProfileService profileService,
                          AccountLifecycleService accountLifecycleService,
                          MfaService mfaService,
                          PasskeyService passkeyService) {
        this.profileService = profileService;
        this.accountLifecycleService = accountLifecycleService;
        this.mfaService = mfaService;
        this.passkeyService = passkeyService;
    }

    /**
     * Returns the authenticated subject's active profile.
     */
    @GetMapping
    public ApiResponse<ProfileResponse> getMyProfile(@AuthenticationPrincipal Jwt jwt) {
        ProfileResponse profile = profileService.getProfile(jwt.getSubject());
        return new ApiResponse<>(profile, null, Instant.now());
    }

    /**
     * Returns the current versioned consent snapshot for the authenticated user.
     */
    @GetMapping("/consent")
    public ApiResponse<ConsentSnapshotResponse> getMyConsent(@AuthenticationPrincipal Jwt jwt) {
        ConsentSnapshotResponse consent = accountLifecycleService.getConsentSnapshot(jwt.getSubject());
        return new ApiResponse<>(consent, null, Instant.now());
    }

    /**
     * Returns a privacy-safe data export for access requests.
     */
    @PostMapping("/export")
    public ApiResponse<UserDataExportResponse> exportMyData(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        UserDataExportResponse export = accountLifecycleService.exportUserData(jwt.getSubject(), request);
        return new ApiResponse<>(export, null, Instant.now());
    }

    /**
     * Updates only the subject's mutable profile attributes.
     */
    @PatchMapping
    public ApiResponse<ProfileResponse> updateMyProfile(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ProfileUpdateRequest request) {
        ProfileResponse updated = profileService.updateProfile(jwt.getSubject(), request, jwt.getSubject());
        return new ApiResponse<>(updated, null, Instant.now());
    }

    /**
     * Changes the password after step-up and preserves only the current session.
     */
    @PostMapping("/password")
    public ApiResponse<String> changePassword(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PasswordChangeRequest request) {
        profileService.changePassword(jwt.getSubject(), request, jwt.getId());
        return new ApiResponse<>("Password changed successfully. All other sessions revoked.", null, Instant.now());
    }

    /**
     * Lists a cursor page of the subject's active refresh sessions.
     */
    @GetMapping("/sessions")
    public ApiResponse<SessionPageResponse> getMySessions(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(required = false) String cursor) {
        SessionPageResponse sessions = profileService.listSessions(jwt.getSubject(), limit, cursor);
        return new ApiResponse<>(sessions, null, Instant.now());
    }

    @GetMapping("/mfa")
    public ApiResponse<MfaStatusResponse> getMfaStatus(@AuthenticationPrincipal Jwt jwt) {
        MfaStatusResponse status = mfaService.getStatus(jwt.getSubject());
        return new ApiResponse<>(status, null, Instant.now());
    }

    /** Starts TOTP enrollment after fresh password and optional MFA step-up. */
    @PostMapping("/mfa/totp/enroll")
    public ApiResponse<MfaTotpEnrollmentResponse> enrollTotp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        MfaTotpEnrollmentResponse response = mfaService.startTotpEnrollment(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Activates TOTP, returns backup codes once, and revokes existing sessions. */
    @PostMapping("/mfa/totp/confirm")
    public ApiResponse<MfaBackupCodesResponse> confirmTotp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody MfaTotpConfirmRequest request) {
        MfaBackupCodesResponse response = mfaService.confirmTotp(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Disables TOTP after step-up and revokes existing sessions. */
    @DeleteMapping("/mfa/totp")
    public ApiResponse<String> disableTotp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody MfaVerificationRequest request) {
        mfaService.disableTotp(jwt.getSubject(), request);
        return new ApiResponse<>("MFA disabled successfully.", null, Instant.now());
    }

    /** Replaces unused backup codes and returns the new raw codes once. */
    @PostMapping("/mfa/backup-codes")
    public ApiResponse<MfaBackupCodesResponse> regenerateBackupCodes(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody MfaVerificationRequest request) {
        MfaBackupCodesResponse response = mfaService.regenerateBackupCodes(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    @GetMapping("/passkeys")
    public ApiResponse<List<PasskeyCredentialResponse>> listPasskeys(@AuthenticationPrincipal Jwt jwt) {
        return new ApiResponse<>(passkeyService.list(jwt.getSubject()), null, Instant.now());
    }

    /** Starts a user-bound passkey registration after step-up. */
    @PostMapping("/passkeys/options")
    public ApiResponse<PasskeyRegistrationOptionsResponse> startPasskeyRegistration(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody(required = false) StepUpRequest request) {
        PasskeyRegistrationOptionsResponse response = passkeyService.startRegistration(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Completes passkey registration by consuming its challenge. */
    @PostMapping("/passkeys")
    public ApiResponse<PasskeyCredentialResponse> finishPasskeyRegistration(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PasskeyRegistrationFinishRequest request) {
        PasskeyCredentialResponse response = passkeyService.finishRegistration(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    @DeleteMapping("/passkeys/{credentialId}")
    public ApiResponse<String> disablePasskey(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID credentialId,
            @Valid @RequestBody(required = false) StepUpRequest request) {
        passkeyService.disable(jwt.getSubject(), credentialId, request);
        return new ApiResponse<>("Passkey disabled successfully.", null, Instant.now());
    }

    /**
     * Revokes one subject-owned session after optional MFA step-up.
     */
    @DeleteMapping("/sessions/{jti}")
    public ApiResponse<String> revokeSession(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable String jti,
            @Valid @RequestBody(required = false) MfaOptionalVerificationRequest request) {
        profileService.revokeSession(jwt.getSubject(), jti, request == null ? null : request.code());
        return new ApiResponse<>("Session revoked successfully.", null, Instant.now());
    }

    /**
     * Requests account deletion and immediately anonymizes direct PII.
     */
    @DeleteMapping
    public ApiResponse<AccountDeletionResponse> deleteMyAccount(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        AccountDeletionResponse deletion = accountLifecycleService.requestDeletion(jwt.getSubject(), request);
        return new ApiResponse<>(deletion, null, Instant.now());
    }
}
