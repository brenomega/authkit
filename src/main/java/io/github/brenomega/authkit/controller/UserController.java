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
import io.github.brenomega.authkit.domain.user.dto.EmailChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.EmailChangeStatusResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.SessionPageResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.dto.UserDataExportResponse;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.AccountLifecycleService;
import io.github.brenomega.authkit.service.EmailChangeService;
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
 * Exposes authenticated self-service account and authenticator operations.
 * The subject is always taken from the verified first-party JWT; services enforce
 * current tenant, account, session, and step-up invariants rather than accepting an
 * arbitrary target user from the request.
 */
@RestController
@RequestMapping("/api/v1/users/me")
@PreAuthorize("hasAnyRole('USER', 'PLATFORM_ADMIN')")
public class UserController {

    private final ProfileService profileService;
    private final AccountLifecycleService accountLifecycleService;
    private final MfaService mfaService;
    private final PasskeyService passkeyService;
    private final EmailChangeService emailChangeService;

    public UserController(ProfileService profileService,
                          AccountLifecycleService accountLifecycleService,
                          MfaService mfaService,
                          PasskeyService passkeyService,
                          EmailChangeService emailChangeService) {
        this.profileService = profileService;
        this.accountLifecycleService = accountLifecycleService;
        this.mfaService = mfaService;
        this.passkeyService = passkeyService;
        this.emailChangeService = emailChangeService;
    }

    @GetMapping
    public ApiResponse<ProfileResponse> getMyProfile(@AuthenticationPrincipal Jwt jwt) {
        ProfileResponse profile = profileService.getProfile(jwt.getSubject());
        return new ApiResponse<>(profile, null, Instant.now());
    }

    @GetMapping("/consent")
    public ApiResponse<ConsentSnapshotResponse> getMyConsent(@AuthenticationPrincipal Jwt jwt) {
        ConsentSnapshotResponse consent = accountLifecycleService.getConsentSnapshot(jwt.getSubject());
        return new ApiResponse<>(consent, null, Instant.now());
    }

    /** Produces a credential-secret-free account export after strong step-up. */
    @PostMapping("/export")
    public ApiResponse<UserDataExportResponse> exportMyData(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        UserDataExportResponse export = accountLifecycleService.exportUserData(jwt.getSubject(), request);
        return new ApiResponse<>(export, null, Instant.now());
    }

    @PatchMapping
    public ApiResponse<ProfileResponse> updateMyProfile(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ProfileUpdateRequest request) {
        ProfileResponse updated = profileService.updateProfile(jwt.getSubject(), request, jwt.getSubject());
        return new ApiResponse<>(updated, null, Instant.now());
    }

    /** Starts a verified, expiring email-change ceremony after strong step-up. */
    @PostMapping("/email-change")
    public ApiResponse<EmailChangeStatusResponse> requestEmailChange(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody EmailChangeRequest request) {
        return ApiResponse.success(emailChangeService.request(jwt.getSubject(), request));
    }

    /** Cancels pending email change with the same strong step-up policy. */
    @DeleteMapping("/email-change")
    public ApiResponse<EmailChangeStatusResponse> cancelEmailChange(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        return ApiResponse.success(emailChangeService.cancel(jwt.getSubject(), request));
    }

    /** Replaces the local password and preserves only the caller's current session. */
    @PostMapping("/password")
    public ApiResponse<String> changePassword(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PasswordChangeRequest request) {
        profileService.changePassword(jwt.getSubject(), request, jwt.getId());
        return new ApiResponse<>("Password changed successfully. All other sessions revoked.", null, Instant.now());
    }

    /** Enumerates active sessions with opaque, owner-bound continuation cursors. */
    @GetMapping("/sessions")
    public ApiResponse<SessionPageResponse> getMySessions(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(required = false) String cursor) {
        SessionPageResponse sessions = profileService.listSessions(jwt.getSubject(), jwt.getId(), limit, cursor);
        return new ApiResponse<>(sessions, null, Instant.now());
    }

    @GetMapping("/mfa")
    public ApiResponse<MfaStatusResponse> getMfaStatus(@AuthenticationPrincipal Jwt jwt) {
        MfaStatusResponse status = mfaService.getStatus(jwt.getSubject());
        return new ApiResponse<>(status, null, Instant.now());
    }

    /** Returns new TOTP enrollment material after password step-up. */
    @PostMapping("/mfa/totp/enroll")
    public ApiResponse<MfaTotpEnrollmentResponse> enrollTotp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        MfaTotpEnrollmentResponse response = mfaService.startTotpEnrollment(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Consumes the first TOTP step and returns the only plaintext copy of new backup codes. */
    @PostMapping("/mfa/totp/confirm")
    public ApiResponse<MfaBackupCodesResponse> confirmTotp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody MfaTotpConfirmRequest request) {
        MfaBackupCodesResponse response = mfaService.confirmTotp(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Disables TOTP after password and MFA verification and revokes existing sessions. */
    @DeleteMapping("/mfa/totp")
    public ApiResponse<String> disableTotp(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody MfaVerificationRequest request) {
        mfaService.disableTotp(jwt.getSubject(), request);
        return new ApiResponse<>("MFA disabled successfully.", null, Instant.now());
    }

    /** Replaces all unused backup codes after strong step-up. */
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

    /** Starts user-bound passkey registration after the required step-up. */
    @PostMapping("/passkeys/options")
    public ApiResponse<PasskeyRegistrationOptionsResponse> startPasskeyRegistration(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody(required = false) StepUpRequest request) {
        PasskeyRegistrationOptionsResponse response = passkeyService.startRegistration(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Consumes a registration challenge and persists the verified public credential. */
    @PostMapping("/passkeys")
    public ApiResponse<PasskeyCredentialResponse> finishPasskeyRegistration(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PasskeyRegistrationFinishRequest request) {
        PasskeyCredentialResponse response = passkeyService.finishRegistration(jwt.getSubject(), request);
        return new ApiResponse<>(response, null, Instant.now());
    }

    /** Disables an owned passkey without allowing removal of the final authenticator. */
    @DeleteMapping("/passkeys/{credentialId}")
    public ApiResponse<String> disablePasskey(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID credentialId,
            @Valid @RequestBody(required = false) StepUpRequest request) {
        passkeyService.disable(jwt.getSubject(), credentialId, request);
        return new ApiResponse<>("Passkey disabled successfully.", null, Instant.now());
    }

    /** Revokes an opaque user-owned session after active MFA policy is satisfied. */
    @DeleteMapping("/sessions/{sessionId}")
    public ApiResponse<String> revokeSession(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable String sessionId,
            @Valid @RequestBody(required = false) MfaOptionalVerificationRequest request) {
        profileService.revokeSession(jwt.getSubject(), sessionId, request == null ? null : request.code());
        return new ApiResponse<>("Session revoked successfully.", null, Instant.now());
    }

    /** Requests deletion after strong step-up while preserving the final platform administrator. */
    @DeleteMapping
    public ApiResponse<AccountDeletionResponse> deleteMyAccount(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody StepUpRequest request) {
        AccountDeletionResponse deletion = accountLifecycleService.requestDeletion(jwt.getSubject(), request);
        return new ApiResponse<>(deletion, null, Instant.now());
    }
}
