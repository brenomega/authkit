package io.github.brenomega.authkit.domain.user.entity;

import java.time.Instant;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.exception.AccountNotActiveException;
import io.github.brenomega.authkit.exception.EmailNotConfirmedException;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;

/**
 * Represents the tenant-owned account and its security lifecycle.
 *
 * <p>The account is the aggregate for role, local-password presence, confirmed
 * email, consent snapshot, suspension, pending deletion, and pending email change.
 * Email identities are normalized before reaching the entity. Deletion is a state
 * transition followed by irreversible anonymization; a deleted account cannot be
 * reactivated. Social-only accounts intentionally have no password hash.</p>
 */
@Entity
@Table(name = "users")
@FilterDef(name = "tenantFilter", parameters = {@ParamDef(name = "tenantId", type = String.class)})
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class User {

    private static final String DEFAULT_TERMS_VERSION = "terms-v1";
    private static final String DEFAULT_PRIVACY_POLICY_VERSION = "privacy-v1";
    private static final String DEFAULT_LAWFUL_BASIS = "consent";

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @NotBlank
    @Email
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "password")
    private String password;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 50)
    private Role role = Role.USER;

    @Column(name = "tenant_id", nullable = false, unique = true, updatable = false)
    private UUID tenantId;

    @Column(name = "name", length = 100)
    private String name;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "account_state", nullable = false, length = 32)
    private AccountState accountState = AccountState.ACTIVE;

    @Column(name = "suspended_at")
    private Instant suspendedAt;

    @Column(name = "suspension_reason", length = 500)
    private String suspensionReason;

    @Column(name = "terms_accepted", nullable = false)
    private boolean termsAccepted;

    @Column(name = "privacy_policy_accepted", nullable = false)
    private boolean privacyPolicyAccepted;

    @Column(name = "email_confirmed", nullable = false)
    private boolean emailConfirmed;

    @Column(name = "email_confirmation_token", length = 100)
    private String emailConfirmationToken;

    @Column(name = "email_confirmation_expires_at")
    private Instant emailConfirmationExpiresAt;

    @Email
    @Column(name = "pending_email", length = 255)
    private String pendingEmail;

    @Column(name = "email_change_token_hash", length = 64)
    private String emailChangeTokenHash;

    @Column(name = "email_change_expires_at")
    private Instant emailChangeExpiresAt;

    @Column(name = "email_change_requested_at")
    private Instant emailChangeRequestedAt;

    @Column(name = "terms_version", nullable = false, length = 64)
    private String termsVersion = DEFAULT_TERMS_VERSION;

    @Column(name = "privacy_policy_version", nullable = false, length = 64)
    private String privacyPolicyVersion = DEFAULT_PRIVACY_POLICY_VERSION;

    @Column(name = "consent_accepted_at")
    private Instant consentAcceptedAt;

    @Column(name = "lawful_basis", nullable = false, length = 64)
    private String lawfulBasis = DEFAULT_LAWFUL_BASIS;

    @Column(name = "deletion_requested_at")
    private Instant deletionRequestedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    @Column(name = "anonymized_at")
    private Instant anonymizedAt;

    protected User() {
    }

    public User(String email, String password, String name,
                boolean termsAccepted, boolean privacyPolicyAccepted,
                String emailConfirmationToken) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.termsAccepted = termsAccepted;
        this.privacyPolicyAccepted = privacyPolicyAccepted;
        this.emailConfirmationToken = emailConfirmationToken;
        recordConsent(DEFAULT_TERMS_VERSION, DEFAULT_PRIVACY_POLICY_VERSION, DEFAULT_LAWFUL_BASIS, Instant.now());

        this.role = Role.USER;
        this.tenantId = UUID.randomUUID();
        this.emailConfirmed = false;
        this.accountState = AccountState.ACTIVE;
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public UUID getTenantId() { return tenantId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public AccountState getAccountState() { return accountState; }
    public Instant getSuspendedAt() { return suspendedAt; }
    public String getSuspensionReason() { return suspensionReason; }
    public boolean isTermsAccepted() { return termsAccepted; }
    public boolean isPrivacyPolicyAccepted() { return privacyPolicyAccepted; }
    public boolean isEmailConfirmed() { return emailConfirmed; }
    public void setEmailConfirmed(boolean emailConfirmed) { this.emailConfirmed = emailConfirmed; }
    public String getEmailConfirmationToken() { return emailConfirmationToken; }
    public void setEmailConfirmationToken(String emailConfirmationToken) {
        this.emailConfirmationToken = emailConfirmationToken;
    }
    public Instant getEmailConfirmationExpiresAt() { return emailConfirmationExpiresAt; }
    public void setEmailConfirmationExpiresAt(Instant emailConfirmationExpiresAt) {
        this.emailConfirmationExpiresAt = emailConfirmationExpiresAt;
    }
    public String getPendingEmail() { return pendingEmail; }
    public String getEmailChangeTokenHash() { return emailChangeTokenHash; }
    public Instant getEmailChangeExpiresAt() { return emailChangeExpiresAt; }
    public Instant getEmailChangeRequestedAt() { return emailChangeRequestedAt; }
    public String getTermsVersion() { return termsVersion; }
    public String getPrivacyPolicyVersion() { return privacyPolicyVersion; }
    public Instant getConsentAcceptedAt() { return consentAcceptedAt; }
    public String getLawfulBasis() { return lawfulBasis; }
    public Instant getDeletionRequestedAt() { return deletionRequestedAt; }
    public Instant getDeletedAt() { return deletedAt; }
    public Instant getAnonymizedAt() { return anonymizedAt; }

    public void recordConsent(
        String termsVersion,
        String privacyPolicyVersion,
        String lawfulBasis,
        Instant acceptedAt) {
        this.termsVersion = termsVersion;
        this.privacyPolicyVersion = privacyPolicyVersion;
        this.lawfulBasis = lawfulBasis;
        this.consentAcceptedAt = (termsAccepted && privacyPolicyAccepted) ? acceptedAt : null;
    }

    /** Returns whether deletion has been requested or completed. */
    public boolean isDeleted() {
        return accountState == AccountState.ANONYMIZED;
    }

    /** Returns whether the account may participate in authentication and user operations. */
    public boolean isActive() {
        return accountState == AccountState.ACTIVE;
    }

    /** Suspends an active account with a required operator reason. */
    public void suspend(String reason, Instant now) {
        if (accountState == AccountState.ANONYMIZED) {
            throw new IllegalStateException("An anonymized account cannot be suspended");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Suspension reason is required");
        }
        this.accountState = AccountState.SUSPENDED;
        this.suspendedAt = now;
        this.suspensionReason = reason.trim();
    }

    /**
     * Restores a suspended account.
     * @throws AccountNotActiveException if the account is not currently suspended
     */
    public void reactivate() {
        if (accountState != AccountState.SUSPENDED) {
            throw new IllegalStateException("Only a suspended account can be reactivated");
        }
        this.accountState = AccountState.ACTIVE;
        this.suspendedAt = null;
        this.suspensionReason = null;
    }

    /** Moves an active account into the deletion grace-period state. */
    public void requestDeletion(Instant requestedAt) {
        if (this.deletionRequestedAt == null) {
            this.deletionRequestedAt = requestedAt;
        }
        this.accountState = AccountState.DELETION_PENDING;
    }

    /** Restores an account whose deletion is still pending and not yet anonymized. */
    public void cancelDeletion() {
        if (accountState != AccountState.DELETION_PENDING) {
            throw new IllegalStateException("No deletion request is pending");
        }
        this.deletionRequestedAt = null;
        this.accountState = AccountState.ACTIVE;
    }

    public void requestEmailChange(String newEmail, String tokenHash, Instant requestedAt, Instant expiresAt) {
        requireEmailConfirmed();
        this.pendingEmail = newEmail;
        this.emailChangeTokenHash = tokenHash;
        this.emailChangeRequestedAt = requestedAt;
        this.emailChangeExpiresAt = expiresAt;
    }

    /**
     * Promotes the pending address, clears the ceremony, and returns the previous address.
     * @throws IllegalStateException when no pending address exists
     */
    public String completeEmailChange() {
        requireEmailConfirmed();
        if (pendingEmail == null || emailChangeTokenHash == null || emailChangeExpiresAt == null) {
            throw new IllegalStateException("No email change is pending");
        }
        String previousEmail = this.email;
        this.email = this.pendingEmail;
        clearPendingEmailChange();
        return previousEmail;
    }

    public void cancelEmailChange() {
        if (pendingEmail == null) {
            throw new IllegalStateException("No email change is pending");
        }
        clearPendingEmailChange();
    }

    public void clearPendingEmailChange() {
        this.pendingEmail = null;
        this.emailChangeTokenHash = null;
        this.emailChangeRequestedAt = null;
        this.emailChangeExpiresAt = null;
    }

    /**
     * Irreversibly removes authenticators, consent identifiers, profile data, and pending ceremonies.
     * The supplied unique tombstone email preserves relational integrity without retaining the original identity.
     */
    public void anonymizeForDeletion(String anonymizedEmail, Instant anonymizedAt) {
        requestDeletion(anonymizedAt);
        this.email = anonymizedEmail;
        this.password = null;
        this.name = null;
        this.emailConfirmationToken = null;
        this.emailConfirmationExpiresAt = null;
        clearPendingEmailChange();
        this.emailConfirmed = false;
        this.termsAccepted = false;
        this.privacyPolicyAccepted = false;
        this.deletedAt = anonymizedAt;
        this.anonymizedAt = anonymizedAt;
        this.accountState = AccountState.ANONYMIZED;
        this.suspendedAt = null;
        this.suspensionReason = null;
    }

    public void requireActive() {
        if (!isActive()) {
            throw new AccountNotActiveException();
        }
    }

    public void requireEmailConfirmed() {
        requireActive();
        if (!this.emailConfirmed) {
            throw new EmailNotConfirmedException();
        }
    }

    @Override
    public String toString() {
        return "User{id='" + id + "', email='" + EmailMasker.mask(email) + "', role=" + role + '}';
    }
}
