package io.github.brenomega.authkit.domain.user.entity;

import java.time.Instant;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.domain.user.enums.Role;
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
 * Represents an account's identity, tenant, consent, and deletion lifecycle.
 *
 * <p>The JPA-generated identity and tenant identifier are UUIDs. Authentication
 * requires a confirmed email and an account not marked deleted or anonymized.
 * Deletion is an irreversible domain transition that replaces direct identifiers,
 * clears confirmation and consent flags, and makes the account inactive.</p>
 *
 * <p>The entity remains independent of Spring Security. Its log representation
 * masks email and excludes password and activation material.</p>
 *
 * @see io.github.brenomega.authkit.infrastructure.security.SecurityUser
 */
@Entity
@Table(name = "users")
@FilterDef(name = "tenantFilter", parameters = {@ParamDef(name = "tenantId", type = String.class)})
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class User {

    private static final String DEFAULT_TERMS_VERSION = "terms-v1";
    private static final String DEFAULT_PRIVACY_POLICY_VERSION = "privacy-v1";
    private static final String DEFAULT_LAWFUL_BASIS = "consent";

    /**
     * Universally unique identifier — primary key (DT 3.1.21).
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private java.util.UUID id;

    /**
     * User's email address, used as the login credential.
     */
    @NotBlank
    @Email
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    /**
     * Hashed password (Argon2id). The plaintext value is never stored (DT 3.2.1).
     */
    @NotBlank
    @Column(name = "password", nullable = false)
    private String password;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 50)
    private Role role = Role.USER;

    /**
     * Multi-tenancy isolation identifier.
     */
    @Column(name = "tenant_id", nullable = false, unique = true, updatable = false)
    private java.util.UUID tenantId;

    /** Optional display name. */
    @Column(name = "name", length = 100)
    private String name;

    /** Optional contact phone number. */
    @Column(name = "phone", length = 20)
    private String phone;

    /** Proof of acceptance of Terms of Use. */
    @Column(name = "terms_accepted", nullable = false)
    private boolean termsAccepted;

    /** Proof of acceptance of Privacy Policy. */
    @Column(name = "privacy_policy_accepted", nullable = false)
    private boolean privacyPolicyAccepted;

    /** Restricts full write capabilities until verified. */
    @Column(name = "email_confirmed", nullable = false)
    private boolean emailConfirmed;

    /** SHA-256 hash of the current one-time email-confirmation token. */
    @Column(name = "email_confirmation_token", length = 100)
    private String emailConfirmationToken;

    /** Expiration for the current email confirmation token. */
    @Column(name = "email_confirmation_expires_at")
    private Instant emailConfirmationExpiresAt;

    /** Terms of Use version accepted by the user. */
    @Column(name = "terms_version", nullable = false, length = 64)
    private String termsVersion = DEFAULT_TERMS_VERSION;

    /** Privacy Policy version accepted by the user. */
    @Column(name = "privacy_policy_version", nullable = false, length = 64)
    private String privacyPolicyVersion = DEFAULT_PRIVACY_POLICY_VERSION;

    /** Timestamp of consent acceptance for terms/privacy. */
    @Column(name = "consent_accepted_at")
    private Instant consentAcceptedAt;

    /** Lawful basis for processing the account data. */
    @Column(name = "lawful_basis", nullable = false, length = 64)
    private String lawfulBasis = DEFAULT_LAWFUL_BASIS;

    /** Timestamp when account deletion was requested. */
    @Column(name = "deletion_requested_at")
    private Instant deletionRequestedAt;

    /** Timestamp when the account was deleted or made inactive. */
    @Column(name = "deleted_at")
    private Instant deletedAt;

    /** Timestamp when direct PII was anonymized. */
    @Column(name = "anonymized_at")
    private Instant anonymizedAt;

    protected User() {
    }

    /**
     * Creates a new user mapping explicitly from registration coordinates.
     * Generates a universally unique tenant identifier tied to the user upon creation.
     */
    public User(String email, String password, String name, String phone,
                boolean termsAccepted, boolean privacyPolicyAccepted,
                String emailConfirmationToken) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.phone = phone;
        this.termsAccepted = termsAccepted;
        this.privacyPolicyAccepted = privacyPolicyAccepted;
        this.emailConfirmationToken = emailConfirmationToken;
        recordConsent(DEFAULT_TERMS_VERSION, DEFAULT_PRIVACY_POLICY_VERSION, DEFAULT_LAWFUL_BASIS, Instant.now());

        this.role = Role.USER;
        this.tenantId = java.util.UUID.randomUUID();
        this.emailConfirmed = false;
    }

    public java.util.UUID getId() {
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

    public java.util.UUID getTenantId() { return tenantId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    public boolean isTermsAccepted() { return termsAccepted; }
    public boolean isPrivacyPolicyAccepted() { return privacyPolicyAccepted; }
    public boolean isEmailConfirmed() { return emailConfirmed; }
    public void setEmailConfirmed(boolean emailConfirmed) { this.emailConfirmed = emailConfirmed; }
    public String getEmailConfirmationToken() { return emailConfirmationToken; }
    public void setEmailConfirmationToken(String emailConfirmationToken) { this.emailConfirmationToken = emailConfirmationToken; }
    public Instant getEmailConfirmationExpiresAt() { return emailConfirmationExpiresAt; }
    public void setEmailConfirmationExpiresAt(Instant emailConfirmationExpiresAt) { this.emailConfirmationExpiresAt = emailConfirmationExpiresAt; }
    public String getTermsVersion() { return termsVersion; }
    public String getPrivacyPolicyVersion() { return privacyPolicyVersion; }
    public Instant getConsentAcceptedAt() { return consentAcceptedAt; }
    public String getLawfulBasis() { return lawfulBasis; }
    public Instant getDeletionRequestedAt() { return deletionRequestedAt; }
    public Instant getDeletedAt() { return deletedAt; }
    public Instant getAnonymizedAt() { return anonymizedAt; }

    /** Records policy versions and an acceptance timestamp only when both required consents are true. */
    public void recordConsent(String termsVersion, String privacyPolicyVersion, String lawfulBasis, Instant acceptedAt) {
        this.termsVersion = termsVersion;
        this.privacyPolicyVersion = privacyPolicyVersion;
        this.lawfulBasis = lawfulBasis;
        this.consentAcceptedAt = (termsAccepted && privacyPolicyAccepted) ? acceptedAt : null;
    }

    /** Returns whether deletion or anonymization has made the account inactive. */
    public boolean isDeleted() {
        return deletedAt != null || anonymizedAt != null;
    }

    /** Records the first deletion-request timestamp and preserves it on retries. */
    public void requestDeletion(Instant requestedAt) {
        if (this.deletionRequestedAt == null) {
            this.deletionRequestedAt = requestedAt;
        }
    }

    /** Replaces direct identity data and completes the account's deletion transition. */
    public void anonymizeForDeletion(String anonymizedEmail, String anonymizedPasswordHash, Instant anonymizedAt) {
        requestDeletion(anonymizedAt);
        this.email = anonymizedEmail;
        this.password = anonymizedPasswordHash;
        this.name = null;
        this.phone = null;
        this.emailConfirmationToken = null;
        this.emailConfirmationExpiresAt = null;
        this.emailConfirmed = false;
        this.termsAccepted = false;
        this.privacyPolicyAccepted = false;
        this.deletedAt = anonymizedAt;
        this.anonymizedAt = anonymizedAt;
    }

    /**
     * Guards operations that require a confirmed email address.
     *
     * @throws EmailNotConfirmedException if the email has not been confirmed
     */
    public void requireEmailConfirmed() {
        if (!this.emailConfirmed || isDeleted()) {
            throw new EmailNotConfirmedException();
        }
    }

    /**
     * Returns a log-safe string that masks the email and excludes the password.
     *
     * @return a representation containing no password or unmasked email
     */
    @Override
    public String toString() {
        return "User{id='" + id + "', email='" + EmailMasker.mask(email) + "', role=" + role + '}';
    }
}
