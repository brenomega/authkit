package io.github.brenomega.authkit.infrastructure.security;

import java.time.Duration;

public enum AbuseRateLimitPolicy {
    LOGIN_ENDPOINT_IP("login_endpoint_ip", 30, 10, Duration.ofMinutes(1), true),
    LOGIN_ENDPOINT_DEVICE("login_endpoint_device", 20, 8, Duration.ofMinutes(1), true),
    LOGIN_EMAIL("login_email", 8, 4, Duration.ofMinutes(15), true),
    MFA_VERIFY_IP("mfa_verify_ip", 20, 8, Duration.ofMinutes(1), true),
    MFA_VERIFY_USER("mfa_verify_user", 6, 3, Duration.ofMinutes(15), true),
    PASSKEY_ASSERTION_IP("passkey_assertion_ip", 30, 10, Duration.ofMinutes(1), true),
    PASSKEY_ASSERTION_DEVICE("passkey_assertion_device", 20, 8, Duration.ofMinutes(1), true),
    PASSKEY_ASSERTION_EMAIL("passkey_assertion_email", 10, 4, Duration.ofMinutes(15), true),
    REGISTRATION_IP("registration_ip", 20, 8, Duration.ofHours(1), true),
    REGISTRATION_EMAIL("registration_email", 3, 2, Duration.ofHours(24), true),
    EMAIL_CONFIRMATION_RESEND_IP("email_confirmation_resend_ip", 10, 5, Duration.ofHours(1), true),
    EMAIL_CONFIRMATION_RESEND_EMAIL_COOLDOWN("email_confirmation_resend_email_cooldown", 1, 1, Duration.ofMinutes(10), true),
    EMAIL_CONFIRMATION_RESEND_EMAIL_DAILY("email_confirmation_resend_email_daily", 5, 3, Duration.ofHours(24), true),
    PASSWORD_RECOVERY_IP("password_recovery_ip", 10, 5, Duration.ofHours(1), true),
    PASSWORD_RECOVERY_EMAIL_COOLDOWN("password_recovery_email_cooldown", 1, 1, Duration.ofMinutes(10), true),
    PASSWORD_RECOVERY_EMAIL_DAILY("password_recovery_email_daily", 5, 3, Duration.ofHours(24), true),
    PASSWORD_RESET_IP("password_reset_ip", 20, 8, Duration.ofHours(1), true),
    PASSWORD_RESET_EMAIL("password_reset_email", 6, 3, Duration.ofHours(1), true),
    REFRESH_IP("refresh_ip", 60, 20, Duration.ofMinutes(1), true),
    OAUTH_AUTHORIZE_IP("oauth_authorize_ip", 60, 20, Duration.ofMinutes(1), true),
    OAUTH_TOKEN_IP("oauth_token_ip", 60, 20, Duration.ofMinutes(1), true),
    OAUTH_CLIENT("oauth_client", 120, 50, Duration.ofMinutes(1), true),
    ADMIN_WRITE_TENANT("admin_write_tenant", 30, 10, Duration.ofMinutes(1), true),
    PROFILE_WRITE_USER("profile_write_user", 20, 8, Duration.ofHours(1), true),
    STEP_UP_PASSWORD_USER("step_up_password_user", 10, 5, Duration.ofMinutes(15), true),
    STEP_UP_MFA_USER("step_up_mfa_user", 10, 5, Duration.ofMinutes(15), true),
    MFA_CHANGE_USER("mfa_change_user", 10, 5, Duration.ofHours(1), true),
    PASSKEY_CHANGE_USER("passkey_change_user", 10, 5, Duration.ofHours(1), true),
    ACCOUNT_DELETION_USER("account_deletion_user", 5, 2, Duration.ofHours(24), true);

    private final String key;
    private final long globalCapacity;
    private final long degradedLocalCapacity;
    private final Duration window;
    private final boolean highRisk;

    AbuseRateLimitPolicy(String key, long globalCapacity, long degradedLocalCapacity, Duration window, boolean highRisk) {
        this.key = key;
        this.globalCapacity = globalCapacity;
        this.degradedLocalCapacity = degradedLocalCapacity;
        this.window = window;
        this.highRisk = highRisk;
    }

    public String key() {
        return key;
    }

    public long globalCapacity() {
        return globalCapacity;
    }

    public long degradedLocalCapacity() {
        return degradedLocalCapacity;
    }

    public Duration window() {
        return window;
    }

    public boolean highRisk() {
        return highRisk;
    }
}
