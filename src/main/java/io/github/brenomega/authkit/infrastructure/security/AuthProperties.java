package io.github.brenomega.authkit.infrastructure.security;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Type-safe runtime configuration for AuthKit authentication surfaces.
 *
 * <p>These settings are intentionally externalized because token lifetimes,
 * cookie posture, issuer identity, and public frontend URLs vary between
 * deployments while the service remains stateless.</p>
 */
@Validated
@ConfigurationProperties(prefix = "authkit.auth")
public class AuthProperties {

    @Valid
    private Token token = new Token();

    @Valid
    private Cookie cookie = new Cookie();

    @Valid
    private Csrf csrf = new Csrf();

    @Valid
    private Jwt jwt = new Jwt();

    @Valid
    private Frontend frontend = new Frontend();

    @Valid
    private Registration registration = new Registration();

    @Valid
    private AuthorityCache authorityCache = new AuthorityCache();

    @Valid
    private Request request = new Request();

    @Valid
    private EmailOutbox emailOutbox = new EmailOutbox();

    @Valid
    private Compliance compliance = new Compliance();

    @Valid
    private Audit audit = new Audit();

    @Valid
    private Mfa mfa = new Mfa();

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    public Cookie getCookie() {
        return cookie;
    }

    public void setCookie(Cookie cookie) {
        this.cookie = cookie;
    }

    public Csrf getCsrf() {
        return csrf;
    }

    public void setCsrf(Csrf csrf) {
        this.csrf = csrf;
    }

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public Frontend getFrontend() {
        return frontend;
    }

    public void setFrontend(Frontend frontend) {
        this.frontend = frontend;
    }

    public Registration getRegistration() {
        return registration;
    }

    public void setRegistration(Registration registration) {
        this.registration = registration;
    }

    public AuthorityCache getAuthorityCache() {
        return authorityCache;
    }

    public void setAuthorityCache(AuthorityCache authorityCache) {
        this.authorityCache = authorityCache;
    }

    public Request getRequest() {
        return request;
    }

    public void setRequest(Request request) {
        this.request = request;
    }

    public EmailOutbox getEmailOutbox() {
        return emailOutbox;
    }

    public void setEmailOutbox(EmailOutbox emailOutbox) {
        this.emailOutbox = emailOutbox;
    }

    public Compliance getCompliance() {
        return compliance;
    }

    public void setCompliance(Compliance compliance) {
        this.compliance = compliance;
    }

    public Audit getAudit() {
        return audit;
    }

    public void setAudit(Audit audit) {
        this.audit = audit;
    }

    public Mfa getMfa() {
        return mfa;
    }

    public void setMfa(Mfa mfa) {
        this.mfa = mfa;
    }

    public static class Token {

        @Min(60)
        private long accessTokenTtlSeconds = 900;

        @Min(1)
        private long refreshTokenTtlDays = 7;

        @Min(1)
        private long recoveryTokenTtlMinutes = 15;

        public long getAccessTokenTtlSeconds() {
            return accessTokenTtlSeconds;
        }

        public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
            this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        }

        public long getRefreshTokenTtlDays() {
            return refreshTokenTtlDays;
        }

        public void setRefreshTokenTtlDays(long refreshTokenTtlDays) {
            this.refreshTokenTtlDays = refreshTokenTtlDays;
        }

        public long getRecoveryTokenTtlMinutes() {
            return recoveryTokenTtlMinutes;
        }

        public void setRecoveryTokenTtlMinutes(long recoveryTokenTtlMinutes) {
            this.recoveryTokenTtlMinutes = recoveryTokenTtlMinutes;
        }
    }

    public static class Cookie {

        @NotBlank
        private String refreshName = "Refresh-Token";

        @NotBlank
        @Pattern(regexp = "/.*")
        private String path = "/api/v1/auth";

        private boolean httpOnly = true;

        private boolean secure = true;

        @NotBlank
        @Pattern(regexp = "Strict|Lax|None")
        private String sameSite = "Strict";

        public String getRefreshName() {
            return refreshName;
        }

        public void setRefreshName(String refreshName) {
            this.refreshName = refreshName;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public boolean isHttpOnly() {
            return httpOnly;
        }

        public void setHttpOnly(boolean httpOnly) {
            this.httpOnly = httpOnly;
        }

        public boolean isSecure() {
            return secure;
        }

        public void setSecure(boolean secure) {
            this.secure = secure;
        }

        public String getSameSite() {
            return sameSite;
        }

        public void setSameSite(String sameSite) {
            this.sameSite = sameSite;
        }

        @AssertTrue(message = "secure must be true when SameSite=None")
        public boolean isSecureWhenSameSiteNone() {
            return !"None".equals(sameSite) || secure;
        }
    }

    public static class Csrf {

        private boolean enabled = true;

        @NotBlank
        private String cookieName = "XSRF-TOKEN";

        @NotBlank
        private String headerName = "X-XSRF-TOKEN";

        @NotBlank
        @Pattern(regexp = "/.*")
        private String path = "/api/v1/auth";

        @Min(16)
        @Max(128)
        private int tokenBytes = 32;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getCookieName() {
            return cookieName;
        }

        public void setCookieName(String cookieName) {
            this.cookieName = cookieName;
        }

        public String getHeaderName() {
            return headerName;
        }

        public void setHeaderName(String headerName) {
            this.headerName = headerName;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public int getTokenBytes() {
            return tokenBytes;
        }

        public void setTokenBytes(int tokenBytes) {
            this.tokenBytes = tokenBytes;
        }
    }

    public static class Jwt {

        @NotBlank
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String issuer = "authkit";

        @NotBlank
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String audience = "authkit-api";

        @NotBlank
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String keyId = "authkit-key-1";

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }
    }

    public static class Frontend {

        @NotBlank
        @Pattern(regexp = "https?://.+")
        private String activationUrl = "https://authkit.io/activate";

        @NotBlank
        @Pattern(regexp = "https?://.+")
        private String passwordResetUrl = "https://frontend.url/reset-password";

        public String getActivationUrl() {
            return activationUrl;
        }

        public void setActivationUrl(String activationUrl) {
            this.activationUrl = activationUrl;
        }

        public String getPasswordResetUrl() {
            return passwordResetUrl;
        }

        public void setPasswordResetUrl(String passwordResetUrl) {
            this.passwordResetUrl = passwordResetUrl;
        }
    }

    public static class Registration {

        private boolean stealthConflicts = true;

        public boolean isStealthConflicts() {
            return stealthConflicts;
        }

        public void setStealthConflicts(boolean stealthConflicts) {
            this.stealthConflicts = stealthConflicts;
        }
    }

    public static class AuthorityCache {

        @Min(1)
        @Max(300)
        private long ttlSeconds = 30;

        @Min(1)
        private long maxSize = 10000;

        public long getTtlSeconds() {
            return ttlSeconds;
        }

        public void setTtlSeconds(long ttlSeconds) {
            this.ttlSeconds = ttlSeconds;
        }

        public long getMaxSize() {
            return maxSize;
        }

        public void setMaxSize(long maxSize) {
            this.maxSize = maxSize;
        }
    }

    public static class Request {

        @Min(1024)
        private long maxBodyBytes = 65536;

        public long getMaxBodyBytes() {
            return maxBodyBytes;
        }

        public void setMaxBodyBytes(long maxBodyBytes) {
            this.maxBodyBytes = maxBodyBytes;
        }
    }

    public static class EmailOutbox {

        private boolean enabled = true;

        @Min(1)
        @Max(500)
        private int batchSize = 50;

        @Min(1000)
        private long pollDelayMs = 5000;

        @Min(1)
        private long lockTtlSeconds = 300;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getBatchSize() {
            return batchSize;
        }

        public void setBatchSize(int batchSize) {
            this.batchSize = batchSize;
        }

        public long getPollDelayMs() {
            return pollDelayMs;
        }

        public void setPollDelayMs(long pollDelayMs) {
            this.pollDelayMs = pollDelayMs;
        }

        public long getLockTtlSeconds() {
            return lockTtlSeconds;
        }

        public void setLockTtlSeconds(long lockTtlSeconds) {
            this.lockTtlSeconds = lockTtlSeconds;
        }
    }

    public static class Compliance {

        @NotBlank
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String termsVersion = "terms-v1";

        @NotBlank
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String privacyPolicyVersion = "privacy-v1";

        @NotBlank
        @Pattern(regexp = "consent|contract|legal_obligation|vital_interests|public_task|legitimate_interests")
        private String lawfulBasis = "consent";

        @Min(1)
        private long securityEventRetentionDays = 365;

        @Min(0)
        private long deletedAccountRetentionDays = 30;

        @Min(1)
        @Max(500)
        private int dataExportSecurityEventLimit = 100;

        @Min(1)
        @Max(5000)
        private int retentionBatchSize = 500;

        private boolean retentionJobEnabled = true;

        @NotBlank
        private String retentionJobCron = "0 30 3 * * *";

        public String getTermsVersion() {
            return termsVersion;
        }

        public void setTermsVersion(String termsVersion) {
            this.termsVersion = termsVersion;
        }

        public String getPrivacyPolicyVersion() {
            return privacyPolicyVersion;
        }

        public void setPrivacyPolicyVersion(String privacyPolicyVersion) {
            this.privacyPolicyVersion = privacyPolicyVersion;
        }

        public String getLawfulBasis() {
            return lawfulBasis;
        }

        public void setLawfulBasis(String lawfulBasis) {
            this.lawfulBasis = lawfulBasis;
        }

        public long getSecurityEventRetentionDays() {
            return securityEventRetentionDays;
        }

        public void setSecurityEventRetentionDays(long securityEventRetentionDays) {
            this.securityEventRetentionDays = securityEventRetentionDays;
        }

        public long getDeletedAccountRetentionDays() {
            return deletedAccountRetentionDays;
        }

        public void setDeletedAccountRetentionDays(long deletedAccountRetentionDays) {
            this.deletedAccountRetentionDays = deletedAccountRetentionDays;
        }

        public int getDataExportSecurityEventLimit() {
            return dataExportSecurityEventLimit;
        }

        public void setDataExportSecurityEventLimit(int dataExportSecurityEventLimit) {
            this.dataExportSecurityEventLimit = dataExportSecurityEventLimit;
        }

        public int getRetentionBatchSize() {
            return retentionBatchSize;
        }

        public void setRetentionBatchSize(int retentionBatchSize) {
            this.retentionBatchSize = retentionBatchSize;
        }

        public boolean isRetentionJobEnabled() {
            return retentionJobEnabled;
        }

        public void setRetentionJobEnabled(boolean retentionJobEnabled) {
            this.retentionJobEnabled = retentionJobEnabled;
        }

        public String getRetentionJobCron() {
            return retentionJobCron;
        }

        public void setRetentionJobCron(String retentionJobCron) {
            this.retentionJobCron = retentionJobCron;
        }
    }

    public static class Audit {

        @NotBlank
        @jakarta.validation.constraints.Size(min = 32)
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String hashPepper = "test-only-authkit-audit-hash-pepper-32-bytes";

        private boolean asyncEnabled = true;

        @Min(1)
        @Max(16)
        private int writerCorePoolSize = 2;

        @Min(1)
        @Max(32)
        private int writerMaxPoolSize = 4;

        @Min(100)
        @Max(100000)
        private int writerQueueCapacity = 5000;

        @Min(1)
        @Max(60)
        private int writerShutdownTimeoutSeconds = 10;

        private boolean persistSynchronouslyOnOverload = true;

        public String getHashPepper() {
            return hashPepper;
        }

        public void setHashPepper(String hashPepper) {
            this.hashPepper = hashPepper;
        }

        public boolean isAsyncEnabled() {
            return asyncEnabled;
        }

        public void setAsyncEnabled(boolean asyncEnabled) {
            this.asyncEnabled = asyncEnabled;
        }

        public int getWriterCorePoolSize() {
            return writerCorePoolSize;
        }

        public void setWriterCorePoolSize(int writerCorePoolSize) {
            this.writerCorePoolSize = writerCorePoolSize;
        }

        public int getWriterMaxPoolSize() {
            return writerMaxPoolSize;
        }

        public void setWriterMaxPoolSize(int writerMaxPoolSize) {
            this.writerMaxPoolSize = writerMaxPoolSize;
        }

        public int getWriterQueueCapacity() {
            return writerQueueCapacity;
        }

        public void setWriterQueueCapacity(int writerQueueCapacity) {
            this.writerQueueCapacity = writerQueueCapacity;
        }

        public int getWriterShutdownTimeoutSeconds() {
            return writerShutdownTimeoutSeconds;
        }

        public void setWriterShutdownTimeoutSeconds(int writerShutdownTimeoutSeconds) {
            this.writerShutdownTimeoutSeconds = writerShutdownTimeoutSeconds;
        }

        public boolean isPersistSynchronouslyOnOverload() {
            return persistSynchronouslyOnOverload;
        }

        public void setPersistSynchronouslyOnOverload(boolean persistSynchronouslyOnOverload) {
            this.persistSynchronouslyOnOverload = persistSynchronouslyOnOverload;
        }

        @AssertTrue(message = "writer-max-pool-size must be greater than or equal to writer-core-pool-size")
        public boolean isWriterPoolSizeValid() {
            return writerMaxPoolSize >= writerCorePoolSize;
        }
    }

    public static class Mfa {

        private boolean enabled = true;

        @Min(5)
        @Max(15)
        private int backupCodeCount = 10;

        @Min(1)
        @Max(30)
        private long loginChallengeTtlMinutes = 5;

        @NotBlank
        @jakarta.validation.constraints.Size(min = 32)
        @Pattern(regexp = "^(?!\\$\\{).+")
        private String secretEncryptionKey = "test-only-authkit-mfa-secret-key-32-bytes";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getBackupCodeCount() {
            return backupCodeCount;
        }

        public void setBackupCodeCount(int backupCodeCount) {
            this.backupCodeCount = backupCodeCount;
        }

        public long getLoginChallengeTtlMinutes() {
            return loginChallengeTtlMinutes;
        }

        public void setLoginChallengeTtlMinutes(long loginChallengeTtlMinutes) {
            this.loginChallengeTtlMinutes = loginChallengeTtlMinutes;
        }

        public String getSecretEncryptionKey() {
            return secretEncryptionKey;
        }

        public void setSecretEncryptionKey(String secretEncryptionKey) {
            this.secretEncryptionKey = secretEncryptionKey;
        }
    }
}
