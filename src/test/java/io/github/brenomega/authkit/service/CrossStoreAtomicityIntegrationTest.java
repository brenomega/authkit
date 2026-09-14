package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import io.github.brenomega.authkit.domain.user.dto.PasswordChangeRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.infrastructure.cache.RedisTokenStorage;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectProcessor;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectRepository;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectService;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectStatus;
import io.github.brenomega.authkit.exception.InvalidRefreshTokenException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.support.PostgresIntegrationTestSupport;
import io.lettuce.core.RedisClient;

@SpringBootTest(properties = {
        "authkit.test.mock-redis=false",
        "authkit.auth.security-effects.poll-delay-ms=3600000",
        "authkit.auth.security-effects.initial-delay-ms=3600000"
})
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = false)
@Import(CrossStoreAtomicityIntegrationTest.RealRedisTestConfiguration.class)
class CrossStoreAtomicityIntegrationTest extends PostgresIntegrationTestSupport {

    @SuppressWarnings("resource")
    private static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(
            "redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"))
            .withExposedPorts(6379);

    static {
        REDIS.start();
    }

    @Autowired PasswordRecoveryService passwordRecoveryService;
    @Autowired ProfileService profileService;
    @Autowired AdminService adminService;
    @Autowired UserRepository users;
    @Autowired PasskeyCredentialRepository passkeys;
    @Autowired EmailOutboxRepository outbox;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired TokenStorage tokens;
    @Autowired TransactionTemplate transactions;
    @Autowired StringRedisTemplate redis;
    @Autowired AuthService authService;
    @Autowired SecurityEffectRepository securityEffects;
    @Autowired SecurityEffectProcessor securityEffectProcessor;
    @Autowired SecurityEffectService securityEffectService;
    @Autowired FaultInjectableRedisTokenStorage faultInjectableTokens;
    @Autowired AuditDigestService auditDigestService;
    @Autowired org.springframework.jdbc.core.JdbcTemplate jdbc;
    @Autowired io.github.brenomega.authkit.infrastructure.security.AuthProperties properties;
    @Autowired io.github.brenomega.authkit.repository.MfaBackupCodeRepository backupCodes;

    @AfterEach
    void clearRedis() {
        faultInjectableTokens.setFailRevocation(false);
        faultInjectableTokens.setFailActivation(false);
        faultInjectableTokens.setFailAfterActivation(false);
        var connection = redis.getConnectionFactory().getConnection();
        try {
            connection.serverCommands().flushDb();
        } finally {
            connection.close();
        }
    }

    @Test
    void sqlRollbackBeforeCommitCannotActivateAnOrphanRecoveryToken() {
        String email = "cross-store-recovery-" + UUID.randomUUID() + "@example.test";
        activeUser(email, "CurrentPassword73!");

        transactions.executeWithoutResult(status -> {
            passwordRecoveryService.requestRecovery(email);
            assertTrue(redis.keys("recovery:*").isEmpty(),
                    "the external token must not exist before SQL commit");
            status.setRollbackOnly();
        });

        assertTrue(redis.keys("recovery:*").isEmpty());
        assertEquals(0, outbox.findAll().stream()
                .filter(message -> email.equals(message.getRecipient())).count());
    }

    @Test
    void recoveryActivationRetriesAfterCommitAndReleasesEmailOnlyAfterRedisRecovers() {
        String email = "activation-retry-" + UUID.randomUUID() + "@example.test";
        User user = activeUser(email, "CurrentPassword73!");
        faultInjectableTokens.setFailActivation(true);
        passwordRecoveryService.requestRecovery(email);
        var message = outbox.findTopByRecipientOrderByCreatedAtDesc(email).orElseThrow();
        var matcher = java.util.regex.Pattern.compile("#token=([A-Za-z0-9_-]+)").matcher(message.getBody());
        assertTrue(matcher.find());
        String token = matcher.group(1);
        var task = securityEffects.findAll().stream()
                .filter(value -> message.getId().equals(value.getEmailMessageId())).findFirst().orElseThrow();
        assertEquals(SecurityEffectStatus.FAILED, task.getStatus());
        assertEquals("WAITING_ACTIVATION", message.getStatus().name());
        assertFalse(tokens.validateRecoveryToken(email, token));
        assertEquals(user.getSecurityVersion(), task.getTargetVersion());
        faultInjectableTokens.setFailActivation(false);
        jdbc.update("update security_effect_outbox set next_attempt_at = current_timestamp where id = ?", task.getId());
        securityEffectProcessor.reconcile();
        assertTrue(tokens.validateRecoveryToken(email, token));
        assertEquals(SecurityEffectStatus.COMPLETED, securityEffects.findById(task.getId()).orElseThrow().getStatus());
        assertEquals("PENDING", outbox.findById(message.getId()).orElseThrow().getStatus().name());
        assertTrue(tokens.consumeRecoveryToken(email, token));
        // Simulate a lost completion acknowledgement and a stale claimant retry.
        jdbc.update("update security_effect_outbox set status = 'FAILED', next_attempt_at = current_timestamp where id = ?", task.getId());
        securityEffectProcessor.reconcile();
        assertFalse(tokens.validateRecoveryToken(email, token), "retry must not resurrect a consumed token");
    }

    @Test
    void lostRedisAcknowledgementRetriesWithoutExtendingExpiryOrReplacingConsumedToken() {
        String email = "activation-ambiguous-" + UUID.randomUUID() + "@example.test";
        activeUser(email, "CurrentPassword73!");
        faultInjectableTokens.setFailAfterActivation(true);
        passwordRecoveryService.requestRecovery(email);
        var message = outbox.findTopByRecipientOrderByCreatedAtDesc(email).orElseThrow();
        var task = securityEffects.findAll().stream()
                .filter(value -> message.getId().equals(value.getEmailMessageId())).findFirst().orElseThrow();
        assertEquals(SecurityEffectStatus.FAILED, task.getStatus());
        assertEquals("WAITING_ACTIVATION", message.getStatus().name());
        String key = "recovery:token:" + task.getRecoveryEmailDigest();
        Long ttl = redis.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS);
        faultInjectableTokens.setFailAfterActivation(false);
        jdbc.update("update security_effect_outbox set next_attempt_at = current_timestamp where id = ?", task.getId());
        securityEffectProcessor.reconcile();
        assertTrue(redis.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS) <= ttl);
        assertEquals("PENDING", outbox.findById(message.getId()).orElseThrow().getStatus().name());
    }

    @Test
    void securityMutationCancelsPendingRecoveryActivationInsteadOfRestoringStaleState() {
        String email = "activation-superseded-" + UUID.randomUUID() + "@example.test";
        User user = activeUser(email, "CurrentPassword73!");
        faultInjectableTokens.setFailActivation(true);
        passwordRecoveryService.requestRecovery(email);
        var message = outbox.findTopByRecipientOrderByCreatedAtDesc(email).orElseThrow();
        transactions.executeWithoutResult(status -> securityEffectService.invalidateSessions(
                users.findByIdForUpdate(user.getId()).orElseThrow(), null));
        faultInjectableTokens.setFailActivation(false);
        jdbc.update("update security_effect_outbox set next_attempt_at = current_timestamp where email_message_id = ?", message.getId());
        securityEffectProcessor.reconcile();
        assertEquals("CANCELLED", outbox.findById(message.getId()).orElseThrow().getStatus().name());
        assertFalse(redis.hasKey("recovery:token:" + auditDigestService.hmacHex(email)));
    }

    @Test
    void olderPendingRevocationMustFinishBeforeANewRecoveryEmailBecomesDispatchable() {
        String email = "activation-old-revocation-" + UUID.randomUUID() + "@example.test";
        activeUser(email, "CurrentPassword73!");
        faultInjectableTokens.setFailRevocation(true);
        transactions.executeWithoutResult(status -> securityEffectService.revokeRecoveryToken(email));
        passwordRecoveryService.requestRecovery(email);
        var message = outbox.findTopByRecipientOrderByCreatedAtDesc(email).orElseThrow();
        assertEquals("WAITING_ACTIVATION", message.getStatus().name(),
                "an older failed revocation must not later delete a newly delivered recovery token");
        faultInjectableTokens.setFailRevocation(false);
        jdbc.update("update security_effect_outbox set next_attempt_at = current_timestamp where recovery_email_digest = ?",
                auditDigestService.hmacHex(email));
        securityEffectProcessor.reconcile();
        assertEquals("PENDING", outbox.findById(message.getId()).orElseThrow().getStatus().name());
        String activated = redis.opsForValue().get("recovery:token:" + auditDigestService.hmacHex(email));
        assertNotNull(activated);
        securityEffectProcessor.reconcile();
        assertEquals(activated, redis.opsForValue().get("recovery:token:" + auditDigestService.hmacHex(email)));
    }

    @Test
    void completedEffectRetentionIsBoundedRepeatSafeAndPreservesUnresolvedTasks() {
        var completed = io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectTask
                .revokeRecoveryToken("a".repeat(64));
        completed.markCompleted(Instant.now().minusSeconds(86400));
        securityEffects.saveAndFlush(completed);
        var pending = securityEffects.saveAndFlush(
                io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectTask
                        .revokeRecoveryToken("b".repeat(64)));
        var failed = io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectTask
                .revokeRecoveryToken("c".repeat(64));
        failed.markFailed("controlled unavailable", Instant.now().minusSeconds(86400));
        securityEffects.saveAndFlush(failed);
        var processing = io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectTask
                .revokeRecoveryToken("d".repeat(64));
        processing.markProcessing(Instant.now().minusSeconds(86400));
        securityEffects.saveAndFlush(processing);
        var recent = io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectTask
                .revokeRecoveryToken("e".repeat(64));
        recent.markCompleted(Instant.now());
        securityEffects.saveAndFlush(recent);
        Instant cutoff = Instant.now().minusSeconds(3600);
        int first = transactions.execute(status -> securityEffects.purgeCompletedBatch(cutoff, 1));
        int repeated = transactions.execute(status -> securityEffects.purgeCompletedBatch(cutoff, 1));
        assertEquals(1, first);
        assertEquals(0, repeated);
        assertTrue(securityEffects.findById(pending.getId()).isPresent());
        assertTrue(securityEffects.findById(failed.getId()).isPresent());
        assertTrue(securityEffects.findById(processing.getId()).isPresent());
        assertTrue(securityEffects.findById(recent.getId()).isPresent());
    }

    @Test
    void coordinatedPepperInvalidationRejectsOldRecoveryBackupAndCursorState() {
        User user = activeUser("pepper-drill-" + UUID.randomUUID() + "@example.test", "CurrentPassword73!");
        String oldPepper = properties.getAudit().getHashPepper();
        String rawRecovery = "pepper-drill-recovery-secret";
        String rawBackup = "ABCD-EFGH-JKLM";
        String oldDigest = auditDigestService.hmacHex(user.getEmail());
        tokens.storeRecoveryToken(user.getEmail(), rawRecovery, 30);
        backupCodes.saveAndFlush(new io.github.brenomega.authkit.domain.mfa.entity.MfaBackupCode(
                user.getId(), user.getTenantId(), auditDigestService.hmacHex(
                        "mfa-backup-code|" + user.getId() + '|' + rawBackup), Instant.now()));
        var cursorCodec = new io.github.brenomega.authkit.infrastructure.security.AdminCursorCodec(auditDigestService);
        String cursor = cursorCodec.issue("users", 1, 20, "operator");
        var redisClient = (RedisClient) ((LettuceConnectionFactory) redis.getConnectionFactory()).getNativeClient();
        var throttle = new io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService(
                java.util.Optional.of(redisClient), auditDigestService,
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry(),
                new io.github.brenomega.authkit.infrastructure.security.AuthProperties());
        var policy = io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy.LOGIN_EMAIL;
        String oldAbuseKey = "login_email:" + auditDigestService.hmacHex("login_email|email:" + user.getEmail());
        for (int attempt = 0; attempt < policy.degradedLocalCapacity(); attempt++) {
            throttle.checkEmail(policy, user.getEmail());
        }
        assertTrue(redis.hasKey(oldAbuseKey), "the actual distributed Bucket4j state must exist");
        assertThrows(io.github.brenomega.authkit.exception.RateLimitExceededException.class,
                () -> throttle.checkEmail(policy, user.getEmail()));
        assertTrue(tokens.validateRecoveryToken(user.getEmail(), rawRecovery));
        try {
            properties.getAudit().setHashPepper("rotated-test-root-" + UUID.randomUUID());
            assertFalse(tokens.validateRecoveryToken(user.getEmail(), rawRecovery));
            assertTrue(backupCodes.findByUserIdAndCodeHashAndUsedAtIsNull(user.getId(),
                    auditDigestService.hmacHex("mfa-backup-code|" + user.getId() + '|' + rawBackup)).isEmpty());
            assertThrows(io.github.brenomega.authkit.exception.InvalidAdminCursorException.class,
                    () -> cursorCodec.decode(cursor, "users", 20, "operator"));
            String newAbuseKey = "login_email:" + auditDigestService.hmacHex("login_email|email:" + user.getEmail());
            assertFalse(redis.hasKey(newAbuseKey));
            // Coordinated maintenance explicitly removes old dependent state before reopening traffic.
            redis.delete(List.of("recovery:token:" + oldDigest, "recovery:claim:" + oldDigest, oldAbuseKey));
            transactions.executeWithoutResult(status -> backupCodes.deleteByUserIdAndUsedAtIsNull(user.getId()));
            tokens.storeRecoveryToken(user.getEmail(), "new-recovery-secret", 30);
            assertTrue(tokens.validateRecoveryToken(user.getEmail(), "new-recovery-secret"));
            assertFalse(tokens.validateRecoveryToken(user.getEmail(), rawRecovery));
            assertEquals(0, backupCodes.countByUserIdAndUsedAtIsNull(user.getId()));
            assertEquals(1, cursorCodec.decode(cursorCodec.issue("users", 1, 20, "operator"), "users", 20, "operator").page());
            assertFalse(redis.hasKey(oldAbuseKey));
            throttle.checkEmail(policy, user.getEmail());
            assertTrue(redis.hasKey(newAbuseKey));
        } finally {
            properties.getAudit().setHashPepper(oldPepper);
        }
    }

    @Test
    void sqlRollbackPreservesSessionsAndCommitRevokesOnlyAfterDurability() {
        String email = "cross-store-password-" + UUID.randomUUID() + "@example.test";
        User user = activeUser(email, "CurrentPassword73!");
        String currentJti = UUID.randomUUID().toString();
        String otherJti = UUID.randomUUID().toString();
        var current = RefreshTokenCodec.issue(user.getId().toString(), currentJti);
        var other = RefreshTokenCodec.issue(user.getId().toString(), otherJti);
        tokens.storeRefreshToken(user.getId().toString(), currentJti, current.rawToken(), 7);
        tokens.storeRefreshToken(user.getId().toString(), otherJti, other.rawToken(), 7);

        transactions.executeWithoutResult(status -> {
            profileService.changePassword(user.getId().toString(),
                    new PasswordChangeRequest("CurrentPassword73!", "ReplacementPassword84!"), currentJti);
            assertTrue(tokens.validateToken(user.getId().toString(), otherJti, other.rawToken()),
                    "revocation must not precede the SQL commit");
            status.setRollbackOnly();
        });

        assertTrue(passwordEncoder.matches("CurrentPassword73!", users.findById(user.getId()).orElseThrow().getPassword()));
        assertTrue(tokens.validateToken(user.getId().toString(), currentJti, current.rawToken()));
        assertTrue(tokens.validateToken(user.getId().toString(), otherJti, other.rawToken()));

        profileService.changePassword(user.getId().toString(),
                new PasswordChangeRequest("CurrentPassword73!", "ReplacementPassword84!"), currentJti);

        assertTrue(tokens.validateToken(user.getId().toString(), currentJti, current.rawToken()));
        assertFalse(tokens.validateToken(user.getId().toString(), otherJti, other.rawToken()));
        assertTrue(passwordEncoder.matches("ReplacementPassword84!",
                users.findById(user.getId()).orElseThrow().getPassword()));
    }

    @Test
    void privilegedSessionRevocationPublishesToRedisOnlyAfterSqlCommit() {
        User admin = activeUser("cross-store-admin-" + UUID.randomUUID() + "@example.test", "CurrentPassword73!");
        admin.setRole(Role.PLATFORM_ADMIN);
        users.saveAndFlush(admin);
        passkeys.saveAndFlush(new PasskeyCredential(
                admin.getId(), admin.getTenantId(), "credential-" + admin.getId(),
                "public-key-cose", 0, "internal", "Admin Passkey", true, Instant.now()));
        User target = activeUser("cross-store-target-" + UUID.randomUUID() + "@example.test", "CurrentPassword73!");
        String jti = UUID.randomUUID().toString();
        var refresh = RefreshTokenCodec.issue(target.getId().toString(), jti);
        tokens.storeRefreshToken(target.getId().toString(), jti, refresh.rawToken(), 7);

        transactions.executeWithoutResult(status -> {
            adminService.revokeAllUserSessions(adminJwt(admin), target.getId(), "CurrentPassword73!", null);
            assertTrue(tokens.validateToken(target.getId().toString(), jti, refresh.rawToken()),
                    "Redis revocation must not precede SQL/audit commit");
            status.setRollbackOnly();
        });

        assertTrue(tokens.validateToken(target.getId().toString(), jti, refresh.rawToken()));
        adminService.revokeAllUserSessions(adminJwt(admin), target.getId(), "CurrentPassword73!", null);
        assertFalse(tokens.validateToken(target.getId().toString(), jti, refresh.rawToken()));
    }

    @Test
    void committedSecurityBoundaryRejectsStaleCredentialsWhileRedisEffectRetries() throws Exception {
        User user = activeUser("durable-security-" + UUID.randomUUID() + "@example.test", "CurrentPassword73!");
        String currentJti = UUID.randomUUID().toString();
        String staleJti = UUID.randomUUID().toString();
        var current = RefreshTokenCodec.issue(user.getId().toString(), currentJti);
        var stale = RefreshTokenCodec.issue(user.getId().toString(), staleJti);
        tokens.storeRefreshToken(user.getId().toString(), currentJti, current.rawToken(), 7);
        tokens.storeRefreshToken(user.getId().toString(), staleJti, stale.rawToken(), 7);

        faultInjectableTokens.setFailRevocation(true);

        profileService.changePassword(user.getId().toString(),
                new PasswordChangeRequest("CurrentPassword73!", "ReplacementPassword84!"), currentJti);

        User committed = users.findById(user.getId()).orElseThrow();
        assertEquals(1, committed.getSecurityVersion());
        assertEquals(currentJti, committed.getPreservedSessionJti());
        assertTrue(tokens.validateToken(user.getId().toString(), staleJti, stale.rawToken()),
                "the injected failure must leave the external session physically present");
        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh(stale.rawToken()),
                "the committed PostgreSQL boundary must reject stale refresh state immediately");

        var task = securityEffects.findAll().stream()
                .filter(candidate -> user.getId().equals(candidate.getUserId()))
                .findFirst().orElseThrow();
        assertEquals(SecurityEffectStatus.FAILED, task.getStatus());

        faultInjectableTokens.setFailRevocation(false);
        Thread.sleep(2_100);
        securityEffectProcessor.reconcile();

        assertEquals(SecurityEffectStatus.COMPLETED,
                securityEffects.findById(task.getId()).orElseThrow().getStatus());
        assertFalse(tokens.validateToken(user.getId().toString(), staleJti, stale.rawToken()));
        assertTrue(tokens.validateToken(user.getId().toString(), currentJti, current.rawToken()));
    }

    @Test
    void committedRecoveryRevocationRetriesUntilExternalStateIsGone() throws Exception {
        String email = "durable-recovery-" + UUID.randomUUID() + "@example.test";
        String rawToken = "recovery-" + UUID.randomUUID();
        tokens.storeRecoveryToken(email, rawToken, 30);
        assertTrue(tokens.validateRecoveryToken(email, rawToken));

        faultInjectableTokens.setFailRevocation(true);
        transactions.executeWithoutResult(status -> securityEffectService.revokeRecoveryToken(email));

        assertTrue(tokens.validateRecoveryToken(email, rawToken),
                "the injected failure must leave the external recovery state physically present");
        String emailDigest = auditDigestService.hmacHex(email);
        var task = securityEffects.findAll().stream()
                .filter(candidate -> emailDigest.equals(candidate.getRecoveryEmailDigest()))
                .findFirst().orElseThrow();
        assertEquals(SecurityEffectStatus.FAILED, task.getStatus());

        faultInjectableTokens.setFailRevocation(false);
        Thread.sleep(2_100);
        securityEffectProcessor.reconcile();

        assertEquals(SecurityEffectStatus.COMPLETED,
                securityEffects.findById(task.getId()).orElseThrow().getStatus());
        assertFalse(tokens.validateRecoveryToken(email, rawToken));
    }

    private User activeUser(String email, String password) {
        User user = new User(email, passwordEncoder.encode(password), "Cross-store User", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-v1", "privacy-v1", "consent", Instant.now());
        return users.saveAndFlush(user);
    }

    private Jwt adminJwt(User admin) {
        return new Jwt(
                "token", Instant.now(), Instant.now().plusSeconds(900),
                Map.of("alg", "none"),
                Map.of("sub", admin.getId().toString(), "tenant_id", admin.getTenantId().toString(),
                        "amr", List.of("webauthn")));
    }

    @TestConfiguration
    static class RealRedisTestConfiguration {

        @Bean(destroyMethod = "destroy")
        @Primary
        LettuceConnectionFactory redisConnectionFactory() {
            var configuration = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
            var factory = new LettuceConnectionFactory(configuration);
            factory.afterPropertiesSet();
            return factory;
        }

        @Bean
        @Primary
        StringRedisTemplate stringRedisTemplate(LettuceConnectionFactory factory) {
            var template = new StringRedisTemplate(factory);
            template.afterPropertiesSet();
            return template;
        }

        @Bean
        @Primary
        RedisClient redisClient(LettuceConnectionFactory factory) {
            return (RedisClient) factory.getNativeClient();
        }

        @Bean
        @Primary
        FaultInjectableRedisTokenStorage faultInjectableTokenStorage(
                StringRedisTemplate template, AuditDigestService auditDigestService) {
            return new FaultInjectableRedisTokenStorage(template, auditDigestService);
        }
    }

    public static class FaultInjectableRedisTokenStorage extends RedisTokenStorage {
        private volatile boolean failRevocation;
        volatile boolean failActivation;
        volatile boolean failAfterActivation;
        public void setFailActivation(boolean value) { failActivation = value; }
        public void setFailAfterActivation(boolean value) { failAfterActivation = value; }

        @Override
        public void activateRecoveryToken(String activationId, String emailDigest, String tokenDigest, Instant expiresAt) {
            if (failActivation) throw new IllegalStateException("injected Redis activation failure after SQL commit");
            super.activateRecoveryToken(activationId, emailDigest, tokenDigest, expiresAt);
            if (failAfterActivation) throw new IllegalStateException("injected lost Redis activation acknowledgement");
        }

        public FaultInjectableRedisTokenStorage(
                StringRedisTemplate redisTemplate, AuditDigestService auditDigestService) {
            super(redisTemplate, auditDigestService);
        }

        public void setFailRevocation(boolean failRevocation) {
            this.failRevocation = failRevocation;
        }

        @Override
        public void revokeSessionsBeforeVersion(String userId, long minimumVersion, String preservedJti) {
            if (failRevocation) {
                throw new IllegalStateException("injected Redis revocation failure");
            }
            super.revokeSessionsBeforeVersion(userId, minimumVersion, preservedJti);
        }

        @Override
        public void revokeRecoveryTokenByDigest(String emailDigest) {
            if (failRevocation) {
                throw new IllegalStateException("injected Redis revocation failure");
            }
            super.revokeRecoveryTokenByDigest(emailDigest);
        }
    }
}
