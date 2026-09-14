package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.AdminAccountStateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.support.PostgresIntegrationTestSupport;

@SpringBootTest(properties = "authkit.auth.compliance.retention-job-enabled=true")
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = false)
class LastPlatformAdminConcurrencyIntegrationTest extends PostgresIntegrationTestSupport {

    private static final String PASSWORD = "AdminConcurrency73!";

    @Autowired AdminService adminService;
    @Autowired AccountLifecycleService accountLifecycleService;
    @Autowired UserRepository users;
    @Autowired PasskeyCredentialRepository passkeys;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired JdbcTemplate jdbc;
    @Autowired AccountAnonymizationService accountAnonymizationService;
    @Autowired SecurityEventRepository securityEvents;
    @Autowired AuthProperties authProperties;

    @DynamicPropertySource
    static void retentionWorkerProperties(DynamicPropertyRegistry registry) {
        registry.add("AUTH_RETENTION_DB_URL", POSTGRES::getJdbcUrl);
        registry.add("AUTH_RETENTION_DB_USERNAME", POSTGRES::getUsername);
        registry.add("AUTH_RETENTION_DB_PASSWORD", POSTGRES::getPassword);
    }

    @ParameterizedTest(name = "{0} versus {1}")
    @CsvSource({
            "DEMOTE,DEMOTE",
            "SUSPEND,SUSPEND",
            "DELETE,DELETE",
            "DEMOTE,SUSPEND",
            "DEMOTE,DELETE",
            "SUSPEND,DELETE"
    })
    void concurrentTransitionsNeverRemoveEveryActiveAdministrator(Action first, Action second) throws Exception {
        jdbc.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
        User adminA = administrator("admin-a-" + UUID.randomUUID() + "@example.test");
        User adminB = administrator("admin-b-" + UUID.randomUUID() + "@example.test");
        CyclicBarrier barrier = new CyclicBarrier(3);
        AtomicInteger successes = new AtomicInteger();

        try (var executor = Executors.newFixedThreadPool(2)) {
            var contenderA = executor.submit(() -> invokeAfterBarrier(barrier, first, adminA, successes));
            var contenderB = executor.submit(() -> invokeAfterBarrier(barrier, second, adminB, successes));
            barrier.await(10, TimeUnit.SECONDS);
            contenderA.get(30, TimeUnit.SECONDS);
            contenderB.get(30, TimeUnit.SECONDS);
        }

        assertEquals(1, successes.get(), "exactly one transition may remove an active admin");
        assertTrue(users.countByRoleAndAccountState(Role.PLATFORM_ADMIN, AccountState.ACTIVE) >= 1);
    }

    @Test
    void aggregateLockQueryIsExercisedOnPostgresql17() {
        assertTrue(POSTGRES.getDockerImageName().startsWith("postgres:17"));
    }

    @Test
    void expiredDeletionCannotRaceBackToActiveWhileAnonymizationRuns() throws Exception {
        jdbc.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
        User admin = administrator("deletion-race-admin-" + UUID.randomUUID() + "@example.test");
        User target = activeUser("deletion-race-target-" + UUID.randomUUID() + "@example.test");
        target.requestDeletion(Instant.now().minusSeconds(
                authProperties.getCompliance().getDeletionGracePeriodDays() * 86_400L));
        target = users.saveAndFlush(target);
        UUID targetId = target.getId();
        CyclicBarrier barrier = new CyclicBarrier(3);
        AtomicInteger cancellationSuccesses = new AtomicInteger();

        try (var executor = Executors.newFixedThreadPool(2)) {
            var cancellation = executor.submit(() -> {
                SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(
                        jwt(admin), List.of(new SimpleGrantedAuthority("ROLE_PLATFORM_ADMIN"))));
                try {
                    barrier.await(10, TimeUnit.SECONDS);
                    adminService.cancelDeletion(jwt(admin), targetId,
                            new AdminAccountStateRequest("owner recovered", PASSWORD, null));
                    cancellationSuccesses.incrementAndGet();
                } catch (RuntimeException | java.util.concurrent.BrokenBarrierException
                        | java.util.concurrent.TimeoutException | InterruptedException expectedDenial) {
                    if (expectedDenial instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            var anonymization = executor.submit(() -> {
                try {
                    barrier.await(10, TimeUnit.SECONDS);
                    accountAnonymizationService.anonymizeExpiredDeletionRequests();
                } catch (java.util.concurrent.BrokenBarrierException
                        | java.util.concurrent.TimeoutException | InterruptedException failure) {
                    throw new IllegalStateException(failure);
                }
            });
            barrier.await(10, TimeUnit.SECONDS);
            cancellation.get(30, TimeUnit.SECONDS);
            anonymization.get(30, TimeUnit.SECONDS);
        }

        assertEquals(0, cancellationSuccesses.get(), "at/after cutoff cancellation must lose");
        User terminal = users.findById(targetId).orElseThrow();
        assertEquals(AccountState.ANONYMIZED, terminal.getAccountState());
        assertTrue(terminal.getEmail().startsWith("deleted+"));
        assertEquals(1, securityEvents.findTop100ByTargetUserIdOrderByOccurredAtDesc(targetId).stream()
                .filter(event -> event.getEventType() == SecurityEventType.ACCOUNT_ANONYMIZED).count());
        assertEquals(0, securityEvents.findTop100ByTargetUserIdOrderByOccurredAtDesc(targetId).stream()
                .filter(event -> event.getEventType() == SecurityEventType.ACCOUNT_DELETION_CANCELLED).count());
    }

    private void invokeAfterBarrier(CyclicBarrier barrier, Action action, User admin, AtomicInteger successes) {
        Jwt jwt = jwt(admin);
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(
                jwt, List.of(new SimpleGrantedAuthority("ROLE_PLATFORM_ADMIN"))));
        try {
            barrier.await(10, TimeUnit.SECONDS);
            switch (action) {
                case DEMOTE -> adminService.updateRole(jwt, admin.getId(),
                        new AdminUpdateRoleRequest(Role.USER, PASSWORD, null));
                case SUSPEND -> adminService.suspendUser(jwt, admin.getId(),
                        new AdminAccountStateRequest("concurrency-proof", PASSWORD, null));
                case DELETE -> accountLifecycleService.requestDeletion(admin.getId().toString(),
                        new StepUpRequest(PASSWORD, null));
            }
            successes.incrementAndGet();
        } catch (RuntimeException | java.util.concurrent.BrokenBarrierException
                | java.util.concurrent.TimeoutException | InterruptedException expectedLoser) {
            if (expectedLoser instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private User administrator(String email) {
        User user = new User(email, passwordEncoder.encode(PASSWORD), "Admin", true, true, null);
        user.setEmailConfirmed(true);
        user.setRole(Role.PLATFORM_ADMIN);
        user.recordConsent("terms-v1", "privacy-v1", "consent", Instant.now());
        user = users.saveAndFlush(user);
        passkeys.saveAndFlush(new PasskeyCredential(user.getId(), user.getTenantId(),
                "credential-" + user.getId(), "public-key", 0, "internal", "Concurrency key", true,
                Instant.now()));
        return user;
    }

    private User activeUser(String email) {
        User user = new User(email, passwordEncoder.encode(PASSWORD), "User", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-v1", "privacy-v1", "consent", Instant.now());
        return users.saveAndFlush(user);
    }

    private Jwt jwt(User user) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("admin-" + user.getId())
                .header("alg", "RS256")
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("tenant_id", user.getTenantId().toString())
                .claim("amr", List.of("pwd", "webauthn"))
                .build();
    }

    private enum Action { DEMOTE, SUSPEND, DELETE }
}
