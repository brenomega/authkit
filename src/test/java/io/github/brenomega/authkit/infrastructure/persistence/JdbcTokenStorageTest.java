package io.github.brenomega.authkit.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.exception.InvalidSessionCursorException;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

class JdbcTokenStorageTest {

    private JdbcTemplate jdbcTemplate;
    private JdbcTokenStorage storage;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:jdbc-token-" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa",
                "");
        jdbcTemplate = new JdbcTemplate(dataSource);
        createSchema(jdbcTemplate);
        AuthProperties properties = new AuthProperties();
        properties.getTokenStorage().setBackend("jdbc");
        properties.getTokenStorage().setSingleInstanceMode(true);
        properties.getTokenStorage().getJdbc().setSessionCursorTtlSeconds(300);
        storage = new JdbcTokenStorage(
                jdbcTemplate,
                new DataSourceTransactionManager(dataSource),
                properties);
    }

    @Test
    void storeValidateSessionActiveAndRevoke() {
        String userId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        String rawToken = RefreshTokenCodec.issue(userId, jti).rawToken();

        storage.storeRefreshToken(userId, jti, rawToken, 7);

        assertTrue(storage.validateToken(userId, jti, rawToken));
        assertTrue(storage.isSessionActive(userId, jti));
        assertFalse(storage.validateToken(userId, jti, "forged"));

        storage.revokeSession(userId, jti);

        assertFalse(storage.validateToken(userId, jti, rawToken));
        assertFalse(storage.isSessionActive(userId, jti));
    }

    @Test
    void rotateRefreshTokenDetectsReplayAndRevokesFamily() {
        String userId = UUID.randomUUID().toString();
        String currentJti = UUID.randomUUID().toString();
        RefreshTokenCodec.IssuedRefreshToken current = RefreshTokenCodec.issue(userId, currentJti);
        String nextJti = UUID.randomUUID().toString();
        RefreshTokenCodec.IssuedRefreshToken next =
                RefreshTokenCodec.issueRotated(userId, nextJti, current.familyId());

        storage.storeRefreshToken(userId, currentJti, current.rawToken(), 7);

        assertTrue(storage.rotateRefreshToken(userId, currentJti, current.rawToken(), nextJti, next.rawToken(), 7));
        assertFalse(storage.validateToken(userId, currentJti, current.rawToken()));
        assertTrue(storage.validateToken(userId, nextJti, next.rawToken()));

        RefreshTokenCodec.IssuedRefreshToken replayReplacement =
                RefreshTokenCodec.issueRotated(userId, UUID.randomUUID().toString(), current.familyId());
        assertThrows(TokenFamilyCompromisedException.class, () -> storage.rotateRefreshToken(
                userId,
                currentJti,
                current.rawToken(),
                replayReplacement.jti(),
                replayReplacement.rawToken(),
                7));
        assertFalse(storage.validateToken(userId, nextJti, next.rawToken()));
    }

    @Test
    void concurrentRefreshReplayAllowsOneRotationAndRevokesFamily() throws Exception {
        String userId = UUID.randomUUID().toString();
        String currentJti = UUID.randomUUID().toString();
        RefreshTokenCodec.IssuedRefreshToken current = RefreshTokenCodec.issue(userId, currentJti);
        RefreshTokenCodec.IssuedRefreshToken nextA =
                RefreshTokenCodec.issueRotated(userId, UUID.randomUUID().toString(), current.familyId());
        RefreshTokenCodec.IssuedRefreshToken nextB =
                RefreshTokenCodec.issueRotated(userId, UUID.randomUUID().toString(), current.familyId());
        storage.storeRefreshToken(userId, currentJti, current.rawToken(), 7);

        CountDownLatch start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            Future<Object> first = executor.submit(() -> rotateAfter(start, userId, current, nextA));
            Future<Object> second = executor.submit(() -> rotateAfter(start, userId, current, nextB));
            start.countDown();

            List<Object> results = List.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS));

            assertEquals(1, results.stream().filter(Boolean.TRUE::equals).count());
            assertEquals(1, results.stream().filter(TokenFamilyCompromisedException.class::isInstance).count());
            assertFalse(storage.validateToken(userId, nextA.jti(), nextA.rawToken()));
            assertFalse(storage.validateToken(userId, nextB.jti(), nextB.rawToken()));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void recoveryAndMfaChallengeConsumeOnlyOnce() {
        String email = "Reset@Example.com";
        String recovery = "recovery-" + UUID.randomUUID();
        storage.storeRecoveryToken(email, recovery, 15);

        assertTrue(storage.validateRecoveryToken(email.toLowerCase(), recovery));
        assertTrue(storage.consumeRecoveryToken(email.toLowerCase(), recovery));
        assertFalse(storage.consumeRecoveryToken(email.toLowerCase(), recovery));

        String userId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        String challenge = "mfa-" + UUID.randomUUID();
        storage.storeMfaChallenge(userId, jti, challenge, 5);

        assertFalse(storage.consumeMfaChallenge(userId, jti, "forged"));
        assertTrue(storage.consumeMfaChallenge(userId, jti, challenge));
        assertFalse(storage.consumeMfaChallenge(userId, jti, challenge));
    }

    @Test
    void listSessionsUsesBoundedCursorPagesWithOwnershipAndExpiry() {
        String userId = UUID.randomUUID().toString();
        List<String> expected = new ArrayList<>();
        for (int i = 0; i < 205; i++) {
            String jti = UUID.randomUUID().toString();
            expected.add(jti);
            storage.storeRefreshToken(userId, jti, RefreshTokenCodec.issue(userId, jti).rawToken(), 7);
        }

        List<String> seen = new ArrayList<>();
        String cursor = null;
        do {
            var page = storage.listSessions(userId, 37, cursor);
            seen.addAll(page.items());
            cursor = page.nextCursor();
        } while (cursor != null);

        assertEquals(205, seen.size());
        assertEquals(205, new HashSet<>(seen).size());
        assertTrue(seen.containsAll(expected));

        var ownedPage = storage.listSessions(userId, 1, null);
        assertThrows(InvalidSessionCursorException.class, () ->
                storage.listSessions(UUID.randomUUID().toString(), 1, ownedPage.nextCursor()));

        var expiringPage = storage.listSessions(userId, 1, null);
        jdbcTemplate.update("update auth_session_cursors set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));
        assertThrows(InvalidSessionCursorException.class, () ->
                storage.listSessions(userId, 1, expiringPage.nextCursor()));

        assertThrows(InvalidSessionCursorException.class, () ->
                storage.listSessions(userId, 1, "not-a-valid-cursor"));
    }

    @Test
    void cleanupRemovesExpiredTokenState() {
        String userId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        storage.storeRefreshToken(userId, jti, RefreshTokenCodec.issue(userId, jti).rawToken(), 7);
        storage.storeRecoveryToken("cleanup@example.com", "recovery", 15);
        storage.storeMfaChallenge(userId, UUID.randomUUID().toString(), "mfa", 5);
        storage.listSessions(userId, 1, null);
        jdbcTemplate.update("insert into oauth_revoked_tokens (jti, expires_at, created_at) values (?, ?, ?)",
                "oauth-jti",
                Timestamp.from(Instant.now().minusSeconds(1)),
                Timestamp.from(Instant.now().minusSeconds(60)));
        jdbcTemplate.update("update auth_refresh_sessions set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));
        jdbcTemplate.update("update auth_refresh_token_families set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));
        jdbcTemplate.update("update auth_recovery_tokens set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));
        jdbcTemplate.update("update auth_mfa_login_challenges set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));
        jdbcTemplate.update("update auth_session_cursors set expires_at = ?", Timestamp.from(Instant.now().minusSeconds(1)));

        assertTrue(storage.deleteExpired() >= 5);
        assertEquals(0, jdbcTemplate.queryForObject("select count(*) from auth_refresh_sessions", Integer.class));
        assertEquals(0, jdbcTemplate.queryForObject("select count(*) from auth_recovery_tokens", Integer.class));
        assertEquals(0, jdbcTemplate.queryForObject("select count(*) from auth_mfa_login_challenges", Integer.class));
        assertEquals(0, jdbcTemplate.queryForObject("select count(*) from auth_session_cursors", Integer.class));
        assertEquals(0, jdbcTemplate.queryForObject("select count(*) from oauth_revoked_tokens", Integer.class));
    }

    private Object rotateAfter(CountDownLatch start,
                               String userId,
                               RefreshTokenCodec.IssuedRefreshToken current,
                               RefreshTokenCodec.IssuedRefreshToken next) throws Exception {
        start.await();
        try {
            return storage.rotateRefreshToken(userId, current.jti(), current.rawToken(), next.jti(), next.rawToken(), 7);
        } catch (TokenFamilyCompromisedException ex) {
            return ex;
        }
    }

    private void createSchema(JdbcTemplate jdbc) {
        jdbc.execute("""
                create table auth_refresh_token_families (
                    family_id varchar(64) primary key,
                    user_id uuid not null,
                    active_jti varchar(64) not null,
                    expires_at timestamp not null,
                    created_at timestamp not null,
                    updated_at timestamp not null
                )
                """);
        jdbc.execute("""
                create table auth_refresh_sessions (
                    user_id uuid not null,
                    jti varchar(64) not null,
                    token_hash char(64) not null,
                    family_id varchar(64) not null,
                    expires_at timestamp not null,
                    created_at timestamp not null,
                    updated_at timestamp not null,
                    primary key (user_id, jti)
                )
                """);
        jdbc.execute("create unique index uq_auth_refresh_sessions_jti on auth_refresh_sessions (jti)");
        jdbc.execute("create index ix_auth_refresh_sessions_user_expires_jti on auth_refresh_sessions (user_id, expires_at, jti)");
        jdbc.execute("""
                create table auth_recovery_tokens (
                    email_hash char(64) primary key,
                    token_hash char(64) not null,
                    expires_at timestamp not null,
                    created_at timestamp not null
                )
                """);
        jdbc.execute("""
                create table auth_mfa_login_challenges (
                    user_id uuid not null,
                    jti varchar(64) not null,
                    token_hash char(64) not null,
                    expires_at timestamp not null,
                    created_at timestamp not null,
                    primary key (user_id, jti)
                )
                """);
        jdbc.execute("""
                create table auth_session_cursors (
                    cursor_hash char(64) primary key,
                    user_id uuid not null,
                    next_jti varchar(64) not null,
                    expires_at timestamp not null,
                    created_at timestamp not null
                )
                """);
        jdbc.execute("""
                create table oauth_revoked_tokens (
                    jti varchar(128) primary key,
                    expires_at timestamp not null,
                    created_at timestamp not null
                )
                """);
    }
}
