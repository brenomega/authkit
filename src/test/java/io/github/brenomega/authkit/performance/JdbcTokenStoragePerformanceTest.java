package io.github.brenomega.authkit.performance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.persistence.JdbcTokenStorage;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

@Tag("performance")
class JdbcTokenStoragePerformanceTest {

    private JdbcTokenStorage storage;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:jdbc-token-perf-" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa",
                "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        createSchema(jdbcTemplate);
        AuthProperties properties = new AuthProperties();
        properties.getTokenStorage().setBackend("jdbc");
        properties.getTokenStorage().setSingleInstanceMode(true);
        properties.getTokenStorage().getJdbc().setSessionCursorTtlSeconds(300);
        properties.getAudit().setHashPepper("jdbc-perf-audit-hash-pepper-32-bytes");
        storage = new JdbcTokenStorage(
                jdbcTemplate,
                new DataSourceTransactionManager(dataSource),
                properties,
                new AuditDigestService(properties));
    }

    @Test
    void boundedSessionPaginationHandlesHundredsOfRowsWithinLocalProbeBudget() {
        String userId = UUID.randomUUID().toString();
        for (int i = 0; i < 300; i++) {
            String jti = UUID.randomUUID().toString();
            storage.storeRefreshToken(userId, jti, RefreshTokenCodec.issue(userId, jti).rawToken(), 7);
        }

        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            int seen = 0;
            String cursor = null;
            do {
                var page = storage.listSessions(userId, 50, cursor);
                seen += page.items().size();
                cursor = page.nextCursor();
            } while (cursor != null);
            assertEquals(300, seen);
        });
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
                    public_session_id uuid not null,
                    last_seen_at timestamp not null,
                    initial_amr varchar(160) not null,
                    user_agent_summary varchar(200) not null,
                    device_label varchar(80),
                    creation_ip_masked varchar(64) not null,
                    last_ip_masked varchar(64) not null,
                    primary key (user_id, jti)
                )
                """);
        jdbc.execute("create unique index uq_auth_refresh_sessions_jti on auth_refresh_sessions (jti)");
        jdbc.execute("create unique index uq_auth_refresh_sessions_public_id on auth_refresh_sessions (public_session_id)");
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
