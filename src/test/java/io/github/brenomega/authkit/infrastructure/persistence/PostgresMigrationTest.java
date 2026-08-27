package io.github.brenomega.authkit.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;

@Testcontainers(disabledWithoutDocker = true)
class PostgresMigrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:17-alpine"));

    @Test
    @DisplayName("Flyway migrations apply on PostgreSQL and enforce lower(email) uniqueness")
    void flywayMigrations_applyOnPostgres() throws Exception {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();

        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {

            statement.executeUpdate("""
                    insert into users (id, email, password, role)
                    values ('%s', 'Case@Test.Example', 'hash', 'USER')
                    """.formatted(UUID.randomUUID()));

            assertThrows(SQLException.class, () -> statement.executeUpdate("""
                    insert into users (id, email, password, role)
                    values ('%s', 'case@test.example', 'hash', 'USER')
                    """.formatted(UUID.randomUUID())));

            try (var result = statement.executeQuery("select count(*) from information_schema.tables where table_name = 'shedlock'")) {
                result.next();
                assertEquals(1, result.getInt(1));
            }
            try (var result = statement.executeQuery("select count(*) from information_schema.tables where table_name = 'auth_refresh_sessions'")) {
                result.next();
                assertEquals(1, result.getInt(1));
            }
            try (var result = statement.executeQuery("select count(*) from information_schema.tables where table_name = 'oauth_revoked_tokens'")) {
                result.next();
                assertEquals(1, result.getInt(1));
            }
            assertEquals("1", scalar(statement,
                    "select count(*) from information_schema.tables where table_name = 'social_identity_providers'"));
            assertEquals("1", scalar(statement,
                    "select count(*) from information_schema.tables where table_name = 'social_identities'"));
            assertEquals("1", scalar(statement,
                    "select count(*) from information_schema.tables where table_name = 'social_login_transactions'"));
            assertEquals("1", scalar(statement,
                    "select count(*) from information_schema.tables where table_name = 'oauth_authorization_transactions'"));
            assertEquals("1", scalar(statement,
                    "select count(*) from information_schema.tables where table_name = 'oauth_refresh_token_families'"));
            assertEquals("1", scalar(statement,
                    "select count(*) from information_schema.tables where table_name = 'oauth_refresh_tokens'"));
            assertEquals("character varying", scalar(statement, """
                    select data_type from information_schema.columns
                    where table_schema = current_schema() and table_name = 'users'
                      and column_name = 'email_change_token_hash'
                    """));
            assertEquals("1|false", scalar(statement, """
                    select id::text || '|' || (completed_at is not null)::text
                    from authkit_bootstrap_state
                    """));
        }
    }

    @Test
    @DisplayName("Runtime cannot delete audit rows while the retention role can use only audited purge functions")
    void retentionRoleSeparatesAuditDeletion() throws Exception {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();

        String workerRole = "retention_" + UUID.randomUUID().toString().replace("-", "");
        UUID eventId = UUID.randomUUID();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            statement.executeUpdate("create role " + workerRole + " nologin nosuperuser");
            statement.executeUpdate("grant usage on schema public to " + workerRole);
            statement.executeUpdate("grant authkit_retention to " + workerRole);
            statement.executeUpdate("""
                    insert into security_events (id, occurred_at, event_type, outcome, severity, event_hash)
                    values ('%s', now(), 'LOGIN_FAILURE', 'FAILURE', 'MEDIUM', '%s')
                    """.formatted(eventId, "f".repeat(64)));

            statement.execute("set role authkit_runtime");
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "delete from security_events where id = '" + eventId + "'"));
            assertThrows(SQLException.class, () -> statement.executeQuery(
                    "select retention_purge_security_events(array['" + eventId + "'::uuid])"));
            statement.execute("reset role");

            statement.execute("set role " + workerRole);
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "delete from security_events where id = '" + eventId + "'"));
            assertEquals("1", scalar(statement,
                    "select retention_purge_security_events(array['" + eventId + "'::uuid])"));
            statement.execute("reset role");

            assertEquals("1", scalar(statement,
                    "select count(*) from retention_purge_log where dataset = 'security_events_by_id' and deleted_count = 1"));
        }
    }

    @Test
    @DisplayName("V15 safely migrates representative legacy roles, lifecycle data, phone, and OAuth clients")
    void v15MigratesRepresentativeExistingData() throws Exception {
        String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
        String jdbcUrl = POSTGRES.getJdbcUrl()
                + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?")
                + "currentSchema=" + schema + ",public";

        Flyway.configure()
                .dataSource(jdbcUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .schemas(schema)
                .defaultSchema(schema)
                .locations("classpath:db/migration")
                .target("14")
                .load()
                .migrate();

        UUID adminId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        UUID pendingId = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();
        UUID outboxId = UUID.randomUUID();
        String legacyJti = UUID.randomUUID().toString();
        String legacyFamily = UUID.randomUUID().toString();
        try (var connection = DriverManager.getConnection(jdbcUrl, POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            statement.executeUpdate("""
                    insert into users (id, email, password, role, phone)
                    values
                      ('%s', 'legacy-admin@example.test', 'hash', 'ADMIN', '111'),
                      ('%s', 'legacy-owner@example.test', 'hash', 'OWNER', '222'),
                      ('%s', 'legacy-pending@example.test', 'hash', 'TENANT_ADMIN', '333')
                    """.formatted(adminId, ownerId, pendingId));
            statement.executeUpdate("update users set deletion_requested_at = now() where id = '%s'".formatted(pendingId));
            statement.executeUpdate("""
                    insert into email_outbox
                        (id, recipient, subject, body, status, attempts, next_attempt_at, created_at, updated_at)
                    values ('%s', 'legacy@example.test', 'Legacy', '<p>Legacy</p>', 'SENT', 1, now(), now(), now())
                    """.formatted(outboxId));
            statement.executeUpdate("""
                    insert into auth_refresh_token_families
                        (family_id, user_id, active_jti, expires_at, created_at, updated_at)
                    values ('%s', '%s', '%s', now() + interval '7 days', now(), now())
                    """.formatted(legacyFamily, ownerId, legacyJti));
            statement.executeUpdate("""
                    insert into auth_refresh_sessions
                        (user_id, jti, token_hash, family_id, expires_at, created_at, updated_at)
                    values ('%s', '%s', '%s', '%s', now() + interval '7 days', now(), now())
                    """.formatted(ownerId, legacyJti, "a".repeat(64), legacyFamily));
            statement.executeUpdate("""
                    insert into oauth_clients (
                        id, tenant_id, client_id, public_client, display_name, redirect_uris,
                        scopes, require_pkce, enabled, created_at, updated_at
                    ) values ('%s', '%s', 'legacy-client', true, 'Legacy',
                              'https://client.example/callback', 'openid', true, true, now(), now())
                    """.formatted(clientId, UUID.randomUUID()));
        }

        Flyway.configure()
                .dataSource(jdbcUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .schemas(schema)
                .defaultSchema(schema)
                .locations("classpath:db/migration")
                .load()
                .migrate();

        try (var connection = DriverManager.getConnection(jdbcUrl, POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            assertEquals("PLATFORM_ADMIN", scalar(statement,
                    "select role from users where id = '" + adminId + "'"));
            assertEquals(adminId.toString(), scalar(statement,
                    "select admin_user_id::text from authkit_bootstrap_state where completed_at is not null"));
            assertEquals("USER", scalar(statement,
                    "select role from users where id = '" + ownerId + "'"));
            assertEquals("DELETION_PENDING", scalar(statement,
                    "select account_state from users where id = '" + pendingId + "'"));
            assertEquals("0", scalar(statement, """
                    select count(*) from information_schema.columns
                    where table_schema = current_schema() and table_name = 'users' and column_name = 'phone'
                    """));
            assertEquals("1", scalar(statement, """
                    select count(*) from auth_refresh_sessions
                    where jti = '%s' and public_session_id is not null
                      and last_seen_at is not null and user_agent_summary = 'Unknown client'
                      and creation_ip_masked = 'unknown' and last_ip_masked = 'unknown'
                    """.formatted(legacyJti)));
            assertEquals("0", scalar(statement, """
                    select count(*) from information_schema.columns
                    where table_schema = current_schema() and table_name = 'oauth_clients' and column_name = 'tenant_id'
                    """));
            assertEquals("ACCEPTED", scalar(statement,
                    "select status from email_outbox where id = '" + outboxId + "'"));
            assertEquals("1", scalar(statement, """
                    select count(*) from information_schema.columns
                    where table_schema = current_schema() and table_name = 'email_outbox' and column_name = 'accepted_at'
                    """));
            assertEquals("0", scalar(statement, """
                    select count(*) from information_schema.columns
                    where table_schema = current_schema() and table_name = 'email_outbox' and column_name = 'delivered_at'
                    """));

            UUID socialOnlyId = UUID.randomUUID();
            UUID providerId = UUID.randomUUID();
            statement.executeUpdate("""
                    insert into users (id, email, password, role)
                    values ('%s', 'social-only@example.test', null, 'USER')
                    """.formatted(socialOnlyId));
            statement.executeUpdate("""
                    insert into social_identity_providers
                      (id, provider_key, display_name, provider_type, issuer, client_id,
                       encrypted_client_secret, scopes, client_auth_method, created_at, updated_at)
                    values ('%s', 'generic', 'Generic', 'GENERIC_OIDC', 'https://issuer.example',
                            'client', 'encrypted', 'openid email', 'CLIENT_SECRET_BASIC', now(), now())
                    """.formatted(providerId));
            statement.executeUpdate("""
                    insert into social_identities
                      (id, user_id, tenant_id, provider_id, issuer, subject, email_at_link,
                       email_verified, created_at)
                    select '%s', id, tenant_id, '%s', 'https://issuer.example', 'subject-1',
                           email, true, now() from users where id = '%s'
                    """.formatted(UUID.randomUUID(), providerId, socialOnlyId));
            assertThrows(SQLException.class, () -> statement.executeUpdate("""
                    insert into social_identities
                      (id, user_id, tenant_id, provider_id, issuer, subject, email_verified, created_at)
                    select '%s', id, tenant_id, '%s', 'https://issuer.example', 'subject-1', true, now()
                    from users where id = '%s'
                    """.formatted(UUID.randomUUID(), providerId, ownerId)));

            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "update users set role = 'USER' where id = '" + adminId + "'"));
        }
    }

    @Test
    @DisplayName("PostgreSQL ShedLock permits only one competing scheduler holder")
    void shedLockCoordinatesCompetingHolders() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();

        @SuppressWarnings("null")
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var firstProvider = lockProvider(dataSource);
        var secondProvider = lockProvider(dataSource);
        var configuration = new LockConfiguration(
                Instant.now(),
                "emailOutboxPoll-test-" + UUID.randomUUID(),
                Duration.ofMinutes(10),
                Duration.ZERO);
        AtomicInteger executions = new AtomicInteger();

        var firstLock = firstProvider.lock(configuration).orElseThrow();
        try {
            executions.incrementAndGet();
            assertTrue(secondProvider.lock(configuration).isEmpty());
            assertEquals(1, executions.get());
        } finally {
            firstLock.unlock();
        }

        var retryLock = secondProvider.lock(configuration).orElseThrow();
        try {
            executions.incrementAndGet();
        } finally {
            retryLock.unlock();
        }
        assertEquals(2, executions.get());
    }

    @Test
    @DisplayName("Flyway schema allows deleted-account purge after related auth records are cleaned")
    void flywayMigrations_allowDeletedAccountPurgeWithRelatedRows() throws Exception {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();

        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID oauthClientId = UUID.randomUUID();
        String clientId = "client-" + UUID.randomUUID();

        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {

            statement.executeUpdate("""
                    insert into users (
                        id, email, password, role, tenant_id, terms_accepted, privacy_policy_accepted,
                        email_confirmed, terms_version, privacy_policy_version, lawful_basis,
                        account_state, deletion_requested_at, deleted_at, anonymized_at
                    )
                    values (
                        '%s', 'deleted-%s@example.test', 'hash', 'USER', '%s', true, true,
                        false, 'terms-v1', 'privacy-v1', 'consent', 'ANONYMIZED',
                        now() - interval '31 days', now() - interval '31 days', now() - interval '31 days'
                    )
                    """.formatted(userId, userId, tenantId));
            statement.executeUpdate("""
                    insert into mfa_totp_credentials (id, user_id, tenant_id, encrypted_secret, confirmed, created_at)
                    values ('%s', '%s', '%s', 'secret', true, now())
                    """.formatted(UUID.randomUUID(), userId, tenantId));
            statement.executeUpdate("""
                    insert into mfa_backup_codes (id, user_id, tenant_id, code_hash, created_at)
                    values ('%s', '%s', '%s', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', now())
                    """.formatted(UUID.randomUUID(), userId, tenantId));
            statement.executeUpdate("""
                    insert into passkey_credentials (
                        id, user_id, tenant_id, credential_id, public_key_cose, signature_count, created_at
                    )
                    values ('%s', '%s', '%s', 'credential-%s', 'public-key', 0, now())
                    """.formatted(UUID.randomUUID(), userId, tenantId, userId));
            statement.executeUpdate("""
                    insert into passkey_challenges (
                        id, ceremony_type, user_id, request_json, created_at, expires_at
                    )
                    values ('%s', 'REGISTRATION', '%s', '{}', now(), now() + interval '5 minutes')
                    """.formatted(UUID.randomUUID(), userId));
            statement.executeUpdate("""
                    insert into oauth_clients (
                        id, client_id, public_client, display_name, redirect_uris, scopes,
                        require_pkce, enabled, created_at, updated_at
                    )
                    values ('%s', '%s', true, 'Client', 'https://client.example/callback',
                            'openid', true, true, now(), now())
                    """.formatted(oauthClientId, clientId));
            statement.executeUpdate("""
                    insert into oauth_consents (id, user_id, tenant_id, client_id, scopes, granted_at)
                    values ('%s', '%s', '%s', '%s', 'openid', now())
                    """.formatted(UUID.randomUUID(), userId, tenantId, clientId));
            statement.executeUpdate("""
                    insert into oauth_authorization_codes (
                        id, code_hash, client_id, user_id, tenant_id, redirect_uri, scopes, amr,
                        code_challenge, code_challenge_method, created_at, expires_at
                    )
                    values ('%s', '%s', '%s', '%s', '%s', 'https://client.example/callback',
                            'openid', 'pwd', '%s', 'S256', now(), now() + interval '5 minutes')
                    """.formatted(
                    UUID.randomUUID(),
                    "b".repeat(64),
                    clientId,
                    userId,
                    tenantId,
                    "c".repeat(43)));
            statement.executeUpdate("""
                    insert into security_events (
                        id, occurred_at, event_type, outcome, severity, actor_user_id, target_user_id, event_hash
                    )
                    values ('%s', now(), 'ACCOUNT_DELETION_REQUESTED', 'SUCCESS', 'HIGH', '%s', '%s', '%s')
                    """.formatted(UUID.randomUUID(), userId, userId, "d".repeat(64)));
            statement.executeUpdate("""
                    insert into consent_events (
                        id, user_id, tenant_id, terms_version, privacy_policy_version, lawful_basis,
                        accepted_at, recorded_at, event_hash
                    )
                    values ('%s', '%s', '%s', 'terms-v1', 'privacy-v1', 'consent', now(), now(), '%s')
                    """.formatted(UUID.randomUUID(), userId, tenantId, "e".repeat(64)));

            statement.executeUpdate("delete from security_events where actor_user_id = '%s' or target_user_id = '%s'".formatted(userId, userId));
            statement.executeUpdate("delete from consent_events where user_id = '%s'".formatted(userId));
            statement.executeUpdate("delete from users where id = '%s'".formatted(userId));

            assertEquals(0, count(statement, "mfa_totp_credentials", userId));
            assertEquals(0, count(statement, "mfa_backup_codes", userId));
            assertEquals(0, count(statement, "passkey_credentials", userId));
            assertEquals(0, count(statement, "passkey_challenges", userId));
            assertEquals(0, count(statement, "oauth_consents", userId));
            assertEquals(0, count(statement, "oauth_authorization_codes", userId));
        }
    }

    private int count(java.sql.Statement statement, String table, UUID userId) throws SQLException {
        try (var result = statement.executeQuery("select count(*) from " + table + " where user_id = '" + userId + "'")) {
            result.next();
            return result.getInt(1);
        }
    }

    private String scalar(java.sql.Statement statement, String sql) throws SQLException {
        try (var result = statement.executeQuery(sql)) {
            result.next();
            return result.getString(1);
        }
    }

    @SuppressWarnings("null")
private JdbcTemplateLockProvider lockProvider(DriverManagerDataSource dataSource) {
        return new JdbcTemplateLockProvider(
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource))
                        .usingDbTime()
                        .build());
    }
}
