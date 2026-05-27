package io.github.brenomega.authkit.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.UUID;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

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
        }
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
                        deleted_at, anonymized_at
                    )
                    values (
                        '%s', 'deleted-%s@example.test', 'hash', 'USER', '%s', true, true,
                        false, 'terms-v1', 'privacy-v1', 'consent', now() - interval '31 days', now() - interval '31 days'
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
                        id, tenant_id, client_id, public_client, display_name, redirect_uris, scopes,
                        require_pkce, enabled, created_at, updated_at
                    )
                    values ('%s', '%s', '%s', true, 'Client', 'https://client.example/callback',
                            'openid', true, true, now(), now())
                    """.formatted(oauthClientId, tenantId, clientId));
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
}
