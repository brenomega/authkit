package io.github.brenomega.authkit.infrastructure.persistence;

import java.util.Collection;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.stereotype.Component;

/**
 * Isolated audit-retention connection. These credentials must belong only to
 * a login that has been granted the non-login {@code authkit_retention} role.
 */
@Component
@ConditionalOnProperty(prefix = "authkit.auth.compliance", name = "retention-job-enabled",
        havingValue = "true", matchIfMissing = true)
public class RetentionDeleteGateway {

    private final JdbcTemplate jdbcTemplate;

    public RetentionDeleteGateway(
            @Value("${AUTH_RETENTION_DB_URL:}") String url,
            @Value("${AUTH_RETENTION_DB_USERNAME:}") String username,
            @Value("${AUTH_RETENTION_DB_PASSWORD:}") String password) {
        if (url.isBlank() || username.isBlank() || password.isBlank()) {
            throw new IllegalStateException(
                    "Retention worker requires AUTH_RETENTION_DB_URL, AUTH_RETENTION_DB_USERNAME, and AUTH_RETENTION_DB_PASSWORD");
        }
        DriverManagerDataSource dataSource = new DriverManagerDataSource(url, username, password);
        dataSource.setDriverClassName("org.postgresql.Driver");
        this.jdbcTemplate = new JdbcTemplate((DataSource) dataSource);
    }

    public long purgeSecurityEvents(Collection<UUID> eventIds) {
        return call("select retention_purge_security_events(?)", eventIds);
    }

    public long purgeSecurityEventsForUsers(Collection<UUID> userIds) {
        return call("select retention_purge_security_events_for_users(?)", userIds);
    }

    public long purgeConsentEventsForUsers(Collection<UUID> userIds) {
        return call("select retention_purge_consent_events_for_users(?)", userIds);
    }

    private long call(String sql, Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return 0;
        }
        Long deleted = jdbcTemplate.execute((ConnectionCallback<Long>) connection -> {
            try (var statement = connection.prepareStatement(sql)) {
                statement.setArray(1, connection.createArrayOf("uuid", ids.toArray(UUID[]::new)));
                try (var result = statement.executeQuery()) {
                    return result.next() ? result.getLong(1) : 0L;
                }
            }
        });
        return deleted == null ? 0 : deleted;
    }
}
