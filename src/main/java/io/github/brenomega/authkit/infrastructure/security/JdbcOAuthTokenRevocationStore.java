package io.github.brenomega.authkit.infrastructure.security;

import java.sql.Timestamp;
import java.time.Instant;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.token-storage", name = "backend", havingValue = "jdbc")
public class JdbcOAuthTokenRevocationStore {

    private final JdbcTemplate jdbcTemplate;

    public JdbcOAuthTokenRevocationStore(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void revoke(String jti, Instant expiresAt) {
        Instant now = Instant.now();
        int updated = jdbcTemplate.update("""
                update oauth_revoked_tokens
                set expires_at = ?
                where jti = ?
                """,
                Timestamp.from(expiresAt),
                jti);
        if (updated == 0) {
            jdbcTemplate.update("""
                    insert into oauth_revoked_tokens (jti, expires_at, created_at)
                    values (?, ?, ?)
                    """,
                    jti,
                    Timestamp.from(expiresAt),
                    Timestamp.from(now));
        }
    }

    public boolean isRevoked(String jti) {
        try {
            Boolean revoked = jdbcTemplate.queryForObject("""
                    select exists (
                        select 1
                        from oauth_revoked_tokens
                        where jti = ? and expires_at > ?
                    )
                    """,
                    Boolean.class,
                    jti,
                    Timestamp.from(Instant.now()));
            return Boolean.TRUE.equals(revoked);
        } catch (EmptyResultDataAccessException ex) {
            return false;
        }
    }
}
