package io.github.brenomega.authkit.infrastructure.persistence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidSessionCursorException;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.SessionPage;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.token-storage", name = "backend", havingValue = "jdbc")
public class JdbcTokenStorage implements TokenStorage {

    private final JdbcTemplate jdbcTemplate;
    private final TransactionTemplate transactionTemplate;
    private final Duration cursorTtl;

    public JdbcTokenStorage(JdbcTemplate jdbcTemplate,
                            @NonNull PlatformTransactionManager transactionManager,
                            AuthProperties authProperties) {
        this.jdbcTemplate = jdbcTemplate;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.cursorTtl = Duration.ofSeconds(
                authProperties.getTokenStorage().getJdbc().getSessionCursorTtlSeconds());
    }

    @Override
    public void storeRefreshToken(String userId, String jti, String rawToken, long durationDays) {
        RefreshTokenCodec.IssuedRefreshToken token = RefreshTokenCodec.parse(rawToken)
                .orElseThrow(() -> new IllegalArgumentException("Malformed refresh token"));
        if (!userId.equals(token.userId()) || !jti.equals(token.jti())) {
            throw new IllegalArgumentException("Refresh token metadata does not match storage key");
        }
        transactionTemplate.executeWithoutResult(status -> {
            Instant now = Instant.now();
            Instant expiresAt = now.plus(Duration.ofDays(durationDays));
            UUID userUuid = UUID.fromString(userId);
            String hash = hashToken(rawToken);
            int updatedFamily = jdbcTemplate.update("""
                    update auth_refresh_token_families
                    set active_jti = ?, expires_at = ?, updated_at = ?
                    where user_id = ? and family_id = ?
                    """,
                    jti,
                    timestamp(expiresAt),
                    timestamp(now),
                    userUuid,
                    token.familyId());
            if (updatedFamily == 0) {
                jdbcTemplate.update("""
                        insert into auth_refresh_token_families
                            (family_id, user_id, active_jti, expires_at, created_at, updated_at)
                        values (?, ?, ?, ?, ?, ?)
                        """,
                        token.familyId(),
                        userUuid,
                        jti,
                        timestamp(expiresAt),
                        timestamp(now),
                        timestamp(now));
            }
            jdbcTemplate.update("""
                    insert into auth_refresh_sessions
                        (user_id, jti, token_hash, family_id, expires_at, created_at, updated_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """,
                    userUuid,
                    jti,
                    hash,
                    token.familyId(),
                    timestamp(expiresAt),
                    timestamp(now),
                    timestamp(now));
        });
    }

    @Override
    public boolean validateToken(String userId, String jti, String rawToken) {
        return findSession(userId, jti, false)
                .map(session -> constantTimeEquals(session.tokenHash(), hashToken(rawToken)))
                .orElse(false);
    }

    @Override
    public boolean isSessionActive(String userId, String jti) {
        if (userId == null || userId.isBlank() || jti == null || jti.isBlank()) {
            return false;
        }
        return findSession(userId, jti, false).isPresent();
    }

    @Override
    public boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                                      String nextJti, String nextRawToken, long durationDays) {
        RefreshTokenCodec.IssuedRefreshToken currentToken = RefreshTokenCodec.parse(currentRawToken).orElse(null);
        RefreshTokenCodec.IssuedRefreshToken nextToken = RefreshTokenCodec.parse(nextRawToken).orElse(null);
        if (currentToken == null
                || nextToken == null
                || !userId.equals(currentToken.userId())
                || !userId.equals(nextToken.userId())
                || !currentJti.equals(currentToken.jti())
                || !nextJti.equals(nextToken.jti())
                || !currentToken.familyId().equals(nextToken.familyId())) {
            return false;
        }

        RotationResult result = transactionTemplate.execute(status -> {
            UUID userUuid = UUID.fromString(userId);
            Optional<FamilyState> family = lockFamily(userUuid, currentToken.familyId());
            if (family.isEmpty()) {
                return RotationResult.INVALID;
            }

            Optional<RefreshSession> current = lockSession(userUuid, currentJti);
            boolean validCurrent = current
                    .filter(session -> currentToken.familyId().equals(session.familyId()))
                    .filter(session -> family.get().activeJti().equals(currentJti))
                    .filter(session -> constantTimeEquals(session.tokenHash(), hashToken(currentRawToken)))
                    .isPresent();
            if (!validCurrent) {
                revokeFamily(userUuid, currentToken.familyId());
                return RotationResult.COMPROMISED;
            }

            Instant now = Instant.now();
            Instant expiresAt = now.plus(Duration.ofDays(durationDays));
            jdbcTemplate.update("""
                    delete from auth_refresh_sessions
                    where user_id = ? and jti = ?
                    """, userUuid, currentJti);
            jdbcTemplate.update("""
                    insert into auth_refresh_sessions
                        (user_id, jti, token_hash, family_id, expires_at, created_at, updated_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """,
                    userUuid,
                    nextJti,
                    hashToken(nextRawToken),
                    nextToken.familyId(),
                    timestamp(expiresAt),
                    timestamp(now),
                    timestamp(now));
            jdbcTemplate.update("""
                    update auth_refresh_token_families
                    set active_jti = ?, expires_at = ?, updated_at = ?
                    where user_id = ? and family_id = ?
                    """,
                    nextJti,
                    timestamp(expiresAt),
                    timestamp(now),
                    userUuid,
                    nextToken.familyId());
            return RotationResult.SUCCESS;
        });
        if (result == RotationResult.COMPROMISED) {
            throw new TokenFamilyCompromisedException();
        }
        return result == RotationResult.SUCCESS;
    }

    @Override
    public SessionPage listSessions(String userId, int limit, String cursor) {
        if (limit < 1 || limit > 100) {
            throw new InvalidSessionCursorException();
        }
        return transactionTemplate.execute(status -> {
            UUID userUuid = UUID.fromString(userId);
            String afterJti = cursor == null || cursor.isBlank()
                    ? null
                    : consumeCursor(userUuid, cursor);
            Instant now = Instant.now();
            List<String> rows;
            if (afterJti == null) {
                rows = jdbcTemplate.queryForList("""
                        select jti
                        from auth_refresh_sessions
                        where user_id = ? and expires_at > ?
                        order by jti asc
                        limit ?
                        """,
                        String.class,
                        userUuid,
                        timestamp(now),
                        limit + 1);
            } else {
                rows = jdbcTemplate.queryForList("""
                        select jti
                        from auth_refresh_sessions
                        where user_id = ? and expires_at > ? and jti > ?
                        order by jti asc
                        limit ?
                        """,
                        String.class,
                        userUuid,
                        timestamp(now),
                        afterJti,
                        limit + 1);
            }

            List<String> items = rows.size() > limit
                    ? List.copyOf(rows.subList(0, limit))
                    : List.copyOf(rows);
            String nextCursor = rows.size() > limit
                    ? storeCursor(userUuid, items.get(items.size() - 1))
                    : null;
            return new SessionPage(items, nextCursor);
        });
    }

    @Override
    public void revokeSession(String userId, String jti) {
        transactionTemplate.executeWithoutResult(status ->
                lockSession(UUID.fromString(userId), jti).ifPresent(session -> {
                    jdbcTemplate.update("delete from auth_refresh_sessions where user_id = ? and jti = ?",
                            UUID.fromString(userId), jti);
                    jdbcTemplate.update("delete from auth_refresh_token_families where user_id = ? and family_id = ?",
                            UUID.fromString(userId), session.familyId());
                }));
    }

    @Override
    public void revokeAllSessions(String userId) {
        transactionTemplate.executeWithoutResult(status -> {
            UUID userUuid = UUID.fromString(userId);
            jdbcTemplate.update("delete from auth_refresh_sessions where user_id = ?", userUuid);
            jdbcTemplate.update("delete from auth_refresh_token_families where user_id = ?", userUuid);
            jdbcTemplate.update("delete from auth_session_cursors where user_id = ?", userUuid);
        });
    }

    @Override
    public void revokeOtherSessions(String userId, String currentJti) {
        transactionTemplate.executeWithoutResult(status -> {
            UUID userUuid = UUID.fromString(userId);
            jdbcTemplate.update("""
                    delete from auth_refresh_sessions
                    where user_id = ? and jti <> ?
                    """, userUuid, currentJti);
            jdbcTemplate.update("""
                    delete from auth_refresh_token_families
                    where user_id = ? and active_jti <> ?
                    """, userUuid, currentJti);
            jdbcTemplate.update("delete from auth_session_cursors where user_id = ?", userUuid);
        });
    }

    @Override
    public void storeRecoveryToken(String email, String rawToken, long durationMinutes) {
        transactionTemplate.executeWithoutResult(status -> {
            Instant now = Instant.now();
            Instant expiresAt = now.plus(Duration.ofMinutes(durationMinutes));
            String emailHash = emailHash(email);
            int updated = jdbcTemplate.update("""
                    update auth_recovery_tokens
                    set token_hash = ?, expires_at = ?, created_at = ?
                    where email_hash = ?
                    """,
                    hashToken(rawToken),
                    timestamp(expiresAt),
                    timestamp(now),
                    emailHash);
            if (updated == 0) {
                jdbcTemplate.update("""
                        insert into auth_recovery_tokens (email_hash, token_hash, expires_at, created_at)
                        values (?, ?, ?, ?)
                        """,
                        emailHash,
                        hashToken(rawToken),
                        timestamp(expiresAt),
                        timestamp(now));
            }
        });
    }

    @Override
    public boolean validateRecoveryToken(String email, String rawToken) {
        return findRecoveryToken(email)
                .map(hash -> constantTimeEquals(hash, hashToken(rawToken)))
                .orElse(false);
    }

    @Override
    public boolean consumeRecoveryToken(String email, String rawToken) {
        Boolean consumed = transactionTemplate.execute(status -> {
            String emailHash = emailHash(email);
            Optional<StoredHash> stored = lockStoredHash("""
                    select token_hash, expires_at
                    from auth_recovery_tokens
                    where email_hash = ?
                    for update
                    """, emailHash);
            if (stored.isEmpty()) {
                return false;
            }
            if (!stored.get().expiresAt().isAfter(Instant.now())) {
                jdbcTemplate.update("delete from auth_recovery_tokens where email_hash = ?", emailHash);
                return false;
            }
            if (!constantTimeEquals(stored.get().tokenHash(), hashToken(rawToken))) {
                return false;
            }
            jdbcTemplate.update("delete from auth_recovery_tokens where email_hash = ?", emailHash);
            return true;
        });
        return Boolean.TRUE.equals(consumed);
    }

    @Override
    public void revokeRecoveryToken(String email) {
        jdbcTemplate.update("delete from auth_recovery_tokens where email_hash = ?", emailHash(email));
    }

    @Override
    public void storeMfaChallenge(String userId, String jti, String rawToken, long durationMinutes) {
        transactionTemplate.executeWithoutResult(status -> {
            Instant now = Instant.now();
            jdbcTemplate.update("""
                    insert into auth_mfa_login_challenges (user_id, jti, token_hash, expires_at, created_at)
                    values (?, ?, ?, ?, ?)
                    """,
                    UUID.fromString(userId),
                    jti,
                    hashToken(rawToken),
                    timestamp(now.plus(Duration.ofMinutes(durationMinutes))),
                    timestamp(now));
        });
    }

    @Override
    public boolean consumeMfaChallenge(String userId, String jti, String rawToken) {
        Boolean consumed = transactionTemplate.execute(status -> {
            UUID userUuid = UUID.fromString(userId);
            Optional<StoredHash> stored = lockStoredHash("""
                    select token_hash, expires_at
                    from auth_mfa_login_challenges
                    where user_id = ? and jti = ?
                    for update
                    """, userUuid, jti);
            if (stored.isEmpty()) {
                return false;
            }
            if (!stored.get().expiresAt().isAfter(Instant.now())) {
                jdbcTemplate.update("delete from auth_mfa_login_challenges where user_id = ? and jti = ?",
                        userUuid, jti);
                return false;
            }
            if (!constantTimeEquals(stored.get().tokenHash(), hashToken(rawToken))) {
                return false;
            }
            jdbcTemplate.update("delete from auth_mfa_login_challenges where user_id = ? and jti = ?",
                    userUuid, jti);
            return true;
        });
        return Boolean.TRUE.equals(consumed);
    }

    public int deleteExpired() {
        Integer deleted = transactionTemplate.execute(status -> {
            Timestamp now = timestamp(Instant.now());
            int count = 0;
            count += jdbcTemplate.update("delete from auth_refresh_sessions where expires_at <= ?", now);
            count += jdbcTemplate.update("delete from auth_refresh_token_families where expires_at <= ?", now);
            count += jdbcTemplate.update("delete from auth_recovery_tokens where expires_at <= ?", now);
            count += jdbcTemplate.update("delete from auth_mfa_login_challenges where expires_at <= ?", now);
            count += jdbcTemplate.update("delete from auth_session_cursors where expires_at <= ?", now);
            count += jdbcTemplate.update("delete from oauth_revoked_tokens where expires_at <= ?", now);
            return count;
        });
        return deleted == null ? 0 : deleted;
    }

    private Optional<RefreshSession> findSession(String userId, String jti, boolean lock) {
        return findSession(UUID.fromString(userId), jti, lock);
    }

    private Optional<RefreshSession> findSession(UUID userId, String jti, boolean lock) {
        String sql = """
                select token_hash, family_id, expires_at
                from auth_refresh_sessions
                where user_id = ? and jti = ? and expires_at > ?
                """ + (lock ? " for update" : "");
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject(
                    sql,
                    (rs, rowNum) -> new RefreshSession(
                            rs.getString("token_hash"),
                            rs.getString("family_id"),
                            rs.getTimestamp("expires_at").toInstant()),
                    userId,
                    jti,
                    timestamp(Instant.now())));
        } catch (EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    private Optional<RefreshSession> lockSession(UUID userId, String jti) {
        return findSession(userId, jti, true);
    }

    private Optional<FamilyState> lockFamily(UUID userId, String familyId) {
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject("""
                    select active_jti, expires_at
                    from auth_refresh_token_families
                    where user_id = ? and family_id = ? and expires_at > ?
                    for update
                    """,
                    (rs, rowNum) -> new FamilyState(
                            rs.getString("active_jti"),
                            rs.getTimestamp("expires_at").toInstant()),
                    userId,
                    familyId,
                    timestamp(Instant.now())));
        } catch (EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    private Optional<String> findRecoveryToken(String email) {
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject("""
                    select token_hash
                    from auth_recovery_tokens
                    where email_hash = ? and expires_at > ?
                    """,
                    String.class,
                    emailHash(email),
                    timestamp(Instant.now())));
        } catch (EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    private Optional<StoredHash> lockStoredHash(@NonNull String sql, Object... args) {
        try {
            return Optional.ofNullable(jdbcTemplate.queryForObject(
                    sql,
                    (rs, rowNum) -> new StoredHash(
                            rs.getString("token_hash"),
                            rs.getTimestamp("expires_at").toInstant()),
                    args));
        } catch (EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    private void revokeFamily(UUID userId, String familyId) {
        jdbcTemplate.update("delete from auth_refresh_sessions where user_id = ? and family_id = ?",
                userId, familyId);
        jdbcTemplate.update("delete from auth_refresh_token_families where user_id = ? and family_id = ?",
                userId, familyId);
        jdbcTemplate.update("delete from auth_session_cursors where user_id = ?", userId);
    }

    private String consumeCursor(UUID userId, String cursor) {
        String cursorHash = hashToken(cursor);
        try {
            CursorState state = jdbcTemplate.queryForObject("""
                    select user_id, next_jti, expires_at
                    from auth_session_cursors
                    where cursor_hash = ?
                    for update
                    """,
                    (rs, rowNum) -> new CursorState(
                            UUID.fromString(rs.getString("user_id")),
                            rs.getString("next_jti"),
                            rs.getTimestamp("expires_at").toInstant()),
                    cursorHash);
            jdbcTemplate.update("delete from auth_session_cursors where cursor_hash = ?", cursorHash);
            if (state == null || !userId.equals(state.userId()) || !state.expiresAt().isAfter(Instant.now())) {
                throw new InvalidSessionCursorException();
            }
            return state.nextJti();
        } catch (EmptyResultDataAccessException ex) {
            throw new InvalidSessionCursorException();
        }
    }

    private String storeCursor(UUID userId, String nextJti) {
        String cursor = SecureTokenGenerator.randomUrlSafeToken(24);
        Instant now = Instant.now();
        jdbcTemplate.update("""
                insert into auth_session_cursors (cursor_hash, user_id, next_jti, expires_at, created_at)
                values (?, ?, ?, ?, ?)
                """,
                hashToken(cursor),
                userId,
                nextJti,
                timestamp(now.plus(cursorTtl)),
                timestamp(now));
        return cursor;
    }

    private String emailHash(String email) {
        return TokenHasher.sha256Hex(email.trim().toLowerCase(Locale.ROOT));
    }

    private String hashToken(String rawToken) {
        return TokenHasher.sha256Hex(rawToken);
    }

    private boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private Timestamp timestamp(Instant instant) {
        return Timestamp.from(instant);
    }

    private record RefreshSession(String tokenHash, String familyId, Instant expiresAt) {
    }

    private record FamilyState(String activeJti, Instant expiresAt) {
    }

    private record StoredHash(String tokenHash, Instant expiresAt) {
    }

    private record CursorState(UUID userId, String nextJti, Instant expiresAt) {
    }

    private enum RotationResult {
        SUCCESS,
        INVALID,
        COMPROMISED
    }
}
