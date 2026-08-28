package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationTransaction;

/** Persists hashed browser authorization transactions and their conditional consumption. */
public interface OAuthAuthorizationTransactionRepository
        extends JpaRepository<OAuthAuthorizationTransaction, UUID> {
    Optional<OAuthAuthorizationTransaction> findByTokenHash(String tokenHash);

    /**
     * Consumes a live transaction exactly once.
     * @return {@code 1} on successful consumption or {@code 0} if expired or already consumed
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update OAuthAuthorizationTransaction t "
            + "set t.consumedAt = :now "
            + "where t.id = :id "
            + "and t.consumedAt is null "
            + "and t.expiresAt > :now")
    int consume(@Param("id") UUID id, @Param("now") Instant now);

    @Modifying
    @Query("delete from OAuthAuthorizationTransaction t where t.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
