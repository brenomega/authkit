package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.Collection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.github.brenomega.authkit.domain.social.entity.SocialLoginTransaction;

/** Persists hashed social-login state and its expiring one-time transition. */
public interface SocialLoginTransactionRepository extends JpaRepository<SocialLoginTransaction, UUID> {
    Optional<SocialLoginTransaction> findByStateHashAndProviderId(String stateHash, UUID providerId);
    /**
     * Consumes a live callback transaction exactly once.
     * @return {@code 1} on success or {@code 0} if expired or previously consumed
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update SocialLoginTransaction t set t.consumedAt = :now where " +
        "t.id = :id and t.consumedAt is null and t.expiresAt > :now")
    int consume(@Param("id") UUID id, @Param("now") Instant now);
    long deleteByUserId(UUID userId);
    long deleteByUserIdIn(Collection<UUID> userIds);
}
