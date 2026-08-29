package io.github.brenomega.authkit.repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshTokenFamily;

/** Persists OAuth refresh lineages and provides the lock required for serialized rotation. */
public interface OAuthRefreshTokenFamilyRepository
        extends JpaRepository<OAuthRefreshTokenFamily, UUID> {
    /** Locks the family active-token pointer and compromise state for update. */
    @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select f from OAuthRefreshTokenFamily f where f.id = :id")
    Optional<OAuthRefreshTokenFamily> findByIdForUpdate(@Param("id") UUID id);

    List<OAuthRefreshTokenFamily> findByUserIdIn(Collection<UUID> userIds);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update OAuthRefreshTokenFamily f set f.revokedAt = :revokedAt " +
            "where f.userId = :userId and f.revokedAt is null")
    int revokeActiveByUserId(@Param("userId") UUID userId, @Param("revokedAt") java.time.Instant revokedAt);

    long deleteByUserIdIn(Collection<UUID> userIds);

    long deleteByUserId(UUID userId);
}
