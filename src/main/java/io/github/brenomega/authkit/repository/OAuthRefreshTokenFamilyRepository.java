package io.github.brenomega.authkit.repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshTokenFamily;

public interface OAuthRefreshTokenFamilyRepository
        extends JpaRepository<OAuthRefreshTokenFamily, UUID> {
    @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select f from OAuthRefreshTokenFamily f where f.id = :id")
    Optional<OAuthRefreshTokenFamily> findByIdForUpdate(@Param("id") UUID id);

    List<OAuthRefreshTokenFamily> findByUserIdIn(Collection<UUID> userIds);

    long deleteByUserIdIn(Collection<UUID> userIds);

    long deleteByUserId(UUID userId);
}
