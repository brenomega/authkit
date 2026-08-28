package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshToken;

public interface OAuthRefreshTokenRepository extends JpaRepository<OAuthRefreshToken, UUID> {
    @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from OAuthRefreshToken t where t.tokenHash = :hash")
    Optional<OAuthRefreshToken> findByTokenHashForUpdate(@Param("hash") String hash);

    Optional<OAuthRefreshToken> findByTokenHash(String hash);

    List<OAuthRefreshToken> findByFamilyId(UUID familyId);

    long deleteByFamilyIdIn(Collection<UUID> familyIds);

    @Modifying
    @Query("delete from OAuthRefreshToken t where t.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
