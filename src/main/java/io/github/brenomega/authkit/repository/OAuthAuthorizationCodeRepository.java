package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationCode;

public interface OAuthAuthorizationCodeRepository extends JpaRepository<OAuthAuthorizationCode, UUID> {

    Optional<OAuthAuthorizationCode> findByCodeHash(String codeHash);

    @Modifying
    @Query("""
            update OAuthAuthorizationCode code
               set code.consumedAt = :consumedAt
             where code.codeHash = :codeHash
               and code.consumedAt is null
               and code.expiresAt > :consumedAt
            """)
    int consume(@Param("codeHash") String codeHash, @Param("consumedAt") Instant consumedAt);

    @Modifying
    @Query("delete from OAuthAuthorizationCode code where code.expiresAt <= :now")
    int deleteExpired(@Param("now") Instant now);

    @Modifying
    long deleteByUserIdIn(Collection<UUID> userIds);
}
