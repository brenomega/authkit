package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.Collection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentity;

/** Provides issuer-subject identity lookup and user-owned link management. */
public interface SocialIdentityRepository extends JpaRepository<SocialIdentity, UUID> {
    /** Resolves the globally stable federated identity tuple; email is not a lookup key. */
    Optional<SocialIdentity> findByIssuerAndSubject(String issuer, String subject);
    Optional<SocialIdentity> findByIdAndUserId(UUID id, UUID userId);
    List<SocialIdentity> findByUserIdOrderByCreatedAtDesc(UUID userId);
    long countByUserId(UUID userId);
    @Query("""
            select count(identity) from SocialIdentity identity, SocialIdentityProvider provider
            where identity.providerId = provider.id
              and identity.userId = :userId
              and provider.enabled = true
              and provider.disabledAt is null
            """)
    long countEnabledByUserId(@Param("userId") UUID userId);

    @Query("""
            select count(identity) from SocialIdentity identity, SocialIdentityProvider provider
            where identity.providerId = provider.id
              and identity.userId = :userId
              and identity.id <> :excludedIdentityId
              and provider.enabled = true
              and provider.disabledAt is null
            """)
    long countEnabledByUserIdExcluding(
            @Param("userId") UUID userId,
            @Param("excludedIdentityId") UUID excludedIdentityId);
    boolean existsByUserIdAndProviderId(UUID userId, UUID providerId);
    long deleteByUserId(UUID userId);
    long deleteByUserIdIn(Collection<UUID> userIds);
}
