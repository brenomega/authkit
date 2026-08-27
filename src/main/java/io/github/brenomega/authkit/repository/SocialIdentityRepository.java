package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.Collection;
import org.springframework.data.jpa.repository.JpaRepository;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentity;

public interface SocialIdentityRepository extends JpaRepository<SocialIdentity, UUID> {
    Optional<SocialIdentity> findByIssuerAndSubject(String issuer, String subject);
    Optional<SocialIdentity> findByIdAndUserId(UUID id, UUID userId);
    List<SocialIdentity> findByUserIdOrderByCreatedAtDesc(UUID userId);
    long countByUserId(UUID userId);
    boolean existsByUserIdAndProviderId(UUID userId, UUID providerId);
    long deleteByUserId(UUID userId);
    long deleteByUserIdIn(Collection<UUID> userIds);
}
