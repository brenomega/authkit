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

public interface SocialLoginTransactionRepository extends JpaRepository<SocialLoginTransaction, UUID> {
    Optional<SocialLoginTransaction> findByStateHashAndProviderId(String stateHash, UUID providerId);
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update SocialLoginTransaction t set t.consumedAt = :now where t.id = :id and t.consumedAt is null and t.expiresAt > :now")
    int consume(@Param("id") UUID id, @Param("now") Instant now);
    long deleteByUserId(UUID userId);
    long deleteByUserIdIn(Collection<UUID> userIds);
}
