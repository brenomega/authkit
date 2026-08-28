package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyChallenge;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyChallengeType;

/** Persists expiring WebAuthn ceremony state and its one-time transition. */
public interface PasskeyChallengeRepository extends JpaRepository<PasskeyChallenge, UUID> {

    Optional<PasskeyChallenge> findByIdAndCeremonyType(UUID id, PasskeyChallengeType ceremonyType);

    /**
     * Consumes a matching, unexpired challenge exactly once.
     *
     * @return {@code 1} only for the ceremony that performed the transition
     */
    @Modifying
    @Query("""
            update PasskeyChallenge challenge
               set challenge.consumedAt = :consumedAt
             where challenge.id = :id
               and challenge.ceremonyType = :ceremonyType
               and challenge.consumedAt is null
               and challenge.expiresAt > :consumedAt
            """)
    int consume(@Param("id") UUID id,
                @Param("ceremonyType") PasskeyChallengeType ceremonyType,
                @Param("consumedAt") Instant consumedAt);

    @Modifying
    @Query("delete from PasskeyChallenge challenge where challenge.expiresAt <= :now")
    int deleteExpired(@Param("now") Instant now);

    @Modifying
    long deleteByUserIdIn(Collection<UUID> userIds);
}
