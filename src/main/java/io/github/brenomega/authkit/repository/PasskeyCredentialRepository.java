package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;

/** Persists active and disabled public passkey credentials. */
public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, UUID> {

    List<PasskeyCredential> findByUserIdAndDisabledAtIsNullOrderByCreatedAtDesc(UUID userId);

    Optional<PasskeyCredential> findByCredentialIdAndDisabledAtIsNull(String credentialId);

    List<PasskeyCredential> findByCredentialId(String credentialId);

    long countByUserIdAndDisabledAtIsNull(UUID userId);

    /** Updates usage metadata only for an active credential owned by the user. */
    @Modifying
    @Query("""
            update PasskeyCredential credential
               set credential.signatureCount = :signatureCount,
                   credential.lastUsedAt = :usedAt
             where credential.credentialId = :credentialId
               and credential.userId = :userId
               and credential.disabledAt is null
            """)
    int markUsed(@Param("credentialId") String credentialId,
                 @Param("userId") UUID userId,
                 @Param("signatureCount") long signatureCount,
                 @Param("usedAt") Instant usedAt);

    /**
     * Disables an active credential only when it is owned by the supplied user.
     *
     * @return {@code 1} when the credential was disabled
     */
    @Modifying
    @Query("""
            update PasskeyCredential credential
               set credential.disabledAt = :disabledAt
             where credential.id = :id
               and credential.userId = :userId
               and credential.disabledAt is null
            """)
    int disable(@Param("id") UUID id, @Param("userId") UUID userId, @Param("disabledAt") Instant disabledAt);

    @Query("""
            select credential
              from PasskeyCredential credential
             where credential.userId in :userIds
               and credential.disabledAt is null
            """)
    List<PasskeyCredential> findActiveByUserIds(@Param("userIds") Set<UUID> userIds);

    @Modifying
    long deleteByUserIdIn(Collection<UUID> userIds);
}
