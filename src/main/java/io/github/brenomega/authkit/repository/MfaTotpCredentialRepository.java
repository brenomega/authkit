package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;

import io.github.brenomega.authkit.domain.mfa.entity.MfaTotpCredential;

/** Persists TOTP enrollment state and replay-prevention time steps. */
public interface MfaTotpCredentialRepository extends JpaRepository<MfaTotpCredential, UUID> {

    boolean existsByUserIdAndConfirmedTrueAndDisabledAtIsNull(UUID userId);
    long countByUserIdAndConfirmedTrueAndDisabledAtIsNull(UUID userId);

    List<MfaTotpCredential> findByUserIdAndConfirmedTrueAndDisabledAtIsNull(UUID userId);
    List<MfaTotpCredential> findByUserIdOrderByCreatedAtDesc(UUID userId);

    Optional<MfaTotpCredential> findByIdAndUserId(UUID id, UUID userId);

    /** Locks pending enrollment state so confirmation has exactly one winner. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select credential from MfaTotpCredential credential where credential.id = :id and credential.userId = :userId")
    Optional<MfaTotpCredential> findByIdAndUserIdForUpdate(UUID id, UUID userId);

    @Modifying
    void deleteByUserIdAndConfirmedFalse(UUID userId);

    @Modifying
    long deleteByUserIdIn(Collection<UUID> userIds);

    /**
     * Advances the accepted TOTP time step only when it is newer than the stored value.
     *
     * @return {@code 1} when this caller claimed the step, otherwise {@code 0}
     */
    @Modifying
    @Query("""
            update MfaTotpCredential credential
               set credential.lastUsedTimeStep = :timeStep
             where credential.id = :id
               and credential.userId = :userId
               and credential.confirmed = true
               and credential.disabledAt is null
               and (credential.lastUsedTimeStep is null or credential.lastUsedTimeStep < :timeStep)
            """)
    int markTimeStepUsedIfNewer(UUID id, UUID userId, long timeStep);
}
