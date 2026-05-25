package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import io.github.brenomega.authkit.domain.mfa.entity.MfaTotpCredential;

public interface MfaTotpCredentialRepository extends JpaRepository<MfaTotpCredential, UUID> {

    boolean existsByUserIdAndConfirmedTrueAndDisabledAtIsNull(UUID userId);

    List<MfaTotpCredential> findByUserIdAndConfirmedTrueAndDisabledAtIsNull(UUID userId);

    Optional<MfaTotpCredential> findByIdAndUserId(UUID id, UUID userId);

    @Modifying
    void deleteByUserIdAndConfirmedFalse(UUID userId);

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
