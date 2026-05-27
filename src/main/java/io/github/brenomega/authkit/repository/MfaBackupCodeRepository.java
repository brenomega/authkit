package io.github.brenomega.authkit.repository;

import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import io.github.brenomega.authkit.domain.mfa.entity.MfaBackupCode;

public interface MfaBackupCodeRepository extends JpaRepository<MfaBackupCode, UUID> {

    int countByUserIdAndUsedAtIsNull(UUID userId);

    Optional<MfaBackupCode> findByUserIdAndCodeHashAndUsedAtIsNull(UUID userId, String codeHash);

    @Modifying
    @Query("""
            update MfaBackupCode code
               set code.usedAt = :usedAt
             where code.userId = :userId
               and code.codeHash = :codeHash
               and code.usedAt is null
            """)
    int consumeUnusedCode(UUID userId, String codeHash, java.time.Instant usedAt);

    @Modifying
    void deleteByUserIdAndUsedAtIsNull(UUID userId);

    @Modifying
    long deleteByUserIdIn(Collection<UUID> userIds);
}
