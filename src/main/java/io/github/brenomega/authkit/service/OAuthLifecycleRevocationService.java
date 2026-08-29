package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.repository.OAuthRefreshTokenFamilyRepository;

/** Revokes every OAuth refresh lineage while participating in the lifecycle transaction. */
@Service
public class OAuthLifecycleRevocationService {
    private final OAuthRefreshTokenFamilyRepository familyRepository;

    public OAuthLifecycleRevocationService(OAuthRefreshTokenFamilyRepository familyRepository) {
        this.familyRepository = familyRepository;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public int revokeAll(UUID userId, Instant revokedAt) {
        return familyRepository.revokeActiveByUserId(userId, revokedAt);
    }
}
