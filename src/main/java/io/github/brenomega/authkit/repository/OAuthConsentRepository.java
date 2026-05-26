package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthConsent;

public interface OAuthConsentRepository extends JpaRepository<OAuthConsent, UUID> {

    Optional<OAuthConsent> findByUserIdAndClientIdAndRevokedAtIsNull(UUID userId, String clientId);

    List<OAuthConsent> findByUserIdOrderByGrantedAtDesc(UUID userId);
}
