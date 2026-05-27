package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, UUID> {

    Optional<OAuthClient> findByClientId(String clientId);

    List<OAuthClient> findByOrderByCreatedAtDesc();

    List<OAuthClient> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
