package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;

public interface SocialIdentityProviderRepository extends JpaRepository<SocialIdentityProvider, UUID> {
    Optional<SocialIdentityProvider> findByProviderKey(String providerKey);
    List<SocialIdentityProvider> findByOrderByCreatedAtDesc();
    boolean existsByIssuer(String issuer);
}
