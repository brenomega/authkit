package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.repository.UserRepository;

/**
 * Binds OAuth tokens to the durable account-lifecycle epoch current at issuance.
 * Lifecycle events are intentionally retained after reactivation/cancellation so
 * credentials issued before the transition can never become live again.
 */
@Service
public class OAuthAccountTokenStateService {

    public static final String EPOCH_CLAIM = "account_token_epoch";
    private static final String INITIAL_EPOCH = "initial";
    private static final List<SecurityEventType> INVALIDATING_EVENTS = List.of(
            SecurityEventType.ACCOUNT_SUSPENDED,
            SecurityEventType.ACCOUNT_DELETION_REQUESTED,
            SecurityEventType.ACCOUNT_ANONYMIZED);

    private final UserRepository userRepository;
    private final SecurityEventRepository securityEventRepository;

    public OAuthAccountTokenStateService(UserRepository userRepository,
                                         SecurityEventRepository securityEventRepository) {
        this.userRepository = userRepository;
        this.securityEventRepository = securityEventRepository;
    }

    @Transactional(readOnly = true)
    public String currentEpoch(UUID userId) {
        return securityEventRepository
                .findFirstByTargetUserIdAndEventTypeInOrderByOccurredAtDesc(userId, INVALIDATING_EVENTS)
                .map(event -> event.getId().toString())
                .orElse(INITIAL_EPOCH);
    }

    @Transactional(readOnly = true)
    public boolean isAccessTokenLive(Jwt jwt) {
        try {
            UUID userId = UUID.fromString(jwt.getSubject());
            String tokenEpoch = jwt.getClaimAsString(EPOCH_CLAIM);
            return tokenEpoch != null
                    && userRepository.findById(userId)
                            .filter(user -> user.isActive() && user.isEmailConfirmed())
                            .isPresent()
                    && tokenEpoch.equals(currentEpoch(userId));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    @Transactional(readOnly = true)
    public boolean isRefreshFamilyLive(UUID userId, Instant familyCreatedAt) {
        return userRepository.findById(userId)
                .filter(user -> user.isActive() && user.isEmailConfirmed())
                .isPresent()
                && securityEventRepository
                        .findFirstByTargetUserIdAndEventTypeInOrderByOccurredAtDesc(userId, INVALIDATING_EVENTS)
                        .map(event -> event.getOccurredAt().isBefore(familyCreatedAt))
                        .orElse(true);
    }
}
