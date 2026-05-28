package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.repository.MfaBackupCodeRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.PasskeyChallengeRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.PasswordHistoryRepository;
import io.github.brenomega.authkit.repository.UserRepository;

class DataRetentionServiceTest {

    @SuppressWarnings("null")
    @Test
    @DisplayName("Retention purges expired security events and deleted account tombstones")
    void purgeExpiredSecurityEvents_purgesEventsAndDeletedUsers() {
        SecurityEventRepository securityEventRepository = mock(SecurityEventRepository.class);
        UserRepository userRepository = mock(UserRepository.class);
        PasskeyChallengeRepository passkeyChallengeRepository = mock(PasskeyChallengeRepository.class);
        OAuthAuthorizationCodeRepository oauthAuthorizationCodeRepository = mock(OAuthAuthorizationCodeRepository.class);
        MfaTotpCredentialRepository mfaTotpCredentialRepository = mock(MfaTotpCredentialRepository.class);
        MfaBackupCodeRepository mfaBackupCodeRepository = mock(MfaBackupCodeRepository.class);
        PasskeyCredentialRepository passkeyCredentialRepository = mock(PasskeyCredentialRepository.class);
        OAuthConsentRepository oauthConsentRepository = mock(OAuthConsentRepository.class);
        PasswordHistoryRepository passwordHistoryRepository = mock(PasswordHistoryRepository.class);
        ConsentEventRepository consentEventRepository = mock(ConsentEventRepository.class);
        EmailOutboxService emailOutboxService = mock(EmailOutboxService.class);
        AuthProperties authProperties = new AuthProperties();
        authProperties.getCompliance().setSecurityEventRetentionDays(30);
        authProperties.getCompliance().setDeletedAccountRetentionDays(7);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        TransactionTemplate transactionTemplate = mock(TransactionTemplate.class);
        when(transactionTemplate.execute(any())).thenAnswer(invocation -> {
            TransactionCallback<?> callback = invocation.getArgument(0);
            return callback.doInTransaction(null);
        });

        UUID eventOne = UUID.fromString("00000000-0000-0000-0000-000000000101");
        UUID eventTwo = UUID.fromString("00000000-0000-0000-0000-000000000102");
        UUID deletedUser = UUID.fromString("00000000-0000-0000-0000-000000000201");
        User deletedUserEntity = mock(User.class);
        when(deletedUserEntity.getEmail()).thenReturn("deleted@example.test");
        when(securityEventRepository.findExpiredIds(any(), any(Pageable.class)))
                .thenReturn(List.of(eventOne, eventTwo));
        when(securityEventRepository.purgeByIdIn(List.of(eventOne, eventTwo))).thenReturn(5L);
        when(userRepository.findDeletedIdsBefore(any(), any(Pageable.class)))
                .thenReturn(List.of(deletedUser));
        when(userRepository.findAllById(List.of(deletedUser))).thenReturn(List.of(deletedUserEntity));
        when(userRepository.purgeDeletedByIdIn(List.of(deletedUser))).thenReturn(2L);

        when(passkeyChallengeRepository.deleteExpired(any())).thenReturn(3);
        when(oauthAuthorizationCodeRepository.deleteExpired(any())).thenReturn(4);

        new DataRetentionService(
                securityEventRepository,
                userRepository,
                passkeyChallengeRepository,
                oauthAuthorizationCodeRepository,
                mfaTotpCredentialRepository,
                mfaBackupCodeRepository,
                passkeyCredentialRepository,
                oauthConsentRepository,
                passwordHistoryRepository,
                consentEventRepository,
                emailOutboxService,
                authProperties,
                meterRegistry,
                transactionTemplate)
                .purgeExpiredSecurityEvents();

        ArgumentCaptor<Instant> eventCutoff = ArgumentCaptor.forClass(Instant.class);
        ArgumentCaptor<Instant> accountCutoff = ArgumentCaptor.forClass(Instant.class);
        verify(securityEventRepository).findExpiredIds(eventCutoff.capture(), any(Pageable.class));
        verify(userRepository).findDeletedIdsBefore(accountCutoff.capture(), any(Pageable.class));
        verify(securityEventRepository).purgeByIdIn(List.of(eventOne, eventTwo));
        verify(userRepository).purgeDeletedByIdIn(List.of(deletedUser));
        verify(passkeyChallengeRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(oauthAuthorizationCodeRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(oauthConsentRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(passkeyCredentialRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(mfaBackupCodeRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(mfaTotpCredentialRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(passwordHistoryRepository).deleteByUserId(deletedUser);
        verify(securityEventRepository).purgeByUserReferences(List.of(deletedUser));
        verify(consentEventRepository).deleteByUserIdIn(List.of(deletedUser));
        verify(emailOutboxService).deleteByRecipients(List.of("deleted@example.test"));
        verify(passkeyChallengeRepository).deleteExpired(any());
        verify(oauthAuthorizationCodeRepository).deleteExpired(any());

        org.junit.jupiter.api.Assertions.assertTrue(eventCutoff.getValue().isBefore(accountCutoff.getValue()));
        assertEquals(5.0, meterRegistry.counter("security.retention.deleted", "dataset", "security_events").count());
        assertEquals(2.0, meterRegistry.counter("security.retention.deleted", "dataset", "deleted_users").count());
        assertEquals(3.0, meterRegistry.counter("security.retention.deleted", "dataset", "passkey_challenges").count());
        assertEquals(4.0, meterRegistry.counter("security.retention.deleted", "dataset", "oauth_authorization_codes").count());
    }
}
