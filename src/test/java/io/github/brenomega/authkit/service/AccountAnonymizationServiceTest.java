package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

class AccountAnonymizationServiceTest {

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void expiredPendingAccountIsAnonymizedOnce() {
        UserRepository users = mock(UserRepository.class);
        SecurityEventService events = mock(SecurityEventService.class);
        EmailOutboxService outbox = mock(EmailOutboxService.class);
        TokenStorage tokens = mock(TokenStorage.class);
        UserAuthoritiesFilter authorities = mock(UserAuthoritiesFilter.class);
        TransactionTemplate transactions = mock(TransactionTemplate.class);
        when(transactions.execute(any())).thenAnswer(invocation ->
                ((TransactionCallback) invocation.getArgument(0)).doInTransaction(mock(TransactionStatus.class)));

        AuthProperties properties = new AuthProperties();
        properties.getCompliance().setDeletionGracePeriodDays(7);
        properties.getCompliance().setRetentionBatchSize(10);
        var service = new AccountAnonymizationService(
                users, events, outbox, tokens, authorities, properties,
                new SimpleMeterRegistry(), transactions,
                mock(io.github.brenomega.authkit.repository.SocialIdentityRepository.class),
                mock(io.github.brenomega.authkit.repository.SocialLoginTransactionRepository.class),
                mock(io.github.brenomega.authkit.repository.OAuthRefreshTokenFamilyRepository.class),
                mock(io.github.brenomega.authkit.repository.OAuthRefreshTokenRepository.class));

        UUID id = UUID.randomUUID();
        User user = new User("pending@example.test", "hash", "Pending", true, true, null);
        ReflectionTestUtils.setField(user, "id", id);
        user.requestDeletion(Instant.now().minus(8, ChronoUnit.DAYS));
        when(users.findDeletionPendingIdsBefore(eq(AccountState.DELETION_PENDING), any(), any()))
                .thenReturn(List.of(id), List.of());
        when(users.findByIdForUpdate(id)).thenReturn(Optional.of(user));

        service.anonymizeExpiredDeletionRequests();

        assertEquals(AccountState.ANONYMIZED, user.getAccountState());
        assertNull(user.getPassword());
        assertNull(user.getName());
        verify(events).record(eq(SecurityEventType.ACCOUNT_ANONYMIZED), any(), any(),
                eq(id), eq(id), eq(user.getTenantId()), eq("pending@example.test"),
                eq("account_anonymized_after_grace"), any());
        verify(outbox).deleteByRecipients(List.of("pending@example.test"));
        verify(tokens).revokeAllSessions(id.toString());
        verify(authorities).evict(id);
    }
}
