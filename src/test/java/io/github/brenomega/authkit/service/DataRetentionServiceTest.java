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
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;

class DataRetentionServiceTest {

    @Test
    @DisplayName("Retention purges expired security events and deleted account tombstones")
    void purgeExpiredSecurityEvents_purgesEventsAndDeletedUsers() {
        SecurityEventRepository securityEventRepository = mock(SecurityEventRepository.class);
        UserRepository userRepository = mock(UserRepository.class);
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
        when(securityEventRepository.findExpiredIds(any(), any(Pageable.class)))
                .thenReturn(List.of(eventOne, eventTwo));
        when(securityEventRepository.purgeByIdIn(List.of(eventOne, eventTwo))).thenReturn(5L);
        when(userRepository.findDeletedIdsBefore(any(), any(Pageable.class)))
                .thenReturn(List.of(deletedUser));
        when(userRepository.purgeDeletedByIdIn(List.of(deletedUser))).thenReturn(2L);

        new DataRetentionService(securityEventRepository, userRepository, authProperties, meterRegistry, transactionTemplate)
                .purgeExpiredSecurityEvents();

        ArgumentCaptor<Instant> eventCutoff = ArgumentCaptor.forClass(Instant.class);
        ArgumentCaptor<Instant> accountCutoff = ArgumentCaptor.forClass(Instant.class);
        verify(securityEventRepository).findExpiredIds(eventCutoff.capture(), any(Pageable.class));
        verify(userRepository).findDeletedIdsBefore(accountCutoff.capture(), any(Pageable.class));
        verify(securityEventRepository).purgeByIdIn(List.of(eventOne, eventTwo));
        verify(userRepository).purgeDeletedByIdIn(List.of(deletedUser));

        org.junit.jupiter.api.Assertions.assertTrue(eventCutoff.getValue().isBefore(accountCutoff.getValue()));
        assertEquals(5.0, meterRegistry.counter("security.retention.deleted", "dataset", "security_events").count());
        assertEquals(2.0, meterRegistry.counter("security.retention.deleted", "dataset", "deleted_users").count());
    }
}
