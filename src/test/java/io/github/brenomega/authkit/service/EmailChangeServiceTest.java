package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import io.github.brenomega.authkit.domain.user.dto.EmailChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

class EmailChangeServiceTest {

    private UserRepository users;
    private StepUpService stepUp;
    private MfaService mfa;
    private EmailOutboxService outbox;
    private SecurityEventService events;
    private TokenStorage tokens;
    private UserAuthoritiesFilter authorities;
    private EmailChangeService service;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        stepUp = mock(StepUpService.class);
        mfa = mock(MfaService.class);
        outbox = mock(EmailOutboxService.class);
        events = mock(SecurityEventService.class);
        tokens = mock(TokenStorage.class);
        authorities = mock(UserAuthoritiesFilter.class);
        AuthProperties properties = new AuthProperties();
        properties.getFrontend().setEmailChangeUrl("https://app.example/change-email");
        var renderer = mock(io.github.brenomega.authkit.infrastructure.email.EmailTemplateRenderer.class);
        when(renderer.render(any(), any(), any())).thenAnswer(invocation -> {
            java.util.Map<?, ?> variables = invocation.getArgument(2);
            return new io.github.brenomega.authkit.service.spi.EmailPayload(
                    invocation.getArgument(1), "subject",
                    variables.containsKey("action_url") ? String.valueOf(variables.get("action_url")) : "notice");
        });
        service = new EmailChangeService(users, stepUp, mfa, outbox, events, tokens, authorities, properties, renderer);
    }

    @Test
    void requestPreservesActiveAddressAndCreatesAuditedPendingState() {
        User user = user("old@example.com");
        when(users.findById(user.getId())).thenReturn(Optional.of(user));
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());

        var response = service.request(user.getId().toString(),
                new EmailChangeRequest(" New@Example.com ", "password", "123456"));

        assertEquals("old@example.com", user.getEmail());
        assertEquals("new@example.com", user.getPendingEmail());
        assertEquals("pending_confirmation", response.status());
        verify(stepUp).verifyCurrentPassword(user, "password", SecurityEventType.EMAIL_CHANGE_FAILED,
                "email_change_step_up_failed");
        verify(mfa).requireMfaIfEnabled(user, "123456", "email_change");
        verify(outbox, org.mockito.Mockito.times(2)).enqueue(any());
        verify(events).recordForAuthenticatedUser(eq(SecurityEventType.EMAIL_CHANGE_REQUESTED),
                eq(SecurityEventOutcome.SUCCESS), eq(SecurityEventSeverity.HIGH), eq(user),
                eq("email_change_requested"), any());
    }

    @Test
    void confirmCommitsOnceAndRevokesAllOldCredentials() {
        User user = user("old@example.com");
        String rawToken = "email-change-token";
        user.requestEmailChange("new@example.com", TokenHasher.sha256Hex(rawToken),
                Instant.now(), Instant.now().plusSeconds(3600));
        when(users.findByEmailChangeTokenHashForUpdate(TokenHasher.sha256Hex(rawToken)))
                .thenReturn(Optional.of(user));
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());

        service.confirm(rawToken);

        assertEquals("new@example.com", user.getEmail());
        assertNull(user.getPendingEmail());
        verify(tokens).revokeAllSessions(user.getId().toString());
        verify(tokens).revokeRecoveryToken("old@example.com");
        verify(tokens).revokeRecoveryToken("new@example.com");
        verify(authorities).evict(user.getId());
        verify(events).record(eq(SecurityEventType.EMAIL_CHANGE_COMPLETED),
                eq(SecurityEventOutcome.SUCCESS), eq(SecurityEventSeverity.HIGH),
                eq(user.getId()), eq(user.getId()), eq(user.getTenantId()),
                eq("new@example.com"), eq("email_change_completed"), any());
    }

    @Test
    void invalidConfirmationNeverMutatesOrRevokesCredentials() {
        when(users.findByEmailChangeTokenHashForUpdate(any())).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class, () -> service.confirm("wrong"));

        verify(tokens, never()).revokeAllSessions(any());
        verify(events).record(eq(SecurityEventType.EMAIL_CHANGE_FAILED),
                eq(SecurityEventOutcome.FAILURE), eq(SecurityEventSeverity.HIGH),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.isNull(),
                eq("invalid_email_change_token"), any());
    }

    @Test
    void cancelClearsPendingStateAfterStepUp() {
        User user = user("old@example.com");
        user.requestEmailChange("new@example.com", TokenHasher.sha256Hex("token"),
                Instant.now(), Instant.now().plusSeconds(3600));
        when(users.findById(user.getId())).thenReturn(Optional.of(user));

        var response = service.cancel(user.getId().toString(), new StepUpRequest("password", "123456"));

        assertEquals("cancelled", response.status());
        assertNull(user.getPendingEmail());
        verify(mfa).requireMfaIfEnabled(user, "123456", "email_change_cancel");
        verify(events).recordForAuthenticatedUser(SecurityEventType.EMAIL_CHANGE_CANCELLED,
                SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, user, "email_change_cancelled");
    }

    private User user(String email) {
        User user = new User(email, "hash", "User", true, true, null);
        user.setEmailConfirmed(true);
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        return user;
    }
}
