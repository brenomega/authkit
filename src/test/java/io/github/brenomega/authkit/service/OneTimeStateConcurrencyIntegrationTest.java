package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@SpringBootTest
@ActiveProfiles("test")
class OneTimeStateConcurrencyIntegrationTest {

    private static final Pattern FRAGMENT_TOKEN = Pattern.compile("#token=([A-Za-z0-9_-]+)");

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private EmailChangeService emailChangeService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailOutboxRepository emailOutboxRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Test
    void exactlyOneConcurrentEmailConfirmationCompletes() throws Exception {
        String email = "confirm-race-" + UUID.randomUUID() + "@example.test";
        registrationService.registerUser(new RegisterRequest(email, "VaultRiver73!", true, true));
        String rawToken = tokenFromFragment(
                emailOutboxRepository.findTopByRecipientOrderByCreatedAtDesc(email).orElseThrow().getBody());

        List<Boolean> outcomes = race(() -> {
            registrationService.confirmEmail(rawToken);
            return true;
        });

        assertEquals(1, outcomes.stream().filter(Boolean.TRUE::equals).count());
        User confirmed = userRepository.findByEmail(email).orElseThrow();
        assertTrue(confirmed.isEmailConfirmed());
        assertNull(confirmed.getEmailConfirmationToken());
        assertEquals(1, securityEventRepository.findTop100ByTargetUserIdOrderByOccurredAtDesc(confirmed.getId())
                .stream().filter(event -> event.getEventType() == SecurityEventType.EMAIL_VERIFIED).count());
    }

    @Test
    void exactlyOneConcurrentEmailChangeCompletes() throws Exception {
        String suffix = UUID.randomUUID().toString();
        String oldEmail = "change-old-" + suffix + "@example.test";
        String newEmail = "change-new-" + suffix + "@example.test";
        String rawToken = "change-token-" + UUID.randomUUID();
        User user = new User(oldEmail, "password-hash", "User", true, true, null);
        user.setEmailConfirmed(true);
        user.requestEmailChange(newEmail, TokenHasher.sha256Hex(rawToken),
                Instant.now(), Instant.now().plusSeconds(3600));
        user = userRepository.saveAndFlush(user);
        UUID userId = user.getId();

        List<Boolean> outcomes = race(() -> {
            emailChangeService.confirm(rawToken);
            return true;
        });

        assertEquals(1, outcomes.stream().filter(Boolean.TRUE::equals).count());
        User changed = userRepository.findById(userId).orElseThrow();
        assertEquals(newEmail, changed.getEmail());
        assertNull(changed.getPendingEmail());
        assertEquals(1, securityEventRepository.findTop100ByTargetUserIdOrderByOccurredAtDesc(userId)
                .stream().filter(event -> event.getEventType() == SecurityEventType.EMAIL_CHANGE_COMPLETED).count());
    }

    private List<Boolean> race(Callable<Boolean> operation) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(3);
        try (var executor = Executors.newFixedThreadPool(2)) {
            Callable<Boolean> contender = () -> {
                barrier.await(5, TimeUnit.SECONDS);
                try {
                    return operation.call();
                } catch (RuntimeException ex) {
                    return false;
                }
            };
            var first = executor.submit(contender);
            var second = executor.submit(contender);
            barrier.await(5, TimeUnit.SECONDS);
            return List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
        }
    }

    private String tokenFromFragment(String body) {
        Matcher matcher = FRAGMENT_TOKEN.matcher(body);
        assertTrue(matcher.find(), "Rendered email must contain a fragment token");
        return matcher.group(1);
    }
}
