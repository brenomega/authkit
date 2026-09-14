package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.domain.mfa.dto.MfaTotpConfirmRequest;
import io.github.brenomega.authkit.domain.mfa.util.TotpGenerator;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyChallenge;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyChallengeType;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.dto.ConsentAcceptanceRequest;
import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.exception.UserAlreadyExistsException;
import io.github.brenomega.authkit.repository.MfaBackupCodeRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.PasskeyChallengeRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.support.PostgresIntegrationTestSupport;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = false)
class OneTimeStateConcurrencyIntegrationTest extends PostgresIntegrationTestSupport {

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

    @Autowired
    private ConsentEventRepository consentEventRepository;

    @Autowired
    private AccountLifecycleService accountLifecycleService;

    @Autowired
    private MfaService mfaService;

    @Autowired
    private MfaTotpCredentialRepository totpRepository;

    @Autowired
    private MfaBackupCodeRepository backupCodeRepository;

    @Autowired
    private PasskeyChallengeRepository passkeyChallengeRepository;

    @Autowired
    private PasskeyCredentialRepository passkeyCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthProperties authProperties;

    @Test
    void exactlyOneConcurrentRegistrationCreatesState() throws Exception {
        String email = "registration-race-" + UUID.randomUUID() + "@example.test";
        ConcurrentLinkedQueue<Class<?>> loserTypes = new ConcurrentLinkedQueue<>();

        List<Boolean> outcomes = race(8, () -> {
            try {
                registrationService.registerUser(new RegisterRequest(email, "VaultRiver73!", true, true));
                return true;
            } catch (RuntimeException ex) {
                loserTypes.add(ex.getClass());
                return false;
            }
        });

        assertEquals(1, outcomes.stream().filter(Boolean.TRUE::equals).count());
        assertEquals(7, loserTypes.size());
        assertTrue(loserTypes.stream().allMatch(UserAlreadyExistsException.class::equals));
        User user = userRepository.findByEmail(email).orElseThrow();
        assertNotNull(user.getEmailConfirmationToken());
        assertEquals(1, emailOutboxRepository.findAll().stream()
                .filter(message -> email.equals(message.getRecipient())).count());
    }

    @Test
    void stealthRegistrationMakesConcurrentWinnerAndLosersIndistinguishable() throws Exception {
        String email = "stealth-registration-race-" + UUID.randomUUID() + "@example.test";
        boolean original = authProperties.getRegistration().isStealthConflicts();
        authProperties.getRegistration().setStealthConflicts(true);
        try {
            List<Boolean> outcomes = race(8, () -> mockMvc.perform(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                    .post("/api/v1/auth/register")
                                    .contentType("application/json")
                                    .content("""
                                            {"email":"%s","password":"VaultRiver73!",
                                             "termsAccepted":true,"privacyPolicyAccepted":true}
                                            """.formatted(email)))
                    .andReturn().getResponse().getStatus() == 202);

            assertEquals(8, outcomes.stream().filter(Boolean.TRUE::equals).count());
            assertTrue(userRepository.findByEmail(email).isPresent());
            assertEquals(1, emailOutboxRepository.findAll().stream()
                    .filter(message -> email.equals(message.getRecipient())).count());
        } finally {
            authProperties.getRegistration().setStealthConflicts(original);
        }
    }

    @Test
    void concurrentConsentAcceptanceIsIdempotentAndCreatesOneEvidenceSet() throws Exception {
        User user = new User("consent-race-" + UUID.randomUUID() + "@example.test",
                passwordEncoder.encode("VaultRiver73!"), "Consent User", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-old", "privacy-old", "consent", Instant.now().minusSeconds(60));
        user = userRepository.saveAndFlush(user);
        UUID userId = user.getId();
        ConsentAcceptanceRequest current = new ConsentAcceptanceRequest(
                true, true, "terms-v1", "privacy-v1");

        List<Boolean> outcomes = race(() ->
                !accountLifecycleService.acceptConsent(userId.toString(), current).consentRequired());

        assertEquals(2, outcomes.stream().filter(Boolean.TRUE::equals).count());
        User accepted = userRepository.findById(userId).orElseThrow();
        assertTrue(accepted.hasCurrentConsent("terms-v1", "privacy-v1"));
        assertEquals(1, consentEventRepository.findByUserIdOrderByAcceptedAtDesc(userId).size());
        assertEquals(1, securityEventRepository.findTop100ByTargetUserIdOrderByOccurredAtDesc(userId).stream()
                .filter(event -> event.getEventType() == SecurityEventType.CONSENT_ACCEPTED).count());
    }

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
    void emailConfirmationAndResendSerializeWithoutRestoringTheConsumedToken() throws Exception {
        String email = "confirm-resend-race-" + UUID.randomUUID() + "@example.test";
        registrationService.registerUser(new RegisterRequest(email, "VaultRiver73!", true, true));
        var originalMessage = emailOutboxRepository.findTopByRecipientOrderByCreatedAtDesc(email).orElseThrow();
        String originalToken = tokenFromFragment(originalMessage.getBody());

        List<Boolean> outcomes = race(
                () -> {
                    registrationService.confirmEmail(originalToken);
                    return true;
                },
                () -> {
                    registrationService.resendEmailConfirmation(email);
                    return true;
                });

        User terminal = userRepository.findByEmail(email).orElseThrow();
        long verificationSuccesses = securityEventRepository
                .findTop100ByTargetUserIdOrderByOccurredAtDesc(terminal.getId()).stream()
                .filter(event -> event.getEventType() == SecurityEventType.EMAIL_VERIFIED)
                .filter(event -> event.getOutcome()
                        == io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome.SUCCESS)
                .count();
        if (terminal.isEmailConfirmed()) {
            assertEquals(2, outcomes.stream().filter(Boolean.TRUE::equals).count(),
                    "the anti-enumeration resend remains externally indistinguishable");
            assertNull(terminal.getEmailConfirmationToken());
            assertEquals(1, verificationSuccesses);
            assertEquals(1, emailOutboxRepository.findAll().stream()
                    .filter(message -> email.equals(message.getRecipient())).count(),
                    "the losing resend must not enqueue or rotate state");
        } else {
            assertEquals(1, outcomes.stream().filter(Boolean.TRUE::equals).count(),
                    "the resend wins and the stale confirmation token loses");
            assertNotNull(terminal.getEmailConfirmationToken());
            assertEquals(0, verificationSuccesses);
            assertEquals(2, emailOutboxRepository.findAll().stream()
                    .filter(message -> email.equals(message.getRecipient())).count());
        }
    }

    @SuppressWarnings("null")
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

    @Test
    void emailChangeConfirmationAndCancellationHaveExactlyOneTerminalOutcome() throws Exception {
        String suffix = UUID.randomUUID().toString();
        String oldEmail = "change-cancel-old-" + suffix + "@example.test";
        String newEmail = "change-cancel-new-" + suffix + "@example.test";
        String rawToken = "change-cancel-token-" + suffix;
        User user = activeUser(oldEmail, "VaultRiver73!");
        user.requestEmailChange(newEmail, TokenHasher.sha256Hex(rawToken),
                Instant.now(), Instant.now().plusSeconds(3600));
        user = userRepository.saveAndFlush(user);
        UUID userId = user.getId();

        List<Boolean> outcomes = race(
                () -> {
                    emailChangeService.confirm(rawToken);
                    return true;
                },
                () -> {
                    emailChangeService.cancel(userId.toString(), new StepUpRequest("VaultRiver73!", null));
                    return true;
                });

        assertEquals(1, outcomes.stream().filter(Boolean.TRUE::equals).count());
        User terminal = userRepository.findById(userId).orElseThrow();
        assertNull(terminal.getPendingEmail());
        assertNull(terminal.getEmailChangeTokenHash());
        assertTrue(terminal.getEmail().equals(oldEmail) || terminal.getEmail().equals(newEmail));
        long completions = securityEventRepository.findTop100ByTargetUserIdOrderByOccurredAtDesc(userId).stream()
                .filter(event -> event.getEventType() == SecurityEventType.EMAIL_CHANGE_COMPLETED).count();
        long cancellations = securityEventRepository.findTop100ByTargetUserIdOrderByOccurredAtDesc(userId).stream()
                .filter(event -> event.getEventType() == SecurityEventType.EMAIL_CHANGE_CANCELLED).count();
        assertEquals(1, completions + cancellations);
    }

    @Test
    void totpConfirmationBackupCodeAndReplayMarkerEachHaveOneWinner() throws Exception {
        User user = activeUser("mfa-race-" + UUID.randomUUID() + "@example.test", "VaultRiver73!");
        var enrollment = mfaService.startTotpEnrollment(user.getId().toString(), new StepUpRequest("VaultRiver73!"));
        String code = new TotpGenerator().currentCode(enrollment.secret());
        AtomicReference<io.github.brenomega.authkit.domain.mfa.dto.MfaBackupCodesResponse> winningResponse =
                new AtomicReference<>();

        List<Boolean> confirmations = race(() -> {
            winningResponse.set(mfaService.confirmTotp(user.getId().toString(),
                    new MfaTotpConfirmRequest(enrollment.credentialId(), "VaultRiver73!", code)));
            return true;
        });
        assertEquals(1, confirmations.stream().filter(Boolean.TRUE::equals).count());
        assertTrue(totpRepository.findById(enrollment.credentialId()).orElseThrow().isConfirmed());
        assertEquals(10, backupCodeRepository.countByUserIdAndUsedAtIsNull(user.getId()));

        String firstBackupCode = winningResponse.get().backupCodes().getFirst();
        List<Boolean> backupOutcomes = race(() ->
                mfaService.verifyMfaCode(user, firstBackupCode, "concurrency_proof").valid());
        assertEquals(1, backupOutcomes.stream().filter(Boolean.TRUE::equals).count());
        assertEquals(9, backupCodeRepository.countByUserIdAndUsedAtIsNull(user.getId()));

        long nextStep = new TotpGenerator().timeStep(Instant.now()) + 10;
        List<Boolean> replayMarkerOutcomes = race(() -> Boolean.TRUE.equals(transactionTemplate.execute(status ->
                totpRepository.markTimeStepUsedIfNewer(
                        enrollment.credentialId(), user.getId(), nextStep) == 1)));
        assertEquals(1, replayMarkerOutcomes.stream().filter(Boolean.TRUE::equals).count());
        assertEquals(nextStep, totpRepository.findById(enrollment.credentialId()).orElseThrow().getLastUsedTimeStep());
    }

    @Test
    void passkeyChallengeAndCounterEachHaveOneWinner() throws Exception {
        User user = activeUser("passkey-race-" + UUID.randomUUID() + "@example.test", "VaultRiver73!");
        Instant now = Instant.now();
        PasskeyChallenge challenge = passkeyChallengeRepository.saveAndFlush(new PasskeyChallenge(
                PasskeyChallengeType.ASSERTION, user.getId(), "{}", now, now.plusSeconds(300)));

        List<Boolean> challengeOutcomes = race(() -> Boolean.TRUE.equals(transactionTemplate.execute(status ->
                passkeyChallengeRepository.consume(challenge.getId(), PasskeyChallengeType.ASSERTION, Instant.now()) == 1)));
        assertEquals(1, challengeOutcomes.stream().filter(Boolean.TRUE::equals).count());
        assertNotNull(passkeyChallengeRepository.findById(challenge.getId()).orElseThrow().getConsumedAt());

        PasskeyCredential credential = passkeyCredentialRepository.saveAndFlush(new PasskeyCredential(
                user.getId(), user.getTenantId(), "credential-" + UUID.randomUUID(), "public-key", 1,
                "internal", "Race key", true, now));
        List<Boolean> counterOutcomes = race(() -> Boolean.TRUE.equals(transactionTemplate.execute(status ->
                passkeyCredentialRepository.markUsed(
                        credential.getCredentialId(), user.getId(), 2, Instant.now()) == 1)));
        assertEquals(1, counterOutcomes.stream().filter(Boolean.TRUE::equals).count());
        assertEquals(2, passkeyCredentialRepository.findById(credential.getId()).orElseThrow().getSignatureCount());
        assertTrue(passkeyCredentialRepository.findById(credential.getId()).orElseThrow().isActive());
    }

    private List<Boolean> race(Callable<Boolean> operation) throws Exception {
        return race(2, operation);
    }

    private List<Boolean> race(Callable<Boolean> first, Callable<Boolean> second) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(3);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var firstFuture = executor.submit(() -> invokeAfterBarrier(barrier, first));
            var secondFuture = executor.submit(() -> invokeAfterBarrier(barrier, second));
            barrier.await(5, TimeUnit.SECONDS);
            return List.of(firstFuture.get(30, TimeUnit.SECONDS), secondFuture.get(30, TimeUnit.SECONDS));
        }
    }

    private boolean invokeAfterBarrier(CyclicBarrier barrier, Callable<Boolean> operation) throws Exception {
        barrier.await(5, TimeUnit.SECONDS);
        try {
            return operation.call();
        } catch (RuntimeException expectedLoser) {
            return false;
        }
    }

    private List<Boolean> race(int contenders, Callable<Boolean> operation) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(contenders + 1);
        try (var executor = Executors.newFixedThreadPool(contenders)) {
            Callable<Boolean> contender = () -> {
                barrier.await(5, TimeUnit.SECONDS);
                try {
                    return operation.call();
                } catch (RuntimeException ex) {
                    return false;
                }
            };
            var futures = java.util.stream.IntStream.range(0, contenders)
                    .mapToObj(ignored -> executor.submit(contender))
                    .toList();
            barrier.await(5, TimeUnit.SECONDS);
            java.util.ArrayList<Boolean> results = new java.util.ArrayList<>(contenders);
            for (var future : futures) {
                results.add(future.get(30, TimeUnit.SECONDS));
            }
            return List.copyOf(results);
        }
    }

    private String tokenFromFragment(String body) {
        Matcher matcher = FRAGMENT_TOKEN.matcher(body);
        assertTrue(matcher.find(), "Rendered email must contain a fragment token");
        return matcher.group(1);
    }

    private User activeUser(String email, String password) {
        User user = new User(email, passwordEncoder.encode(password), "Concurrency User", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-v1", "privacy-v1", "consent", Instant.now());
        return userRepository.saveAndFlush(user);
    }
}
