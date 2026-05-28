package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.PasskeyRegistrationFinishRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidPasskeyCeremonyException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class PasskeyServiceTest {

    @Autowired
    private PasskeyService passkeyService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasskeyCredentialRepository passkeyCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Starts WebAuthn registration with persisted challenge and rejects invalid attestation")
    void startRegistrationReturnsBrowserOptionsAndRejectsInvalidFinish() {
        User user = confirmedUser("passkey-user@example.com");

        assertThrows(InvalidCredentialsException.class,
                () -> passkeyService.startRegistration(user.getId().toString(), null));

        var options = passkeyService.startRegistration(
                user.getId().toString(),
                new StepUpRequest("Password123!"));

        assertTrue(options.publicKeyCredentialCreationOptionsJson().contains("\"challenge\""));
        assertFalse(options.publicKeyCredentialCreationOptionsJson().contains(user.getEmail()));
        assertThrows(InvalidPasskeyCeremonyException.class, () -> passkeyService.finishRegistration(
                user.getId().toString(),
                new PasskeyRegistrationFinishRequest(options.challengeId(), "Laptop", "{}")));
        assertEqualsZero(passkeyCredentialRepository.countByUserIdAndDisabledAtIsNull(user.getId()));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Passkey disable cannot target another user's credential")
    void disable_rejectsCredentialOwnedByAnotherUser() {
        User caller = confirmedUser("passkey-caller@example.com");
        User victim = confirmedUser("passkey-victim@example.com");
        PasskeyCredential credential = passkeyCredentialRepository.save(new PasskeyCredential(
                victim.getId(),
                victim.getTenantId(),
                "credential-" + victim.getId(),
                "public-key-cose",
                0,
                "internal",
                "Victim Credential",
                true,
                Instant.now()));

        assertThrows(UserNotFoundException.class, () -> passkeyService.disable(
                caller.getId().toString(),
                credential.getId(),
                new StepUpRequest("Password123!")));

        assertNull(passkeyCredentialRepository.findById(credential.getId()).orElseThrow().getDisabledAt());
    }

    private void assertEqualsZero(long value) {
        org.junit.jupiter.api.Assertions.assertEquals(0L, value);
    }

    private User confirmedUser(String email) {
        User user = new User(email, passwordEncoder.encode("Password123!"), "Test User", null, true, true, "token");
        user.setEmailConfirmed(true);
        return userRepository.save(user);
    }
}
