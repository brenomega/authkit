package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.brenomega.authkit.domain.user.dto.PasskeyRegistrationFinishRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidPasskeyCeremonyException;
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

    private void assertEqualsZero(long value) {
        org.junit.jupiter.api.Assertions.assertEquals(0L, value);
    }

    private User confirmedUser(String email) {
        User user = new User(email, passwordEncoder.encode("Password123!"), "Test User", null, true, true, "token");
        user.setEmailConfirmed(true);
        return userRepository.save(user);
    }
}
