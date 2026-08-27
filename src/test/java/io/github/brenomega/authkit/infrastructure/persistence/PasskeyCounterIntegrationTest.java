package io.github.brenomega.authkit.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class PasskeyCounterIntegrationTest {

    @Autowired private UserRepository users;
    @Autowired private PasskeyCredentialRepository credentials;

    @Test
    void signatureCounterNeverDecreasesAndPositiveReplayIsRejected() {
        User user = new User("counter@example.test", "hash", null, true, true, null);
        user.setEmailConfirmed(true);
        user = users.save(user);
        PasskeyCredential credential = credentials.save(new PasskeyCredential(
                user.getId(), user.getTenantId(), "counter-credential", "public-key",
                5, "internal", "Counter", true, Instant.now()));

        assertEquals(0, credentials.markUsed(credential.getCredentialId(), user.getId(), 4, Instant.now()));
        assertEquals(0, credentials.markUsed(credential.getCredentialId(), user.getId(), 5, Instant.now()));
        assertEquals(1, credentials.markUsed(credential.getCredentialId(), user.getId(), 6, Instant.now()));
        assertEquals(6, credentials.findById(credential.getId()).orElseThrow().getSignatureCount());
    }

    @Test
    void zeroCounterAuthenticatorsRemainSupportedWithoutNegativeWrites() {
        User user = new User("zero-counter@example.test", "hash", null, true, true, null);
        user.setEmailConfirmed(true);
        user = users.save(user);
        PasskeyCredential credential = credentials.save(new PasskeyCredential(
                user.getId(), user.getTenantId(), "zero-counter-credential", "public-key",
                0, "internal", "Zero Counter", true, Instant.now()));

        assertEquals(1, credentials.markUsed(credential.getCredentialId(), user.getId(), 0, Instant.now()));
        assertEquals(0, credentials.markUsed(credential.getCredentialId(), user.getId(), -1, Instant.now()));
    }
}
