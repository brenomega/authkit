package io.github.brenomega.authkit.domain.mfa.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MfaChallengeCodecTest {

    @Test
    void issuedChallengeParsesBackToHandles() {
        String userId = "00000000-0000-0000-0000-000000000000";
        var issued = MfaChallengeCodec.issue(userId);
        var parsed = MfaChallengeCodec.parse(issued.rawToken());

        assertTrue(parsed.isPresent());
        assertEquals(userId, parsed.get().userId());
        assertEquals(issued.jti(), parsed.get().jti());
    }
}
