package io.github.brenomega.authkit.domain.mfa.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

class TotpGeneratorTest {

    @Test
    void base32RoundTrip() {
        byte[] input = "hello-authkit".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertArrayEquals(input, Base32.decode(Base32.encode(input)));
    }

    @Test
    void verifiesCurrentCodeAndRejectsReplay() {
        TotpGenerator generator = new TotpGenerator(Clock.fixed(Instant.ofEpochSecond(1_700_000_000), ZoneOffset.UTC));
        String secret = Base32.encode("12345678901234567890".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String code = generator.currentCode(secret);

        var result = generator.verify(secret, code, null);
        assertTrue(result.valid());
        assertFalse(generator.verify(secret, code, result.timeStep()).valid());
    }
}
