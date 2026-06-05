package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class HibpCompromisedPasswordCheckerTest {

    @Test
    void sendsOnlyPrefixCachesRangeAndRejectsMatches() throws Exception {
        String password = "Correct-Horse-Battery-7!";
        String hash = HexFormat.of().withUpperCase().formatHex(
                MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8)));
        AtomicReference<String> submitted = new AtomicReference<>();
        AuthProperties properties = enabledProperties();
        HibpRangeClient client = prefix -> {
            submitted.set(prefix);
            return hash.substring(5) + ":42\n" + "0".repeat(35) + ":0";
        };
        var checker = new HibpCompromisedPasswordChecker(client, new SimpleMeterRegistry(), properties);

        assertTrue(checker.isCompromised(password));
        assertTrue(checker.isCompromised(password));
        assertEquals(hash.substring(0, 5), submitted.get());
        assertEquals(5, submitted.get().length());
    }

    @Test
    void providerFailureFailsOpenAndRecordsMetric() {
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        HibpRangeClient client = prefix -> { throw new IOException("timeout"); };
        var checker = new HibpCompromisedPasswordChecker(client, meters, enabledProperties());

        assertFalse(checker.isCompromised("Correct-Horse-Battery-8!"));
        assertEquals(1.0, meters.counter("security.password.hibp.degraded").count());
    }

    private AuthProperties enabledProperties() {
        AuthProperties properties = new AuthProperties();
        properties.getPassword().setHibpEnabled(true);
        return properties;
    }
}
