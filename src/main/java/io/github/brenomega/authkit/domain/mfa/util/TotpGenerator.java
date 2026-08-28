package io.github.brenomega.authkit.domain.mfa.util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Generates and verifies RFC 6238-style HMAC-SHA-1 codes on 30-second steps.
 * Verification accepts the adjacent time steps and excludes any step at or below
 * the supplied last-used value; callers must still persist the accepted step atomically.
 */
public class TotpGenerator {

    public static final int DEFAULT_DIGITS = 6;
    public static final int DEFAULT_PERIOD_SECONDS = 30;
    public static final int DEFAULT_WINDOW = 1;

    private final Clock clock;

    public TotpGenerator() {
        this(Clock.systemUTC());
    }

    public TotpGenerator(Clock clock) {
        this.clock = clock;
    }

    /** Returns the matching time step after constant-time code comparison, or an invalid result. */
    public VerificationResult verify(String base32Secret, String code, Long lastUsedTimeStep) {
        if (code == null || !code.matches("\\d{6,8}")) {
            return VerificationResult.invalid();
        }

        long currentStep = timeStep(Instant.now(clock));
        byte[] secret = Base32.decode(base32Secret);
        for (int offset = -DEFAULT_WINDOW; offset <= DEFAULT_WINDOW; offset++) {
            long candidateStep = currentStep + offset;
            if (lastUsedTimeStep != null && candidateStep <= lastUsedTimeStep) {
                continue;
            }
            String expected = generate(secret, candidateStep, code.length());
            if (constantTimeEquals(expected, code)) {
                return new VerificationResult(true, candidateStep);
            }
        }

        return VerificationResult.invalid();
    }

    public String currentCode(String base32Secret) {
        return generate(Base32.decode(base32Secret), timeStep(Instant.now(clock)), DEFAULT_DIGITS);
    }

    public long timeStep(Instant instant) {
        return instant.getEpochSecond() / DEFAULT_PERIOD_SECONDS;
    }

    private String generate(byte[] secret, long timeStep, int digits) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(timeStep).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            int modulus = (int) Math.pow(10, digits);
            return String.format("%0" + digits + "d", binary % modulus);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("TOTP generation failed", ex);
        }
    }

    private boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    /** Identifies the accepted step so callers can persist replay-prevention state. */
    public record VerificationResult(boolean valid, long timeStep) {
        public static VerificationResult invalid() {
            return new VerificationResult(false, -1);
        }
    }
}
