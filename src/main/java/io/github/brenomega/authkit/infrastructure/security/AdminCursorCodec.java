package io.github.brenomega.authkit.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.exception.InvalidAdminCursorException;

/** Short-lived signed cursors bound to an admin query without embedding PII. */
@Component
public class AdminCursorCodec {
    private static final long TTL_SECONDS = 900;
    private final AuditDigestService digestService;

    public AdminCursorCodec(AuditDigestService digestService) {
        this.digestService = digestService;
    }

    public String issue(String kind, int page, int limit, String binding) {
        String payload = String.join(":", "v1", kind, Integer.toString(page), Integer.toString(limit),
                Long.toString(Instant.now().plusSeconds(TTL_SECONDS).getEpochSecond()),
                digestService.hmacHex("admin-cursor-binding|" + binding));
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return encoded + "." + digestService.hmacHex("admin-cursor|" + encoded);
    }

    public PagePosition decode(String cursor, String kind, int limit, String binding) {
        try {
            if (cursor == null || cursor.isBlank()) return new PagePosition(0, limit);
            if (cursor.length() > 1024) throw new IllegalArgumentException();
            String[] token = cursor.split("\\.", -1);
            if (token.length != 2) throw new IllegalArgumentException();
            String expected = digestService.hmacHex("admin-cursor|" + token[0]);
            if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                    token[1].getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException();
            String payload = new String(Base64.getUrlDecoder().decode(token[0]), StandardCharsets.UTF_8);
            String[] fields = payload.split(":", -1);
            if (fields.length != 6 || !"v1".equals(fields[0]) || !kind.equals(fields[1])) throw new IllegalArgumentException();
            int page = Integer.parseInt(fields[2]);
            int encodedLimit = Integer.parseInt(fields[3]);
            long expiresAt = Long.parseLong(fields[4]);
            String expectedBinding = digestService.hmacHex("admin-cursor-binding|" + binding);
            if (page < 0 || encodedLimit != limit || expiresAt < Instant.now().getEpochSecond()
                    || !MessageDigest.isEqual(expectedBinding.getBytes(StandardCharsets.US_ASCII),
                            fields[5].getBytes(StandardCharsets.US_ASCII))) throw new IllegalArgumentException();
            return new PagePosition(page, limit);
        } catch (RuntimeException ex) {
            if (ex instanceof InvalidAdminCursorException invalid) throw invalid;
            throw new InvalidAdminCursorException();
        }
    }

    public record PagePosition(int page, int limit) {}
}
