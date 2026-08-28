package io.github.brenomega.authkit.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;

/**
 * Issues signed opaque handles for browser-facing OAuth authorization transactions.
 * The HMAC rejects forged handles before database lookup, while persistence uses
 * only the SHA-256 hash of the complete handle. Expiry and one-time consumption are
 * enforced by the transaction repository and provider service, not by this codec.
 */
@Component
public class OAuthTransactionCodec {
    private final byte[] key;
    public OAuthTransactionCodec(AuthProperties properties) {
        this.key = properties.getAudit().getHashPepper().getBytes(StandardCharsets.UTF_8);
    }

    /** Creates a new raw handle and its persistence-safe digest. */
    public IssuedTransaction issue() {
        String random = SecureTokenGenerator.randomUrlSafeToken(32);
        String raw = "oat.v1." + random + "." + sign(random);
        return new IssuedTransaction(raw, TokenHasher.sha256Hex(raw));
    }

    /** Returns the persistence digest only when version, shape, and HMAC are valid. */
    public Optional<String> validatedHash(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String[] parts = raw.split("\\.", -1);
        if (parts.length != 4 || !"oat".equals(parts[0]) || !"v1".equals(parts[1])) {
            return Optional.empty();
        }
        boolean signatureMatches = MessageDigest.isEqual(
                sign(parts[2]).getBytes(StandardCharsets.US_ASCII),
                parts[3].getBytes(StandardCharsets.US_ASCII));
        if (!signatureMatches) {
            return Optional.empty();
        }
        return Optional.of(TokenHasher.sha256Hex(raw));
    }

    private String sign(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(mac.doFinal(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** Couples the browser secret with the digest stored by the caller. */
    public record IssuedTransaction(String raw, String hash) {}
}
