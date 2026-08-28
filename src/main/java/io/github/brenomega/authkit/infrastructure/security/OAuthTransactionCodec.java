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

@Component
public class OAuthTransactionCodec {
    private final byte[] key;
    public OAuthTransactionCodec(AuthProperties properties) {
        this.key = properties.getAudit().getHashPepper().getBytes(StandardCharsets.UTF_8);
    }

    public IssuedTransaction issue() {
        String random = SecureTokenGenerator.randomUrlSafeToken(32);
        String raw = "oat.v1." + random + "." + sign(random);
        return new IssuedTransaction(raw, TokenHasher.sha256Hex(raw));
    }

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

    public record IssuedTransaction(String raw, String hash) {}
}
