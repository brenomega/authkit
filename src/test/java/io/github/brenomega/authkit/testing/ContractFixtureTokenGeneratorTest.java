package io.github.brenomega.authkit.testing;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class ContractFixtureTokenGeneratorTest {

    private static final String TEST_ISSUER = "authkit";
    private static final String FIRST_PARTY_AUDIENCE = "authkit-api";
    private static final String RESOURCE_AUDIENCE = "sample-resource-api";
    private static final String TEST_KEY_ID = "authkit-key-1";

    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void generateSignedContractFixtureTokens() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        Path keyPath = root.resolve("src/test/resources/test-keys/app.key").normalize();
        assertTrue(Files.exists(keyPath), "test-only private key must exist");
        assertTrue(keyPath.startsWith(root.resolve("src/test/resources/test-keys").normalize()),
                "fixture generation may only use committed test keys");

        RSAPrivateKey privateKey = readPrivateKey(keyPath);
        Instant now = Instant.now();
        String subject = UUID.nameUUIDFromBytes("fixture-user".getBytes(StandardCharsets.UTF_8)).toString();
        String tenant = UUID.nameUUIDFromBytes("fixture-tenant".getBytes(StandardCharsets.UTF_8)).toString();

        Map<String, JWTClaimsSet> claims = new LinkedHashMap<>();
        claims.put("valid-first-party-access", base(now, subject, tenant)
                .audience(FIRST_PARTY_AUDIENCE)
                .jwtID("fixture-session-jti")
                .claim("token_use", "first_party_access")
                .claim("amr", List.of("pwd"))
                .build());
        claims.put("valid-oauth-access", oauth(now, subject, tenant)
                .claim("scope", "openid email profile admin")
                .build());
        claims.put("valid-id-token", base(now, subject, tenant)
                .audience(RESOURCE_AUDIENCE)
                .jwtID("fixture-id-jti")
                .claim("token_use", "id_token")
                .claim("nonce", "fixture-nonce")
                .claim("amr", List.of("pwd"))
                .build());
        claims.put("wrong-audience", oauth(now, subject, tenant)
                .audience("other-resource-api")
                .build());
        claims.put("wrong-issuer", oauth(now, subject, tenant)
                .issuer("https://issuer.example.invalid")
                .build());
        claims.put("expired-token", oauth(now.minusSeconds(600), subject, tenant)
                .expirationTime(java.util.Date.from(now.minusSeconds(60)))
                .build());
        claims.put("missing-token-use", base(now, subject, tenant)
                .audience(FIRST_PARTY_AUDIENCE)
                .jwtID("fixture-session-jti")
                .claim("amr", List.of("pwd"))
                .build());
        claims.put("missing-tenant-id", oauth(now, subject, null)
                .claim("tenant_id", null)
                .build());
        claims.put("tenant-mismatch", oauth(now, subject, "fixture-tenant-a")
                .build());
        claims.put("revoked-session", base(now, subject, tenant)
                .audience(FIRST_PARTY_AUDIENCE)
                .jwtID("revoked-session-jti")
                .claim("token_use", "first_party_access")
                .claim("amr", List.of("pwd"))
                .build());
        claims.put("oauth-token-used-on-first-party-api", oauth(now, subject, tenant).build());
        claims.put("first-party-token-used-on-oauth-userinfo", base(now, subject, tenant)
                .audience(FIRST_PARTY_AUDIENCE)
                .jwtID("fixture-session-jti")
                .claim("token_use", "first_party_access")
                .claim("amr", List.of("pwd"))
                .build());
        claims.put("id-token-used-on-api", base(now, subject, tenant)
                .audience(RESOURCE_AUDIENCE)
                .jwtID("fixture-id-jti")
                .claim("token_use", "id_token")
                .claim("nonce", "fixture-nonce")
                .build());

        Path output = root.resolve("target/contract-fixtures");
        Files.createDirectories(output);

        List<Map<String, String>> manifest = new java.util.ArrayList<>();
        RSASSASigner signer = new RSASSASigner(privateKey);
        for (Map.Entry<String, JWTClaimsSet> entry : claims.entrySet()) {
            String keyId = "revoked-key-id".equals(entry.getKey()) ? "revoked-test-key" : TEST_KEY_ID;
            String token = sign(entry.getValue(), signer, keyId);
            Files.writeString(output.resolve(entry.getKey() + ".jwt"), token + System.lineSeparator(), StandardCharsets.UTF_8);
            manifest.add(Map.of("name", entry.getKey(), "file", entry.getKey() + ".jwt"));
        }

        JWTClaimsSet revokedKeyClaims = oauth(now, subject, tenant).build();
        Files.writeString(
                output.resolve("revoked-key-id.jwt"),
                sign(revokedKeyClaims, signer, "revoked-test-key") + System.lineSeparator(),
                StandardCharsets.UTF_8);
        manifest.add(Map.of("name", "revoked-key-id", "file", "revoked-key-id.jwt"));

        Files.writeString(output.resolve("tokens.json"), objectMapper.writeValueAsString(manifest), StandardCharsets.UTF_8);
    }

    private JWTClaimsSet.Builder oauth(Instant now, String subject, String tenant) {
        JWTClaimsSet.Builder builder = base(now, subject, tenant)
                .audience(RESOURCE_AUDIENCE)
                .jwtID(UUID.randomUUID().toString())
                .claim("token_use", "oauth_access")
                .claim("client_id", RESOURCE_AUDIENCE)
                .claim("scope", "openid email profile")
                .claim("amr", List.of("pwd"));
        if (tenant == null) {
            builder.claim("tenant_id", null);
        }
        return builder;
    }

    private JWTClaimsSet.Builder base(Instant now, String subject, String tenant) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(TEST_ISSUER)
                .subject(subject)
                .issueTime(java.util.Date.from(now))
                .expirationTime(java.util.Date.from(now.plusSeconds(900)));
        if (tenant != null) {
            builder.claim("tenant_id", tenant);
        }
        return builder;
    }

    private String sign(JWTClaimsSet claims, RSASSASigner signer, String keyId) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private RSAPrivateKey readPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pem);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
