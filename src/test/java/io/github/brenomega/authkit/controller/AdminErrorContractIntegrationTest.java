package io.github.brenomega.authkit.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;
import org.yaml.snakeyaml.Yaml;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.SessionMetadata;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.support.PostgresIntegrationTestSupport;

/** Executes the admin HTTP error boundary and correlates observed errors with OpenAPI. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AdminErrorContractIntegrationTest extends PostgresIntegrationTestSupport {
    @Autowired MockMvc http;
    @Autowired UserRepository users;
    @Autowired PasskeyCredentialRepository passkeys;
    @Autowired PasswordEncoder encoder;
    @Autowired TokenStorage tokens;
    @Autowired AuthProperties properties;
    @Autowired ObjectMapper json;

    @Test
    void userMutationsDocumentAuthenticationStepUpMfaAndInvariantErrors() throws Exception {
        User admin = user(Role.PLATFORM_ADMIN);
        User target = user(Role.USER);
        String path = "/api/v1/admin/users/{userId}/role";
        String body = "{\"role\":\"USER\",\"currentPassword\":\"AdminProof73!\"}";
        check("patch", path, target.getId(), body, null, 401, null);
        check("patch", path, target.getId(), body, proof(target, true), 403, "forbidden");
        check("patch", path, target.getId(), "{\"role\":\"USER\"}", proof(admin, true), 401, "invalid_credentials");
        check("patch", path, target.getId(), body, proof(admin, true), 403, "mfa_required");
        passkeys.saveAndFlush(new PasskeyCredential(admin.getId(), admin.getTenantId(),
                "admin-contract-" + admin.getId(), "cose", 0, "internal", "Admin", true, Instant.now()));
        check("patch", path, target.getId(), body, proof(admin, false), 403, "mfa_required");
        check("patch", path, target.getId(), "{}", proof(admin, true), 400, "validation_failed");
        check("patch", path, UUID.randomUUID(), body, proof(admin, true), 404, "user_not_found");
        // This transaction contains the only active admin in this isolated PostgreSQL context.
        check("patch", path, admin.getId(), body, proof(admin, true), 403, "forbidden");
    }

    @Test
    void clientAndProviderMutationsUseTheirActualDomainErrorsNotInventedNotFound() throws Exception {
        User admin = user(Role.PLATFORM_ADMIN);
        User target = user(Role.USER);
        passkeys.saveAndFlush(new PasskeyCredential(admin.getId(), admin.getTenantId(),
                "admin-contract-" + admin.getId(), "cose", 0, "internal", "Admin", true, Instant.now()));
        for (String path : List.of("/api/v1/admin/oauth-clients/{clientId}",
                "/api/v1/admin/social-providers/{providerId}")) {
            String body = "{\"currentPassword\":\"AdminProof73!\"}";
            check("delete", path, UUID.randomUUID(), body, null, 401, null);
            check("delete", path, UUID.randomUUID(), body, proof(target, true), 403, "forbidden");
            check("delete", path, UUID.randomUUID(), "{}", proof(admin, true), 401, "invalid_credentials");
            check("delete", path, UUID.randomUUID(), body, proof(admin, false), 403, "mfa_required");
            check("delete", path, UUID.randomUUID(), body, proof(admin, true), 400,
                    path.contains("oauth") ? "invalid_oauth_request" : "invalid_social_login");
        }
    }

    @SuppressWarnings("unchecked")
    private void check(String method, String template, UUID id, String body, RequestPostProcessor principal,
                       int expected, String code) throws Exception {
        var call = request(HttpMethod.valueOf(method.toUpperCase(java.util.Locale.ROOT)), template, id)
                .contentType("application/json").content(body);
        if (principal != null) call.with(principal);
        var response = http.perform(call).andReturn().getResponse();
        assertEquals(expected, response.getStatus(), response.getContentAsString());
        if (code != null) assertEquals(code, json.readTree(response.getContentAsString()).path("code").asText());
        Map<String, Object> spec = new Yaml().load(Files.readString(Path.of("docs/openapi.yaml")));
        var operation = (Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) spec.get("paths"))
                .get(template)).get(method);
        assertTrue(((Map<String, Object>) operation.get("responses")).containsKey(Integer.toString(expected)),
                template + " " + method + " must document observed " + expected);
        if (code != null) assertTrue(operation.get("description").toString().contains(code),
                template + " must document observed stable error " + code);
    }

    private User user(Role role) {
        User user = new User(UUID.randomUUID() + "@admin-contract.test", encoder.encode("AdminProof73!"),
                "Contract", true, true, null);
        user.setRole(role); user.setEmailConfirmed(true);
        user.acceptConsent(properties.getCompliance().getTermsVersion(),
                properties.getCompliance().getPrivacyPolicyVersion(), properties.getCompliance().getLawfulBasis(), Instant.now());
        return users.saveAndFlush(user);
    }

    private RequestPostProcessor proof(User user, boolean fresh) {
        String jti = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant issued = fresh ? now : now.minusSeconds(properties.getStepUp().getPasskeyFreshnessSeconds() + 1);
        var refresh = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokens.storeRefreshToken(user.getId().toString(), jti, refresh.rawToken(), 1,
                new SessionMetadata(UUID.randomUUID().toString(), jti, issued, now, now.plusSeconds(86400),
                        user.getSecurityVersion(), List.of("webauthn"), "JUnit", null, "127.0.0.***", "127.0.0.***"));
        return jwt().jwt(builder -> builder.claims(claims -> claims.remove("scope"))
                .subject(user.getId().toString()).audience(List.of("authkit-api"))
                .claim("token_use", "first_party_access").claim("jti", jti)
                .claim("tenant_id", user.getTenantId().toString()).claim("amr", List.of("webauthn"))
                .claim("session_version", user.getSecurityVersion()).issuedAt(issued).expiresAt(now.plusSeconds(900)));
    }
}
