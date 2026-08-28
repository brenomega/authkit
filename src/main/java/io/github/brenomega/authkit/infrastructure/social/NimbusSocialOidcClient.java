package io.github.brenomega.authkit.infrastructure.social;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.brenomega.authkit.domain.social.entity.OidcClientAuthMethod;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;
import io.github.brenomega.authkit.exception.InvalidSocialLoginException;
import io.github.brenomega.authkit.infrastructure.security.SocialSecretCipher;
import io.github.brenomega.authkit.service.spi.SocialOidcClient;

/**
 * Performs bounded OIDC discovery, code exchange, and ID-token verification for social providers.
 *
 * <p>Discovery redirects are disabled, all discovered endpoints must be HTTPS, and
 * the returned issuer must exactly equal the configured issuer. Code exchange uses
 * PKCE and the configured client-authentication method. The ID token is accepted
 * only after RS256 signature, issuer, temporal, audience, nonce, and nonblank
 * subject validation. All protocol and transport failures collapse to
 * {@link InvalidSocialLoginException}.</p>
 */
@Component
public class NimbusSocialOidcClient implements SocialOidcClient {
    private final ObjectMapper objectMapper;
    private final SocialSecretCipher cipher;
    private final RestTemplate http;

    @SuppressWarnings("null")
    public NimbusSocialOidcClient(ObjectMapper objectMapper, SocialSecretCipher cipher) {
        this.objectMapper = objectMapper;
        this.cipher = cipher;
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        @SuppressWarnings("null")
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(Duration.ofSeconds(5));
        this.http = new RestTemplate(factory);
    }

    @Override
    public OidcProviderMetadata metadata(SocialIdentityProvider provider) {
        try {
            String discoveryUrl = provider.getIssuer().replaceAll("/$", "") + "/.well-known/openid-configuration";
            @SuppressWarnings("null")
            JsonNode document = http.getForObject(URI.create(discoveryUrl), JsonNode.class);
            if (document == null) throw new InvalidSocialLoginException();
            String issuer = requiredHttps(document, "issuer");
            if (!provider.getIssuer().equals(issuer)) throw new InvalidSocialLoginException();
            return new OidcProviderMetadata(
                    issuer,
                    requiredHttps(document, "authorization_endpoint"),
                    requiredHttps(document, "token_endpoint"),
                    requiredHttps(document, "jwks_uri"));
        } catch (InvalidSocialLoginException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InvalidSocialLoginException(ex);
        }
    }

    @SuppressWarnings("null")
    @Override
    public FederatedIdentity exchangeAndVerify(SocialIdentityProvider provider, String code, String codeVerifier,
                                               String redirectUri, String expectedNonce) {
        try {
            OidcProviderMetadata metadata = metadata(provider);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "authorization_code");
            form.add("code", code);
            form.add("redirect_uri", redirectUri);
            form.add("client_id", provider.getClientId());
            form.add("code_verifier", codeVerifier);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            String clientSecret = cipher.decrypt(provider.getEncryptedClientSecret());
            if (provider.getClientAuthMethod() == OidcClientAuthMethod.CLIENT_SECRET_BASIC) {
                headers.setBasicAuth(provider.getClientId(), clientSecret);
            } else {
                form.add("client_secret", clientSecret);
            }

            @SuppressWarnings("null")
            String response = http.postForObject(URI.create(metadata.tokenEndpoint()),
                    new HttpEntity<>(form, headers), String.class);
            JsonNode tokenResponse = objectMapper.readTree(response);
            String idToken = text(tokenResponse, "id_token");

            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(metadata.jwksUri())
                    .jwsAlgorithm(SignatureAlgorithm.RS256)
                    .restOperations(http)
                    .build();
            decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(provider.getIssuer()));
            Jwt jwt = decoder.decode(idToken);
            if (!jwt.getAudience().contains(provider.getClientId())
                    || !expectedNonce.equals(jwt.getClaimAsString("nonce"))
                    || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
                throw new InvalidSocialLoginException();
            }
            String email = jwt.getClaimAsString("email");
            Boolean emailVerified = jwt.getClaim("email_verified");
            List<String> amr = jwt.getClaimAsStringList("amr");
            return new FederatedIdentity(jwt.getIssuer().toString(), jwt.getSubject(), email,
                    Boolean.TRUE.equals(emailVerified), jwt.getClaimAsString("name"),
                    jwt.getClaimAsString("acr"), amr == null ? List.of() : List.copyOf(amr));
        } catch (InvalidSocialLoginException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InvalidSocialLoginException(ex);
        }
    }

    private String requiredHttps(JsonNode document, String field) {
        String value = text(document, field);
        URI uri = URI.create(value);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new InvalidSocialLoginException();
        }
        return value;
    }

    private String text(JsonNode document, String field) {
        JsonNode value = document == null ? null : document.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) throw new InvalidSocialLoginException();
        return value.asText();
    }
}
